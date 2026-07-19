//! field-monitor — entry point.
//! Subcommands: probe | audit | corroborate | run-all | aggregate

mod aggregate;
mod audit;
mod corroborate;
mod model;
mod probe;
mod ssh;

use std::path::PathBuf;

use model::*;

/// Print servers (for CI/CD scripts). The private key PATH is deliberately
/// redacted — it must not leak into logs/scripts.
fn cmd_list_servers() {
    let cfg = load_config();
    for s in &cfg.servers {
        println!("{}|{}|<redacted>|{}|{}", s.ip, s.name, s.port, s.user);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let sub = args.get(1).map(|s| s.as_str()).unwrap_or("");

    match sub {
        "probe" => cmd_probe(),
        "audit" => cmd_audit(),
        "corroborate" => cmd_corroborate(),
        "run-all" => cmd_run_all(),
        "aggregate" => cmd_aggregate(),
        "list-servers" => cmd_list_servers(),
        _ => {
            eprintln!(
                "Usage: field-monitor <probe|audit|corroborate|run-all|aggregate|list-servers> [--config path]"
            );
            eprintln!(
                "  probe         — local measurement of allowlist targets (needs FIELD_PROBE_IP)"
            );
            eprintln!("  audit         — local read-only security audit");
            eprintln!(
                "  corroborate   — Layer 2: cross-check with a public reference API (read-only)"
            );
            eprintln!(
                "  run-all       — run probe/audit across servers from config (orchestrator)"
            );
            eprintln!("  aggregate     — summarize logs in RESULTS_DIR");
            eprintln!("  list-servers  — print servers (ip|name|key|port|user) for CI/CD scripts");
            std::process::exit(2);
        }
    }
}

/// Load configuration.
///
/// Loads `.env` if present (no-op if absent) so operators can point
/// `FIELD_MONITOR_CONFIG` at a private, git-ignored config without passing
/// `--config` on every invocation. Secrets (API tokens, key passphrases)
/// also belong in `.env`, never in source or config.toml.
///
/// Targets (allowlist) live in a SEPARATE private file `targets.toml`
/// (git-ignored) — the code ships NO hardcoded hosts. They are loaded only
/// if the operator did not inline `[[targets]]` in config.toml.
fn load_config() -> Config {
    let _ = dotenvy::dotenv();
    let path = std::env::var("FIELD_MONITOR_CONFIG").unwrap_or_else(|_| "config.toml".into());
    let mut cfg = match std::fs::read_to_string(&path) {
        Ok(t) => toml::from_str(&t).unwrap_or_default(),
        Err(_) => Config::default(),
    };
    if cfg.targets.is_empty() {
        let tp = std::env::var("FIELD_MONITOR_TARGETS").unwrap_or_else(|_| "targets.toml".into());
        if let Ok(tt) = std::fs::read_to_string(&tp) {
            if let Ok(t) = toml::from_str::<TargetsOnly>(&tt) {
                cfg.targets = t.targets;
            }
        }
    }
    cfg
}

/// Helper to parse only the `[[targets]]` table from targets.toml.
#[derive(Debug, serde::Deserialize)]
struct TargetsOnly {
    #[serde(default)]
    targets: Vec<Target>,
}

/// Resolve the host's name (for labeling measurements in the systemd timer).
fn hostname() -> Option<String> {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

fn cmd_probe() {
    let cfg = load_config();
    // Auto-resolve public IP and name if not provided (for the systemd timer).
    let ip = match std::env::var("FIELD_PROBE_IP") {
        Ok(v) if !v.is_empty() => v,
        _ => probe::resolve_public_ip().unwrap_or_else(|| "unknown".into()),
    };
    let label = match std::env::var("FIELD_PROBE_NAME") {
        Ok(v) if !v.is_empty() => v,
        _ => hostname().unwrap_or_else(|| ip.clone()),
    };
    let rows = probe::run(&label, &ip, &cfg.targets);
    println!("PROBE_IP={} NAME={}", ip, label);
    for r in &rows {
        println!(
            "target,{},{},{},{},{},{},{},{},{}",
            r.target,
            r.dns_ip,
            fnum(r.dns_ms),
            r.https_code.map(|c| c.to_string()).unwrap_or("-".into()),
            fnum(r.https_ms),
            r.tcp,
            fnum(r.tcp_ms),
            r.icmp,
            fnum(r.icmp_ms),
        );
    }
    // Debug JSON (not in the log by default, but available).
    if std::env::var("FIELD_MONITOR_JSON").is_ok() {
        println!("{}", serde_json::to_string(&rows).unwrap_or_default());
    }
}

fn cmd_audit() {
    let ip = std::env::var("FIELD_PROBE_IP").unwrap_or_else(|_| "unknown".into());
    let label = std::env::var("FIELD_PROBE_NAME").unwrap_or_else(|_| ip.clone());
    let a = audit::run(&label, &ip);
    println!(
        "AUDIT:{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        a.ip,
        a.name,
        a.sudo_nopass,
        a.os,
        a.ssh_port,
        a.ssh_pw,
        a.ssh_root,
        a.ufw,
        a.fail2ban,
        a.docker,
        a.ports
    );
}

fn cmd_corroborate() {
    let cfg = load_config();
    let rows = corroborate::run(&cfg.targets);
    println!("=== Layer 2: cross-check with a public reference API (read-only) ===");
    println!("CORRO:target,input,ref_anomaly,blocking_type,last_measurement,probe_count");
    for r in &rows {
        println!(
            "CORRO:{},{},{},{},{},{}",
            r.target, r.input, r.ref_anomaly, r.blocking_type, r.last_measurement, r.probe_count
        );
    }
    if std::env::var("FIELD_MONITOR_JSON").is_ok() {
        println!("{}", serde_json::to_string(&rows).unwrap_or_default());
    }
}

/// Orchestrator: run probe + audit on every configured server over SSH.
fn cmd_run_all() {
    let cfg = load_config();
    let self_exe = std::env::current_exe().unwrap_or_default();
    let self_bin = self_exe.to_string_lossy().to_string();
    println!(
        "=== field-monitor run-all: {} servers (rate-limit {}s/target, max 4 in parallel) ===",
        cfg.servers.len(),
        cfg.min_interval_sec
    );
    // Limit parallelism to batches of `batch_size` so a fleet of servers does
    // not fork-bomb the operator host, and so one unresponsive server (now
    // timeout-guarded in ssh.rs) cannot block the rest.
    let min_interval = cfg.min_interval_sec;
    let servers = &cfg.servers;
    let batch = if cfg.batch_size == 0 {
        servers.len().max(1)
    } else {
        cfg.batch_size
    };
    let mut start = 0;
    while start < servers.len() {
        let end = (start + batch).min(servers.len());
        std::thread::scope(|scope| {
            for (i, srv) in servers.iter().enumerate().skip(start).take(end - start) {
                let self_bin = self_bin.clone();
                let self_exe = self_exe.clone();
                scope.spawn(move || {
                    let bin = if srv.arch.trim() == "aarch64" {
                        model::bin_for_arch(&srv.arch, &self_exe)
                            .to_string_lossy()
                            .to_string()
                    } else {
                        self_bin.clone()
                    };
                    let mut out_lines: Vec<String> = Vec::new();
                    for sub in ["probe", "audit"] {
                        match ssh::run_remote(srv, sub, &bin) {
                            Ok(out) => {
                                for line in out.lines() {
                                    // Remote stderr lines (errors like "Exec format error")
                                    // are also collected so a server doesn't vanish silently.
                                    if line.starts_with("# remote-stderr:")
                                        || line.starts_with("PROBE_IP=")
                                        || line.starts_with("AUDIT:")
                                        || line.contains("target,")
                                    {
                                        out_lines.push(format!(
                                            "[{}] {} -> {}",
                                            i + 1,
                                            srv.ip,
                                            line
                                        ));
                                    }
                                }
                            }
                            Err(e) => {
                                out_lines.push(format!("[{}] {} — error: {}", i + 1, srv.ip, e))
                            }
                        }
                    }
                    // Print this server's block atomically to avoid interleaving.
                    let block = out_lines.join("\n");
                    if !block.is_empty() {
                        println!("{}", block);
                    }
                });
            }
        });
        // Rate-limit: minimum pause between server batches (fleet throttle).
        if min_interval > 0 {
            std::thread::sleep(std::time::Duration::from_secs(min_interval));
        }
        start = end;
    }
}

fn cmd_aggregate() {
    let dir = std::env::var("RESULTS_DIR").unwrap_or_else(|_| "results".into());
    let rows = aggregate::load_probe_logs(&PathBuf::from(&dir));
    let s = aggregate::summarize(rows);
    aggregate::print_summary(&s);

    // Generate markdown report if FIELD_MONITOR_MD env is set
    if let Ok(md_path) = std::env::var("FIELD_MONITOR_MD") {
        let out_path = PathBuf::from(&md_path);
        if let Err(e) = aggregate::generate_markdown_report(&s, &out_path) {
            eprintln!("Failed to write markdown report: {}", e);
        } else {
            eprintln!("Markdown report written to {}", out_path.display());
        }
    }

    if std::env::var("FIELD_MONITOR_JSON").is_ok() {
        println!("{}", serde_json::to_string(&s).unwrap_or_default());
    }
}

/// Format an optional metric as a string (`-` when absent).
fn fnum(v: Option<u64>) -> String {
    v.map(|x| x.to_string()).unwrap_or("-".into())
}
