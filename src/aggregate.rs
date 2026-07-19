//! aggregate — summarize logs from all vantage points (probe + audit).

use std::collections::BTreeMap;
use std::path::Path;

use crate::model::*;

/// Parse an `AUDIT:`-prefixed line from the audit log.
/// Returns None if the line lacks 11 pipe-delimited fields.
#[allow(dead_code)] // public parser API; used in tests and by external consumers
pub fn parse_audit_line(line: &str) -> Option<AuditRow> {
    let r = line.strip_prefix("AUDIT:")?;
    let p: Vec<&str> = r.split('|').collect();
    if p.len() < 11 {
        return None;
    }
    // Defensive: use first() to avoid panic on malformed input (clippy-friendly)
    Some(AuditRow {
        ip: p.first().map(|s| s.to_string())?,
        name: p.get(1).map(|s| s.to_string())?,
        sudo_nopass: p.get(2).map(|s| s.to_string())?,
        os: p.get(3).map(|s| s.to_string())?,
        ssh_port: p.get(4).map(|s| s.to_string())?,
        ssh_pw: p.get(5).map(|s| s.to_string())?,
        ssh_root: p.get(6).map(|s| s.to_string())?,
        ufw: p.get(7).map(|s| s.to_string())?,
        fail2ban: p.get(8).map(|s| s.to_string())?,
        docker: p.get(9).map(|s| s.to_string())?,
        ports: p.get(10).map(|s| s.to_string())?,
    })
}

/// Aggregate `ProbeRow`s into a `Summary` and compute anomalies.
pub fn summarize(rows: Vec<ProbeRow>) -> Summary {
    let mut servers: BTreeMap<String, String> = BTreeMap::new();
    let mut anomalies = Vec::new();
    for r in &rows {
        servers.entry(r.server.clone()).or_insert(r.label.clone());
        let bad = r.sane
            && (r.https_code.is_some_and(|c| c != 200)
                || r.https_ms.is_some_and(|m| m > 2000)
                || (r.tcp != "open" && r.tcp != "-" && !r.tcp.is_empty()));
        if bad {
            anomalies.push(Anomaly {
                ip: r.server.clone(),
                label: r.label.clone(),
                target: r.target.clone(),
                https_code: r.https_code,
                https_ms: r.https_ms,
                tcp: r.tcp.clone(),
            });
        }
    }
    Summary {
        n_points: servers.len(),
        servers: servers
            .into_iter()
            .map(|(ip, label)| ServerInfo { ip, label })
            .collect(),
        rows,
        anomalies,
    }
}

/// Read a log directory, collect `ProbeRow`s from the CSV blocks.
pub fn load_probe_logs(dir: &Path) -> Vec<ProbeRow> {
    let mut rows = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) != Some("log") {
                continue;
            }
            let text = match std::fs::read_to_string(&path) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let mut cur_ip = "?".to_string();
            let mut cur_label = "?".to_string();
            for line in text.lines() {
                // PROBE_IP may be prefixed with "[N] IP ->" from run-all.
                if let Some(rest) = line.split("PROBE_IP=").nth(1) {
                    let mut it = rest.split_whitespace();
                    cur_ip = it.next().unwrap_or("?").trim().to_string();
                    if let Some(n) = it.next() {
                        cur_label = n.trim_start_matches("NAME=").trim().to_string();
                    }
                    continue;
                }
                if line.contains("AUDIT:") {
                    continue; // audit lines are not aggregated into the probe summary
                }
                // Probe lines may be prefixed with "[N] IP ->" from run-all.
                let csv = match line.find("target,") {
                    Some(idx) => &line[idx..],
                    None => continue,
                };
                let f: Vec<&str> = csv.split(',').collect();
                // Line format: target,<name>,<dns_ip>,<dns_ms>,<https>,<https_ms>,<tcp>,<tcp_ms>,<icmp>,<icmp_ms> (10 fields).
                // f[0] == "target" (literal label); real data is shifted by +1.
                if f.len() != 10 || !f[1].chars().next().is_some_and(|c| c.is_alphabetic()) {
                    continue;
                }
                let parse_u = |s: &str| s.parse::<u64>().ok();
                rows.push(ProbeRow {
                    server: cur_ip.clone(),
                    label: cur_label.clone(),
                    target: f[1].into(),
                    dns_ip: f[2].into(),
                    dns_ms: parse_u(f[3]),
                    https_code: f[4].parse::<u16>().ok(),
                    https_ms: parse_u(f[5]),
                    tcp: f[6].into(),
                    tcp_ms: parse_u(f[7]),
                    icmp: f[8].into(),
                    icmp_ms: parse_u(f[9]),
                    sane: f.iter().all(|v| {
                        let n = v.parse::<u64>().ok();
                        n.is_none() || n.unwrap() < 60_000
                    }),
                });
            }
        }
    }
    rows
}

/// Print the summary to stdout (compact, like the bash aggregator).
pub fn print_summary(s: &Summary) {
    println!("\n=== FIELD MONITOR SUMMARY, points: {} ===\n", s.n_points);
    println!("server          label          target       HTTPS  ms     DNSms TCP    ICMP");
    println!("{}", "-".repeat(68));
    // Group rows by server for display
    let mut server_rows: std::collections::BTreeMap<String, Vec<&ProbeRow>> =
        std::collections::BTreeMap::new();
    for r in &s.rows {
        server_rows.entry(r.server.clone()).or_default().push(r);
    }
    for srv in &s.servers {
        if let Some(rows) = server_rows.get(&srv.ip) {
            for r in rows {
                println!(
                    "{}  {}  {}  {}  {}  {}  {}  {}",
                    r.server,
                    r.label,
                    r.target,
                    r.https_code.map(|c| c.to_string()).unwrap_or("-".into()),
                    r.https_ms.map(|m| m.to_string()).unwrap_or("-".into()),
                    r.dns_ms.map(|m| m.to_string()).unwrap_or("-".into()),
                    r.tcp,
                    r.icmp
                );
            }
        }
        println!();
    }
    println!("=== ANOMALIES ===");
    if s.anomalies.is_empty() {
        println!("  none (all targets 200/open, latencies normal)");
    } else {
        for a in &s.anomalies {
            println!(
                "  {} {} {}: HTTPS={:?} ms={:?} TCP={}",
                a.ip, a.label, a.target, a.https_code, a.https_ms, a.tcp
            );
        }
    }
}

/// Generate a markdown report file from the summary.
///
/// Output format:
/// - Header with timestamp and point count
/// - Per-server sections with tables (latest measurement per target)
/// - Anomalies section (if any)
pub fn generate_markdown_report(s: &Summary, out_path: &Path) -> std::io::Result<()> {
    use std::io::Write;

    let timestamp = crate::model::timestamp_iso8601(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );

    // Archive existing report if it exists
    if out_path.exists() {
        let stem = out_path.file_stem().unwrap_or_default().to_string_lossy();
        let parent = out_path.parent().unwrap_or(Path::new("."));
        let archive_path = parent.join(format!("{}-{}.md", stem, timestamp));
        if archive_path != out_path {
            let _ = std::fs::copy(out_path, &archive_path);
        }
    }

    let mut content = String::new();
    content.push_str("# Field Monitor Report\n\n");
    content.push_str(&format!("**Generated:** {}\n\n", timestamp));
    content.push_str(&format!("**Vantage points:** {}\n\n", s.n_points));

    // Executive summary
    if !s.anomalies.is_empty() {
        content.push_str(&format!(
            "**Anomalies:** {} (see below)\n\n",
            s.anomalies.len()
        ));
    } else {
        content.push_str("**Status:** All OK\n\n");
    }

    // Group rows by server, take latest per target
    let mut server_rows: BTreeMap<String, Vec<&ProbeRow>> = BTreeMap::new();
    for r in &s.rows {
        server_rows.entry(r.server.clone()).or_default().push(r);
    }

    for srv in &s.servers {
        content.push_str(&format!("## {}\n\n", srv.label));

        if let Some(rows) = server_rows.get(&srv.ip) {
            // Take latest measurement per target (by DNS ms as proxy for "most recent")
            let mut latest: BTreeMap<&str, &ProbeRow> = BTreeMap::new();
            for r in rows {
                latest.entry(&r.target).or_insert(r);
            }

            content
                .push_str("| Target | DNS IP | HTTPS | Latency (ms) | DNS (ms) | TCP | ICMP |\n");
            content
                .push_str("|--------|--------|-------|--------------|----------|-----|------|\n");
            for r in latest.values() {
                // Status: distinguish a real success from "could not measure".
                let status = if r.tcp == "closed" {
                    "BLOCKED"
                } else if r.https_ms.map(|m| m > 2000).unwrap_or(false) {
                    "SLOW"
                } else if r.https_code == Some(200) || r.tcp == "open" || r.icmp == "ok" {
                    "OK"
                } else {
                    "NOT MEASURED"
                };
                content.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {} | {} | {}\n",
                    r.target,
                    r.dns_ip,
                    r.https_code.map(|c| c.to_string()).unwrap_or("-".into()),
                    r.https_ms
                        .map(|m| format!("{} ms", m))
                        .unwrap_or("-".into()),
                    r.dns_ms.map(|m| format!("{} ms", m)).unwrap_or("-".into()),
                    r.tcp,
                    r.icmp,
                    status
                ));
            }
            content.push('\n');
        } else {
            content.push_str("(no data)\n\n");
        }
    }

    if !s.anomalies.is_empty() {
        content.push_str("## Anomalies\n\n");
        content.push_str("| Server | Label | Target | HTTPS | Latency (ms) | TCP | Status |\n");
        content.push_str("|--------|-------|--------|-------|--------------|-----|--------|\n");
        for a in &s.anomalies {
            let status = if a.https_code.unwrap_or(0) != 200 {
                "HTTPS_FAIL"
            } else {
                "HIGH_LATENCY"
            };
            content.push_str(&format!(
                "| {} | {} | {} | {:?} | {:?} | {} | {} |\n",
                a.ip, a.label, a.target, a.https_code, a.https_ms, a.tcp, status
            ));
        }
    } else {
        content
            .push_str("## Anomalies\n\nNone detected (all targets 200/open, latencies normal).\n");
    }

    let mut file = std::fs::File::create(out_path)?;
    file.write_all(content.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn parse_audit_line_ok() {
        let line = "AUDIT:YOUR_SERVER_IP|server-1|no|Ubuntu 24.04|22|default|yes|none|none|none|";
        let a = parse_audit_line(line).expect("should parse");
        assert_eq!(a.ip, "YOUR_SERVER_IP");
        assert_eq!(a.name, "server-1");
        assert_eq!(a.os, "Ubuntu 24.04");
        assert_eq!(a.ssh_port, "22");
    }

    #[test]
    fn parse_audit_line_too_short_is_none() {
        assert!(parse_audit_line("AUDIT:only|two|fields").is_none());
        assert!(parse_audit_line("not an audit line").is_none());
    }

    #[test]
    fn summarize_flags_non_200() {
        let rows = vec![ProbeRow {
            server: "YOUR_SERVER_IP".into(),
            label: "server-1".into(),
            target: "example".into(),
            dns_ip: "YOUR_SERVER_IP".into(),
            dns_ms: Some(10),
            https_code: Some(403),
            https_ms: Some(120),
            tcp: "open".into(),
            tcp_ms: Some(20),
            icmp: "ok".into(),
            icmp_ms: Some(5),
            sane: true,
        }];
        let s = summarize(rows);
        assert_eq!(s.anomalies.len(), 1);
        assert_eq!(s.anomalies[0].target, "example");
    }

    #[test]
    fn summarize_flags_tcp_closed() {
        let rows = vec![ProbeRow {
            server: "YOUR_SERVER_IP".into(),
            label: "server-1".into(),
            target: "example".into(),
            dns_ip: "YOUR_SERVER_IP".into(),
            dns_ms: Some(10),
            https_code: None,
            https_ms: None,
            tcp: "closed".into(),
            tcp_ms: Some(20),
            icmp: "ok".into(),
            icmp_ms: Some(5),
            sane: true,
        }];
        let s = summarize(rows);
        assert_eq!(s.anomalies.len(), 1);
    }

    #[test]
    fn summarize_clean_has_no_anomalies() {
        let rows = vec![ProbeRow {
            server: "YOUR_SERVER_IP".into(),
            label: "server-1".into(),
            target: "example".into(),
            dns_ip: "YOUR_SERVER_IP".into(),
            dns_ms: Some(10),
            https_code: Some(200),
            https_ms: Some(120),
            tcp: "open".into(),
            tcp_ms: Some(20),
            icmp: "ok".into(),
            icmp_ms: Some(5),
            sane: true,
        }];
        let s = summarize(rows);
        assert!(s.anomalies.is_empty());
    }

    #[test]
    fn load_probe_logs_parses_run_all_format() {
        // Real run-all output format: "[N] IP -> target,..." and "PROBE_IP=... NAME=...".
        let dir = std::env::temp_dir().join("fm_test_logs");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("server-1.log");
        std::fs::write(
            &p,
            "[1] YOUR_SERVER_IP -> PROBE_IP=YOUR_SERVER_IP NAME=server-1\n[1] YOUR_SERVER_IP -> target,example,YOUR_DNS_IP,32,200,391,open,77,-,-\n[1] YOUR_SERVER_IP -> target,resolver,YOUR_RESOLVER_IP,0,-,-,-,-,ok,4\n",
        )
        .unwrap();
        let rows = load_probe_logs(Path::new(&dir));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].server, "YOUR_SERVER_IP");
        assert_eq!(rows[0].label, "server-1");
        assert_eq!(rows[0].target, "example");
        assert_eq!(rows[0].https_code, Some(200));
        assert_eq!(rows[1].target, "resolver");
        assert_eq!(rows[1].icmp, "ok");
        // cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }
}
