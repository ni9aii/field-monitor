//! aggregate — summarize logs from all vantage points (probe + audit).

use std::collections::BTreeMap;
use std::path::Path;

use crate::model::*;

/// Parse an `AUDIT:`-prefixed line from the audit log.
#[allow(dead_code)] // public parser API; used in tests and by external consumers
pub fn parse_audit_line(line: &str) -> Option<AuditRow> {
    let r = line.strip_prefix("AUDIT:")?;
    let p: Vec<&str> = r.split('|').collect();
    if p.len() < 11 {
        return None;
    }
    Some(AuditRow {
        ip: p[0].into(),
        name: p[1].into(),
        sudo_nopass: p[2].into(),
        os: p[3].into(),
        ssh_port: p[4].into(),
        ssh_pw: p[5].into(),
        ssh_root: p[6].into(),
        ufw: p[7].into(),
        fail2ban: p[8].into(),
        docker: p[9].into(),
        ports: p[10].into(),
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
                    cur_ip = it.next().unwrap_or("?").trim_matches('\'').to_string();
                    if let Some(n) = it.next() {
                        cur_label = n.trim_start_matches("NAME=").trim_matches('\'').to_string();
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
    for srv in &s.servers {
        for tg in [
            "example",
            "example-api",
            "service-a",
            "service-b",
            "service-c",
            "resolver",
        ] {
            for r in &s.rows {
                if r.server == srv.ip && r.target == tg {
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
