//! Shared log-line format for probe/audit/corroborate emit + parse.
//!
//! Single source of truth so the writer (`cmd_probe`) and the reader
//! (`aggregate::load_probe_logs`) cannot silently drift apart. A round-trip
//! test (`emit -> parse`) guards this.

use crate::model::ProbeRow;

/// Prefix of a probe CSV line, e.g. `target,github.com,...`.
pub const PROBE_PREFIX: &str = "target,";
/// Prefix of an audit line.
#[allow(dead_code)]
pub const AUDIT_PREFIX: &str = "AUDIT:";
/// Prefix of a corroboration line.
#[allow(dead_code)]
pub const CORRO_PREFIX: &str = "CORRO:";
/// Prefix of the server identity banner line.
#[allow(dead_code)]
pub const PROBE_IP_PREFIX: &str = "PROBE_IP=";

/// Number of CSV fields in a probe line (excluding the literal `target,`
/// label at `f[0]`).
#[allow(dead_code)]
pub const PROBE_FIELDS: usize = 10;

/// Format `Some(n)` / `None` as the integer string or `-` placeholder.
pub fn fnum(v: Option<u64>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "-".to_string(),
    }
}

/// Serialize a probe row to its canonical CSV line.
pub fn emit_probe_row(r: &ProbeRow) -> String {
    format!(
        "{}{},{},{},{},{},{},{},{},{},{},{}",
        PROBE_PREFIX,
        r.target,
        r.dns_ip,
        fnum(r.dns_ms),
        r.https_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "-".into()),
        fnum(r.https_ms),
        r.tcp,
        fnum(r.tcp_ms),
        r.icmp,
        fnum(r.icmp_ms),
        if r.partial { 1 } else { 0 },
        r.ts,
    )
}

/// Parse a probe CSV line (with an optional `[N] IP ->` run-all prefix) into a
/// `ProbeRow`. Returns `None` if the line is not a probe line or is malformed.
///
/// `server_ip` / `server_label` come from the surrounding `PROBE_IP=` banner
/// (set by the caller); this only extracts the per-target fields.
pub fn parse_probe_line(line: &str, server_ip: &str, server_label: &str) -> Option<ProbeRow> {
    // Strip an optional run-all prefix like "[2] 1.2.3.4 -> ".
    let csv = line.find(PROBE_PREFIX).map(|idx| &line[idx..])?;
    let f: Vec<&str> = csv.split(',').collect();
    // Accept both formats for backward compatibility with older agents:
    //   10 fields: target,dns_ip,dns_ms,https_code,https_ms,tcp,tcp_ms,icmp,icmp_ms
    //   11 fields: ... + trailing `partial` (newer agents, via emit_probe_row)
    //   12 fields: ... + trailing `partial`,`ts` (newest agents, time window)
    // Reject anything shorter than 10 or lines whose 2nd field isn't a target name.
    if f.len() < 10 || !f[1].chars().next().is_some_and(|c| c.is_alphabetic()) {
        return None;
    }
    let parse_u = |s: &str| s.parse::<u64>().ok();
    let partial = f.get(10).map(|v| *v == "1").unwrap_or(false);
    let ts = f.get(11).and_then(|v| parse_u(v)).unwrap_or(0);
    let row = ProbeRow {
        server: server_ip.to_string(),
        label: server_label.to_string(),
        target: f[1].to_string(),
        dns_ip: f[2].to_string(),
        dns_ms: parse_u(f[3]),
        https_code: f[4].parse::<u16>().ok(),
        https_ms: parse_u(f[5]),
        tcp: f[6].to_string(),
        tcp_ms: parse_u(f[7]),
        icmp: f[8].to_string(),
        icmp_ms: parse_u(f[9]),
        // Sane = no field parses to a value >= 60000 (defensive; real rows
        // carry sane=true from the probe side).
        sane: ![f[3], f[5], f[7], f[9]]
            .iter()
            .any(|v| v.parse::<u64>().map(|n| n >= 60_000).unwrap_or(false)),
        partial,
        ts,
    };
    Some(row)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ProbeRow {
        ProbeRow {
            server: "203.0.113.5".into(),
            label: "edge-1".into(),
            target: "github.com".into(),
            dns_ip: "93.184.216.34".into(),
            dns_ms: Some(12),
            https_code: Some(200),
            https_ms: Some(45),
            tcp: "open".into(),
            tcp_ms: Some(30),
            icmp: "ok".into(),
            icmp_ms: Some(20),
            sane: true,
            partial: false,
            ts: 1753000000,
        }
    }

    #[test]
    fn round_trip_preserves_fields() {
        let r = sample();
        let line = emit_probe_row(&r);
        assert!(line.starts_with(PROBE_PREFIX));
        let parsed = parse_probe_line(&line, "203.0.113.5", "edge-1").expect("parses back");
        assert_eq!(parsed.target, r.target);
        assert_eq!(parsed.dns_ip, r.dns_ip);
        assert_eq!(parsed.dns_ms, r.dns_ms);
        assert_eq!(parsed.https_code, r.https_code);
        assert_eq!(parsed.https_ms, r.https_ms);
        assert_eq!(parsed.tcp, r.tcp);
        assert_eq!(parsed.tcp_ms, r.tcp_ms);
        assert_eq!(parsed.icmp, r.icmp);
        assert_eq!(parsed.icmp_ms, r.icmp_ms);
        assert!(!parsed.partial);
    }

    #[test]
    fn round_trip_with_run_all_prefix() {
        let r = sample();
        let line = format!("[2] 203.0.113.5 -> {}", emit_probe_row(&r));
        let parsed = parse_probe_line(&line, "203.0.113.5", "edge-1").expect("parses back");
        assert_eq!(parsed.target, "github.com");
    }

    #[test]
    fn parse_rejects_short_line() {
        assert!(parse_probe_line("target,only,two", "ip", "lbl").is_none());
    }

    #[test]
    fn parse_rejects_nonalpha_target() {
        assert!(parse_probe_line("target,,93.0.0.1,-,-,-,-,-,-,-,0", "ip", "lbl").is_none());
    }
}
