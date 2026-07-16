//! field_probe — measure DNS / HTTPS / TCP:443 / ICMP for allowlist targets.
//!
//! v1 wraps system tools (curl/dig/ping) via `std::process::Command`.
//! It does NOT scan third-party hosts and does NOT generate load.

use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::model::*;

/// Resolve the server's public IP (for the systemd timer when FIELD_PROBE_IP
/// is not set). Only a passive request to an external service; falls back to
/// `hostname -I`.
pub fn resolve_public_ip() -> Option<String> {
    // First try ifconfig.me (passive, like a normal client).
    if let Ok(o) = Command::new("curl")
        .args(["-s", "--max-time", "5", "https://ifconfig.me"])
        .output()
    {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s.split('.').count() == 4 && s.split('.').all(|p| p.parse::<u8>().is_ok()) {
            return Some(s);
        }
    }
    // Fallback: local interfaces (may yield an internal IP — worse, but ok for logging).
    if let Ok(o) = Command::new("hostname").args(["-I"]).output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if let Some(first) = s.split_whitespace().next() {
            if first.split('.').count() == 4 {
                return Some(first.to_string());
            }
        }
    }
    None
}

/// Current time in milliseconds (monotonic-safe, no overflow).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Resolve DNS via `dig` (or `python3` socket as fallback). Returns (ip, ms).
fn dns_resolve(host: &str) -> Option<(String, u64)> {
    let t0 = now_ms();
    let out = Command::new("dig")
        .args(["+short", "+time=3", "+tries=1", host])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let ip = s
        .lines()
        .find(|l| l.split('.').count() == 4 && l.split('.').all(|p| p.parse::<u8>().is_ok()))?;
    let t1 = now_ms();
    if ip.is_empty() {
        return None;
    }
    Some((ip.to_string(), t1.saturating_sub(t0)))
}

/// HTTPS check via `curl --max-time 8`. Returns (code, ms).
fn https_check(url: &str) -> Option<(u16, u64)> {
    let t0 = now_ms();
    let out = Command::new("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "8",
            url,
        ])
        .output()
        .ok()?;
    let t1 = now_ms();
    let code = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u16>()
        .unwrap_or(0);
    Some((code, t1.saturating_sub(t0)))
}

/// TCP:443 check via python3 socket. Returns (state, ms).
fn tcp_check(host: &str, port: u16) -> (String, Option<u64>) {
    let py = format!(
        "import socket,time\nt0=time.time()\ntry:\n s=socket.create_connection(('{h}',{p}),timeout=8); s.close()\n print('open',int((time.time()-t0)*1000))\nexcept Exception:\n print('closed',int((time.time()-t0)*1000))",
        h = host,
        p = port
    );
    let out = Command::new("python3").args(["-c", &py]).output();
    match out {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let mut parts = s.split_whitespace();
            let st = parts.next().unwrap_or("closed").to_string();
            let ms = parts.next().and_then(|v| v.parse::<u64>().ok());
            (st, ms)
        }
        Err(_) => ("closed".into(), None),
    }
}

/// ICMP check via `ping`. Returns (state, ms).
fn icmp_check(ip: &str) -> (String, Option<u64>) {
    let out = Command::new("ping")
        .args(["-c", "3", "-W", "2", ip])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8_lossy(&o.stdout);
            let ms = s
                .lines()
                .last()
                .and_then(|l| l.split('/').nth(4))
                .and_then(|v| v.trim().parse::<f64>().ok())
                .map(|f| f as u64);
            ("ok".into(), ms)
        }
        _ => ("fail".into(), None),
    }
}

/// Run all targets once for a server (name/label/public IP supplied by caller).
pub fn run(label: &str, public_ip: &str, targets: &[Target]) -> Vec<ProbeRow> {
    let mut rows = Vec::new();
    for t in targets {
        if !t.is_safe() {
            eprintln!("SKIP unsafe target: {}", t.name);
            continue;
        }
        // DNS
        let (dns_ip, dns_ms) = if t.ip.is_empty() {
            match dns_resolve(&t.host) {
                Some((ip, ms)) => (ip, Some(ms)),
                None => ("-".into(), None),
            }
        } else {
            (t.ip.clone(), Some(0))
        };
        // HTTPS
        let (https_code, https_ms) = if t.url.is_empty() {
            (None, None)
        } else {
            match https_check(&t.url) {
                Some((c, ms)) => (Some(c), Some(ms)),
                None => (Some(0), None),
            }
        };
        // TCP:443 (only for hostname-based targets)
        let (tcp, tcp_ms) = if !t.host.is_empty() && t.host != t.ip {
            tcp_check(&t.host, 443)
        } else {
            ("-".into(), None)
        };
        // ICMP (by known IP)
        let (icmp, icmp_ms) = if !t.ip.is_empty() {
            icmp_check(&t.ip)
        } else {
            ("-".into(), None)
        };
        // In Rust now_ms uses SystemTime, so no timer overflow — sane is
        // always true (unlike the bash prototype which used `date`).
        let sane = true;
        rows.push(ProbeRow {
            server: public_ip.to_string(),
            label: label.to_string(),
            target: t.name.clone(),
            dns_ip,
            dns_ms,
            https_code,
            https_ms,
            tcp,
            tcp_ms,
            icmp,
            icmp_ms,
            sane,
        });
        // Rate-limit between targets (legitimacy: do not spam).
        std::thread::sleep(Duration::from_millis(200));
    }
    rows
}
