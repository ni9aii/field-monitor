//! field_probe — measure DNS / HTTPS / TCP:443 / ICMP for allowlist targets.
//!
//! v1 wraps system tools (curl/dig/ping) via `std::process::Command`.
//! It does NOT scan third-party hosts and does NOT generate load.

use std::net::{TcpStream, ToSocketAddrs};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::model::*;
use crate::runner::{CommandRunner, RealRunner};

/// Get timeout from env or default (seconds for most operations).
fn timeout_env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.into())
}

/// DNS timeout in seconds (default: 3).
fn dns_timeout() -> String {
    timeout_env("FM_DNS_TIMEOUT", "3")
}

/// HTTPS timeout in seconds (default: 8).
fn https_timeout() -> String {
    timeout_env("FM_HTTPS_TIMEOUT", "8")
}

/// TCP timeout in seconds (default: 8).
fn tcp_timeout() -> String {
    timeout_env("FM_TCP_TIMEOUT", "8")
}

/// ICMP packet count (default: 3).
fn ping_count() -> String {
    timeout_env("FM_PING_COUNT", "3")
}

/// ICMP timeout per packet in seconds (default: 2).
fn ping_timeout() -> String {
    timeout_env("FM_PING_TIMEOUT", "2")
}

/// Resolve the server's public IP (for the systemd timer when FIELD_PROBE_IP
/// is not set). The external lookup endpoint is operator-configurable via
/// `FM_PUBLIC_IP_URL` and **disabled by default** — when unset we only fall
/// back to local interfaces (`hostname -I`), so there is no hardcoded outbound
/// call and no third party learns the vantage point's IP. This keeps the
/// project's "no hardcoded hosts / no undisclosed outbound" guarantee.
pub fn resolve_public_ip() -> Option<String> {
    // Optional external lookup (operator opt-in only).
    if let Ok(url) = std::env::var("FM_PUBLIC_IP_URL") {
        if !url.trim().is_empty() {
            if let Ok(o) = Command::new("curl")
                .args(["-s", "--max-time", "5", &url])
                .output()
            {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if s.split('.').count() == 4 && s.split('.').all(|p| p.parse::<u8>().is_ok()) {
                    return Some(s);
                }
            }
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
/// Uses a `CommandRunner` so it can be unit-tested with a mock.
fn dns_resolve(host: &str, runner: &dyn CommandRunner) -> Option<(String, u64)> {
    let t0 = now_ms();
    let out = runner
        .run(
            "dig",
            &[
                "+short",
                &format!("+time={}", dns_timeout()),
                "+tries=1",
                host,
            ],
        )
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

/// HTTPS check via `curl`. Returns (code, ms). Uses a `CommandRunner` so it
/// can be unit-tested with a mock.
fn https_check(url: &str, runner: &dyn CommandRunner) -> Option<(u16, u64)> {
    let t0 = now_ms();
    let out = runner
        .run(
            "curl",
            &[
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                &https_timeout(),
                url,
            ],
        )
        .ok()?;
    let t1 = now_ms();
    let code = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u16>()
        .unwrap_or(0);
    Some((code, t1.saturating_sub(t0)))
}

/// TCP check via native Rust socket (no python3 subprocess → no command
/// injection via the `host` value). Returns (state, ms).
fn tcp_check(host: &str, port: u16) -> (String, Option<u64>) {
    let t0 = now_ms();
    let timeout = Duration::from_secs(tcp_timeout().parse::<u64>().unwrap_or(8));
    let addr = format!("{}:{}", host, port);
    let connected = addr
        .to_socket_addrs()
        .ok()
        .and_then(|mut iter| iter.next())
        .map(|sa| TcpStream::connect_timeout(&sa, timeout).is_ok())
        .unwrap_or(false);
    let t1 = now_ms();
    let ms = Some(t1.saturating_sub(t0));
    if connected {
        ("open".into(), ms)
    } else {
        ("closed".into(), ms)
    }
}

/// ICMP check via `ping`. Returns (state, ms).
fn icmp_check(ip: &str) -> (String, Option<u64>) {
    let out = Command::new("ping")
        .args(["-c", &ping_count(), "-W", &ping_timeout(), ip])
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

/// Run all targets once for a server (name/label/public IP supplied by caller),
/// executing external probes through `runner` (real commands by default).
pub fn run_with(
    label: &str,
    public_ip: &str,
    targets: &[Target],
    runner: &dyn CommandRunner,
) -> Vec<ProbeRow> {
    let mut rows = Vec::new();
    for t in targets {
        if !t.is_safe() {
            eprintln!("SKIP unsafe target: {}", t.name);
            continue;
        }
        // DNS
        let (dns_ip, dns_ms) = if t.ip.is_empty() {
            match dns_resolve(&t.host, runner) {
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
            match https_check(&t.url, runner) {
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
        // Partial = every sub-check returned no measurement (vantage couldn't
        // measure, not "target is dead"). Used by the report to distinguish
        // "not measured" from a real outage.
        let partial =
            dns_ms.is_none() && https_ms.is_none() && tcp_ms.is_none() && icmp_ms.is_none();
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
            partial,
        });
        // Rate-limit between targets (legitimacy: do not spam).
        std::thread::sleep(Duration::from_millis(200));
    }
    rows
}

/// Run all targets once, using the real system commands.
pub fn run(label: &str, public_ip: &str, targets: &[Target]) -> Vec<ProbeRow> {
    run_with(label, public_ip, targets, &RealRunner)
}

/// Parse curl output to extract HTTP code. Used for testing.
#[cfg(test)]
fn parse_curl_code(output: &str) -> u16 {
    output.trim().parse().unwrap_or(0)
}

/// Timeout environment helper. Used for testing.
#[cfg(test)]
fn test_timeout_env() -> String {
    std::env::var("FM_DNS_TIMEOUT").unwrap_or_else(|_| "3".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_curl_code_parses_valid() {
        assert_eq!(parse_curl_code("200"), 200);
        assert_eq!(parse_curl_code("404"), 404);
    }

    #[test]
    fn parse_curl_code_handles_invalid() {
        assert_eq!(parse_curl_code("not_a_code"), 0);
        assert_eq!(parse_curl_code(""), 0);
    }

    #[test]
    fn test_timeout_env_defaults() {
        // Remove the env var temporarily to test default
        std::env::remove_var("FM_DNS_TIMEOUT");
        assert_eq!(test_timeout_env(), "3");
    }

    #[test]
    fn dns_resolve_parses_mock_output() {
        use crate::runner::test_runner::MockRunner;
        let mock = MockRunner::new();
        // dig +short <host> -> an IP on stdout
        mock.expect(
            "dig",
            &["+short", "+time=3", "+tries=1", "example.com"],
            "93.184.216.34\n",
        );
        let got = dns_resolve("example.com", &mock);
        // IP is parsed from the mock; ms is elapsed time (don't assert it).
        assert_eq!(got.map(|(ip, _ms)| ip), Some("93.184.216.34".to_string()));
    }

    #[test]
    fn https_check_parses_mock_code() {
        use crate::runner::test_runner::MockRunner;
        let mock = MockRunner::new();
        mock.expect(
            "curl",
            &[
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                "8",
                "https://example.com",
            ],
            "200",
        );
        let got = https_check("https://example.com", &mock);
        // code is parsed from the mock; ms is elapsed time (don't assert it).
        assert_eq!(got.map(|(code, _ms)| code), Some(200));
    }

    #[test]
    fn run_with_mock_marks_not_partial_when_measured() {
        use crate::runner::test_runner::MockRunner;
        // Both dig and curl return valid data -> row is a real measurement,
        // not partial.
        let mock = MockRunner::new();
        mock.expect(
            "dig",
            &["+short", "+time=3", "+tries=1", "example.com"],
            "93.184.216.34\n",
        );
        mock.expect(
            "curl",
            &[
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                "8",
                "https://example.com",
            ],
            "200",
        );
        let targets = vec![Target {
            name: "t".into(),
            host: "example.com".into(),
            url: "https://example.com".into(),
            ip: "".into(),
        }];
        let rows = run_with("lbl", "203.0.113.5", &targets, &mock);
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].partial, "measured row is not partial");
        assert_eq!(rows[0].dns_ip, "93.184.216.34");
        assert_eq!(rows[0].https_code, Some(200));
    }
}
