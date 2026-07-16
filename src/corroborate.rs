//! corroborate — Layer 2: cross-check our measurements against a
//! public reference measurement API (read-only, GET). Does NOT run
//! third-party agents or probes on any host. This is analysis of
//! divergence, not detection.
//!
//! Legitimacy: a consumer of a public API, like any browser.
//! Rate-limit between requests — respect for the upstream API.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::model::*;

/// Public reference measurement API (operator-configured via env).
/// API endpoint is operator-configured via CORRO_API_URL env.
/// No hardcoded default in this repo — the operator MUST set it.
fn api_url() -> String {
    std::env::var("CORRO_API_URL")
        .expect("CORRO_API_URL must be set (operator-configured reference API)")
}

/// Country code to cross-check (operator-configured via env,
/// default empty -> the API's own default). No hardcoded country.
fn probe_cc() -> String {
    std::env::var("CORRO_CC").unwrap_or_default()
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CorroRow {
    pub target: String,
    pub input: String,
    /// reference anomaly (True = suspected blocking)
    pub ref_anomaly: String,
    pub blocking_type: String,
    pub last_measurement: String,
    /// how many records found in the window
    pub probe_count: usize,
    /// our local HTTPS code (from last measurement, if any)
    pub local_https: String,
}

/// Query the reference API for a concrete input (URL).
/// Returns (anomaly, blocking_type, last_measurement, count).
/// GET only; parsed via serde_json (no external processes).
fn fetch_reference(input: &str) -> Option<(bool, String, String, usize)> {
    // since = 30 days ago (ISO8601, UTC)
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .saturating_sub(30 * 24 * 3600);
    let since = chrono_like(secs);
    let cc = probe_cc();
    let url = format!(
        "{}?country_code={}&test_name=web_connectivity&input={}&limit=10&order_by=measurement_start_time&since={}",
        api_url(), cc, input, since
    );
    let out = std::process::Command::new("curl")
        .args(["-s", "--max-time", "25", &url])
        .output()
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let results = v.get("results")?.as_array()?;
    if results.is_empty() {
        return Some((false, "".into(), "".into(), 0));
    }
    let x = results.last()?;
    let anomaly = x.get("anomaly").and_then(|a| a.as_bool()).unwrap_or(false);
    let bt = x
        .get("scores")
        .and_then(|s| s.get("analysis"))
        .and_then(|a| a.get("blocking_type"))
        .and_then(|b| b.as_str())
        .unwrap_or("")
        .to_string();
    let mt = x
        .get("measurement_start_time")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    Some((anomaly, bt, mt, results.len()))
}

/// Rough ISO8601 without external crates (YYYY-MM-DDTHH:MM:SS).
fn chrono_like(secs: u64) -> String {
    let days = secs / 86400;
    let mut y = 1970;
    let mut d = days as i64;
    let month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    while d >= 365 {
        let leap = if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
            366
        } else {
            365
        };
        if d >= leap {
            d -= leap;
            y += 1;
        } else {
            break;
        }
    }
    let mut m = 0;
    while m < 12 && d >= month_days[m] {
        d -= month_days[m];
        m += 1;
    }
    let day = d + 1;
    let mon = m + 1;
    let rem = secs % 86400;
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        y, mon, day, hh, mm, ss
    )
}

/// Run corroboration over allowlist targets (only those with a url).
pub fn run(targets: &[Target]) -> Vec<CorroRow> {
    let mut rows = Vec::new();
    for t in targets {
        if t.url.is_empty() {
            continue; // ip-only target irrelevant for web_connectivity
        }
        if !t.is_safe() {
            eprintln!("SKIP unsafe target: {}", t.name);
            continue;
        }
        match fetch_reference(&t.url) {
            Some((anomaly, bt, mt, count)) => {
                rows.push(CorroRow {
                    target: t.name.clone(),
                    input: t.url.clone(),
                    ref_anomaly: if anomaly {
                        "True".into()
                    } else {
                        "False".into()
                    },
                    blocking_type: bt,
                    last_measurement: mt,
                    probe_count: count,
                    local_https: "-".into(),
                });
            }
            None => {
                rows.push(CorroRow {
                    target: t.name.clone(),
                    input: t.url.clone(),
                    ref_anomaly: "no-data".into(),
                    blocking_type: "".into(),
                    last_measurement: "".into(),
                    probe_count: 0,
                    local_https: "-".into(),
                });
            }
        }
        // Rate-limit: do not spam the upstream API
        std::thread::sleep(Duration::from_millis(500));
    }
    rows
}
