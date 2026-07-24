//! gen-report — fill templates/apple-report-template.md from field-monitor CSV dumps.
//!
//! Usage:
//!   gen-report \
//!     --snapshots apple-availability-YYYY_MM_DD_DD_snapshots.csv \
//!     --anomalies apple-availability-YYYY_MM_DD_DD_anomalies.csv \
//!     --title "Report title" \
//!     --created 2026-01-01 \
//!     --heading "Report heading" \
//!     --current-ts "01.01 00:00Z" \
//!     --empty-reason "optional reason" \
//!     --empty-hours '{"2026-01-01":["01","02"]}' \
//!     --facts examples/22-23-facts.txt \
//!     --open-questions examples/22-23-open-questions.txt \
//!     --geo-notes "geography notes" \
//!     --current-state "current state" \
//!     --raw-blocked "| EXAMPLE | host | github | Some(0) | Some(8000) | open | HTTPS_FAIL |" \
//!     --raw-ok "| apple | 203.0.113.5 | 200 | 132 ms | 30 ms | open | - | OK |" \
//!     --raw-tail "(fill from probe.log tail)" \
//!     --template templates/apple-report-template.md \
//!     > report.md

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::process;

/// Minimal CLI arg parser: --key value.
fn parse_args() -> BTreeMap<String, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut m = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(key) = a.strip_prefix("--") {
            let val = if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                i += 1;
                args[i].clone()
            } else {
                String::new()
            };
            m.insert(key.to_string(), val);
        }
        i += 1;
    }
    m
}

/// Read file, one trimmed non-empty line per entry.
fn read_lines(path: &str) -> Vec<String> {
    match fs::read_to_string(path) {
        Ok(c) => c
            .lines()
            .map(|l| l.trim_end().to_string())
            .filter(|l| !l.is_empty())
            .collect(),
        Err(e) => {
            eprintln!("gen-report: cannot read {}: {}", path, e);
            process::exit(1);
        }
    }
}

/// Server/region/DC map (kept in sync with deploy.sh HOSTS). IPs redacted.
fn server_table() -> String {
    let rows: &[(&str, &str, &str)] = &[
        ("ruvds-x7yuy", "Владивосток", "RUVDS"),
        ("EKB", "Екатеринбург", "отдельный ДЦ"),
        ("ruvds-8vi23", "Екатеринбург", "RUVDS"),
        ("ruvds-klh99", "Казань", "RUVDS"),
        ("MOW-vladimir", "Москва", "отдельный ДЦ"),
        ("bm-server-1779046186914", "Москва", "отдельный ДЦ"),
        ("ruvds-8drd7", "Санкт-Петербург", "RUVDS"),
        ("omsk.org", "Омск", "отдельный ДЦ"),
        ("PERM-home", "Пермь", "отдельный ДЦ"),
        ("SPB", "Санкт-Петербург", "отдельный ДЦ"),
        ("VPN-DvaPuka-SPB2", "Санкт-Петербург", "тот же ДЦ, что SPB (relay)"),
        ("ruvds-ow0uq", "Новосибирск", "RUVDS"),
    ];
    let mut out = String::new();
    for (label, region, dc) in rows {
        out.push_str(&format!("| {} | {} | {} | [REDACTED] |\n", label, region, dc));
    }
    out
}

/// Group snapshots by (day, hour): vps count, apple OK, icloud OK, status.
fn build_timeline(snap_rows: &[Vec<String>]) -> String {
    // Expected columns: day, hour, server, target, status OK/SLOW/FAIL (index varies).
    // We accept any CSV with >=5 cols: [day, hour, server, target, ...status].
    let mut agg: BTreeMap<(String, String), (std::collections::HashSet<String>, usize, usize)> =
        BTreeMap::new();
    for r in snap_rows {
        if r.len() < 4 {
            continue;
        }
        let day = &r[0];
        let hour = &r[1];
        let server = &r[2];
        let target = &r[3];
        let status = r.get(4).map(|s| s.as_str()).unwrap_or("");
        let key = (day.clone(), hour.clone());
        let e = agg.entry(key).or_insert_with(|| {
            (
                std::collections::HashSet::new(),
                0_usize,
                0_usize,
            )
        });
        e.0.insert(server.clone());
        if target == "apple" && status == "OK" {
            e.1 += 1;
        }
        if target == "icloud" && status == "OK" {
            e.2 += 1;
        }
    }
    let mut lines = String::from(
        "| Generated (UTC) | vps | apple OK | icloud OK | Статус / интерпретация |\n",
    );
    lines.push_str("|-----------------|----:|---------:|----------:|------------------------|\n");
    for ((day, hour), (servers, apple_ok, icloud_ok)) in &agg {
        let vps = servers.len();
        let note = if *apple_ok > 0 || *icloud_ok > 0 {
            "CLEAR"
        } else {
            "SLOW/FAIL"
        };
        lines.push_str(&format!(
            "| {} {}:00 | {} | {} | {} | {} |\n",
            &day[5..],
            hour,
            vps,
            apple_ok,
            icloud_ok,
            note
        ));
    }
    lines
}

/// Build cumulative apple/icloud FAIL tables from anomalies CSV.
/// Expected columns: [day?, hour?, server, target, ...anomaly]. We count rows
/// where target == apple/icloud and anomaly contains FAIL.
fn build_fail_table(anom_rows: &[Vec<String>], target_name: &str) -> String {
    let mut counts: BTreeMap<String, (usize, usize)> = BTreeMap::new(); // server -> (fail, latency)
    for r in anom_rows {
        if r.len() < 4 {
            continue;
        }
        let server = &r[2];
        let target = &r[3];
        let an = r.get(4).map(|s| s.as_str()).unwrap_or("");
        if target != target_name {
            continue;
        }
        let e = counts.entry(server.clone()).or_insert((0, 0));
        if an.contains("FAIL") {
            e.0 += 1;
        }
        if an.contains("LATENCY") {
            e.1 += 1;
        }
    }
    let mut lines = String::new();
    for (server, (fail, lat)) in &counts {
        lines.push_str(&format!("| {} | {} | {} |\n", server, fail, lat));
    }
    lines
}

fn main() {
    let args = parse_args();
    let get = |k: &str| -> String {
        match args.get(k) {
            Some(v) if !v.is_empty() => v.clone(),
            _ => {
                eprintln!("gen-report: missing required --{}", k);
                process::exit(1);
            }
        }
    };

    let template_path = args
        .get("template")
        .cloned()
        .unwrap_or_else(|| "templates/apple-report-template.md".to_string());
    let template = match fs::read_to_string(&template_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("gen-report: cannot read template {}: {}", template_path, e);
            process::exit(1);
        }
    };

    let snapshots = read_lines(&get("snapshots"));
    let anomalies = read_lines(&get("anomalies"));
    let snap_rows: Vec<Vec<String>> = snapshots.iter().map(|l| l.split(',').map(String::from).collect()).collect();
    let anom_rows: Vec<Vec<String>> = anomalies.iter().map(|l| l.split(',').map(String::from).collect()).collect();

    let facts_lines = read_lines(&get("facts"));
    let facts = if facts_lines.is_empty() {
        String::new()
    } else {
        facts_lines
            .iter()
            .enumerate()
            .map(|(i, l)| format!("{}. {}", i + 1, l))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let oq_lines = read_lines(&get("open-questions"));
    let open_questions = if oq_lines.is_empty() {
        String::new()
    } else {
        oq_lines
            .iter()
            .map(|l| format!("- [ ] {}", l))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let empty_hours = args
        .get("empty-hours")
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_default();

    let timeline = build_timeline(&snap_rows);
    let apple_fail = build_fail_table(&anom_rows, "apple");
    let icloud_fail = build_fail_table(&anom_rows, "icloud");
    let server_tbl = server_table();

    // Replace placeholders.
    let mut out = template;
    let replacements: &[(&str, &str)] = &[
        ("{{TITLE}}", &get("title")),
        ("{{CREATED}}", &get("created")),
        ("{{HEADING}}", &get("heading")),
        ("{{TIMELINE_TABLE}}", &timeline),
        ("{{EMPTY_HOURS}}", &empty_hours),
        ("{{EMPTY_REASON}}", &get("empty-reason")),
        ("{{SERVER_TABLE}}", &server_tbl),
        ("{{APPLE_FAIL_TABLE}}", &apple_fail),
        ("{{ICLOUD_FAIL_TABLE}}", &icloud_fail),
        ("{{GEO_NOTES}}", &get("geo-notes")),
        ("{{FACTS}}", &facts),
        ("{{OPEN_QUESTIONS}}", &open_questions),
        ("{{CURRENT_STATE}}", &get("current-state")),
        ("{{CURRENT_TS}}", &get("current-ts")),
        ("{{RAW_BLOCKED_EXAMPLE}}", &get("raw-blocked")),
        ("{{RAW_OK_EXAMPLE}}", &get("raw-ok")),
        ("{{RAW_TAIL_EXAMPLE}}", &get("raw-tail")),
    ];
    for (ph, val) in replacements {
        out = out.replace(ph, val);
    }

    print!("{}", out);
}
