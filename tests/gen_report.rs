//! Integration test for the `gen-report` binary.
//!
//! Builds the binary (if needed) and runs it against throwaway CSV inputs,
//! asserting that all template placeholders are replaced and the expected
//! structure appears in the output. No real infrastructure or network.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    // tests/ lives one level under the crate root.
    let manifest = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest)
}

fn ensure_binary() -> PathBuf {
    let bin = repo_root().join("target/debug/gen-report");
    if !bin.exists() {
        let status = Command::new("cargo")
            .args(["build", "--bin", "gen-report"])
            .status()
            .expect("failed to spawn cargo");
        assert!(status.success(), "cargo build --bin gen-report failed");
    }
    bin
}

fn write_tmp(name: &str, content: &str) -> PathBuf {
    let p = std::env::temp_dir().join(name);
    fs::write(&p, content).expect("write temp file");
    p
}

#[test]
fn fills_all_placeholders_and_produces_report() {
    let bin = ensure_binary();
    let template = repo_root().join("templates/apple-report-template.md");
    assert!(template.exists(), "template missing");

    let snap = write_tmp(
        "gen_report_test_snap.csv",
        "2026-07-22,01,vp-01,apple,OK\n\
         2026-07-22,01,vp-01,icloud,OK\n\
         2026-07-22,02,vp-01,apple,SLOW\n\
         2026-07-23,03,vp-02,apple,OK\n",
    );
    let anom = write_tmp(
        "gen_report_test_anom.csv",
        "2026-07-22,01,vp-01,apple,HTTPS_FAIL\n\
         2026-07-22,01,vp-01,apple,HIGH_LATENCY\n",
    );
    let facts = write_tmp(
        "gen_report_test_facts.txt",
        "Example fact one\nExample fact two\n",
    );
    let oq = write_tmp("gen_report_test_oq.txt", "Example question one\n");

    let out = Command::new(&bin)
        .args([
            "--snapshots",
            snap.to_str().unwrap(),
            "--anomalies",
            anom.to_str().unwrap(),
            "--title",
            "Test Report",
            "--created",
            "2026-07-24",
            "--heading",
            "Test Heading",
            "--current-ts",
            "01.01 00:00Z",
            "--empty-reason",
            "test reason",
            "--facts",
            facts.to_str().unwrap(),
            "--open-questions",
            oq.to_str().unwrap(),
            "--geo-notes",
            "test geo",
            "--current-state",
            "test state",
            "--raw-blocked",
            "| EXAMPLE | host | github | Some(0) | Some(8000) | open | HTTPS_FAIL |",
            "--raw-ok",
            "| apple | 203.0.113.5 | 200 | 132 ms | 30 ms | open | - | OK |",
            "--raw-tail",
            "(tail)",
            "--template",
            template.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run gen-report");

    assert!(out.status.success(), "gen-report exited non-zero");
    let stdout = String::from_utf8_lossy(&out.stdout);

    // No unresolved placeholders remain.
    assert!(
        !stdout.contains("{{"),
        "unfilled placeholder left in output:\n{}",
        stdout
    );

    // Key sections present.
    assert!(stdout.contains("# Test Heading"), "heading missing");
    assert!(stdout.contains("| Сервер (label)"), "server table missing");
    assert!(
        stdout.contains("Распределение apple HTTPS_FAIL"),
        "apple fail table missing"
    );
    assert!(stdout.contains("Example fact one"), "facts not substituted");
    assert!(
        stdout.contains("- [ ] Example question one"),
        "open questions not substituted"
    );

    // Anonymous server labels only (vp-01..vp-12), no real hostnames.
    assert!(stdout.contains("vp-01"), "vp-01 label missing");

    // Cleanup.
    let _ = fs::remove_file(&snap);
    let _ = fs::remove_file(&anom);
    let _ = fs::remove_file(&facts);
    let _ = fs::remove_file(&oq);
}
