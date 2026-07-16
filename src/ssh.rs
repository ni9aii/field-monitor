//! ssh — orchestration: copy the binary to a server and run it remotely.
//! Legitimate: only our servers, our keys, an explicit target allowlist.

use std::process::Command;

use crate::model::*;

/// Run `field-monitor <subcmd>` on a remote server, passing its public IP
/// and name. Returns stdout (a log with PROBE_IP=/AUDIT: lines).
pub fn run_remote(server: &ServerEntry, subcmd: &str, bin_local: &str) -> std::io::Result<String> {
    let remote = format!("{}@{}", server.user, server.ip);
    let dest = format!("{}:/tmp/field-monitor", remote);
    // 1) scp the binary
    let scp = Command::new("scp")
        .args([
            "-i",
            &server.key,
            "-P",
            &server.port.to_string(),
            "-o",
            "StrictHostKeyChecking=accept-new",
            bin_local,
            &dest,
        ])
        .output()?;
    if !scp.status.success() {
        return Err(std::io::Error::other(format!(
            "scp failed ({}): {}",
            scp.status,
            String::from_utf8_lossy(&scp.stderr).trim()
        )));
    }
    // 2) ssh run
    let out = Command::new("ssh")
        .args([
            "-i",
            &server.key,
            "-p",
            &server.port.to_string(),
            "-o",
            "StrictHostKeyChecking=accept-new",
            &remote,
            &format!(
                "FIELD_PROBE_IP='{}' FIELD_PROBE_NAME='{}' /tmp/field-monitor {}",
                server.ip, server.name, subcmd
            ),
        ])
        .output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "ssh {} failed ({}): {}",
            subcmd,
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    // Remote stderr (e.g. "Exec format error" on an arch mismatch);
    // otherwise it is lost and the server vanishes from the output silently.
    let err = String::from_utf8_lossy(&out.stderr);
    if !err.trim().is_empty() {
        s.push_str(&format!("\n# remote-stderr: {}", err.trim()));
    }
    Ok(s)
}
