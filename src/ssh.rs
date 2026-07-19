//! ssh — orchestration: copy the binary to a server and run it remotely.
//! Legitimate: only our servers, our keys, an explicit target allowlist.

use std::io::{Error, ErrorKind};
use std::process::Command;

use crate::model::*;

/// Escape a single-quoted shell argument: replace `'` with `'\''` so a value
/// interpolated inside single quotes cannot break out and inject commands.
fn sh_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

#[allow(clippy::io_other_error)]
/// Run `field-monitor <subcmd>` on a remote server, passing its public IP
/// and name. Returns stdout (a log with PROBE_IP=/AUDIT: lines).
///
/// The remote binary in `/tmp` is cleaned up afterwards (best-effort) so it
/// does not linger across runs. SSH connections carry explicit timeouts so a
/// single unresponsive server cannot hang the whole orchestrator.
pub fn run_remote(server: &ServerEntry, subcmd: &str, bin_local: &str) -> std::io::Result<String> {
    let remote = format!("{}@{}", server.user, server.ip);
    let dest = format!("{}:/tmp/field-monitor", remote);
    let ssh_opts = [
        "-i",
        &server.key,
        "-P",
        &server.port.to_string(),
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
    ];
    // 1) scp the binary
    let scp = Command::new("scp")
        .args(ssh_opts)
        .args([bin_local, &dest])
        .output()?;
    if !scp.status.success() {
        return Err(std::io::Error::new(
            ErrorKind::Other,
            format!(
                "scp failed ({}): {}",
                scp.status,
                String::from_utf8_lossy(&scp.stderr).trim()
            ),
        ));
    }
    // 2) ssh run, then clean up the remote binary (best-effort).
    // Values are single-quote-escaped to prevent shell injection from config.
    let remote_cmd = format!(
        "FIELD_PROBE_IP={ip} FIELD_PROBE_NAME={name} /tmp/field-monitor {subcmd}; rm -f /tmp/field-monitor",
        ip = sh_quote(&server.ip),
        name = sh_quote(&server.name),
        subcmd = subcmd,
    );
    let out = Command::new("ssh")
        .args(ssh_opts)
        .arg(&remote)
        .arg(&remote_cmd)
        .output()?;
    if !out.status.success() {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "ssh {} failed ({}): {}",
                subcmd,
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sh_quote_escapes_single_quote() {
        // A value with an apostrophe must not break out of the single quotes.
        assert_eq!(
            sh_quote("x'; touch /tmp/pwned #"),
            "'x'\\''; touch /tmp/pwned #'"
        );
    }

    #[test]
    fn sh_quote_plain_value() {
        assert_eq!(sh_quote("192.0.2.10"), "'192.0.2.10'");
    }

    #[test]
    fn sh_quote_empty() {
        assert_eq!(sh_quote(""), "''");
    }
}
