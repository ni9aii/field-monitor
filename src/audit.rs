//! security_audit — read-only security audit (legitimate, read-only).
//!
//! Does not change configuration. When privileges are insufficient it
//! reports "need root".

use std::process::Command;

use crate::model::*;

/// Check whether a tool is available on PATH.
fn has(tool: &str) -> bool {
    Command::new("command")
        .args(["-v", tool])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Whether `sudo` can run without a password prompt.
fn sudo_nopass() -> bool {
    Command::new("sudo")
        .args(["-n", "true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Read a file, returning None on error.
fn read_file(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Extract a `key value` from an sshd_config-style file.
fn sshd_value(config: &str, key: &str) -> Option<String> {
    config
        .lines()
        .find(|l| {
            l.trim_start()
                .to_lowercase()
                .starts_with(&format!("{} ", key.to_lowercase()))
        })
        .and_then(|l| l.split_whitespace().nth(1).map(|s| s.to_string()))
}

/// ufw firewall status (or "none" if not installed).
fn ufw_status() -> String {
    if has("ufw") {
        Command::new("ufw")
            .arg("status")
            .output()
            .ok()
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .next()
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "unknown".into())
    } else {
        "none".into()
    }
}

/// fail2ban status (or "none" if not installed; "needroot" if unreadable).
fn fail2ban_status() -> String {
    if has("fail2ban-client") {
        if Command::new("fail2ban-client")
            .arg("status")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            "yes".into()
        } else {
            "needroot".into()
        }
    } else {
        "none".into()
    }
}

/// docker status (or "none" if not installed).
fn docker_status() -> String {
    if has("docker") {
        if Command::new("docker")
            .args(["ps", "-q"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            "yes".into()
        } else {
            "no".into()
        }
    } else {
        "none".into()
    }
}

/// List listening TCP/UDP ports via `ss`.
fn listeners() -> Vec<String> {
    if has("ss") {
        if let Ok(o) = Command::new("ss").args(["-tuln"]).output() {
            return String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| l.starts_with("tcp") || l.starts_with("udp"))
                .filter_map(|l| {
                    let parts: Vec<&str> = l.split_whitespace().collect();
                    parts.get(4).and_then(|addr| {
                        let seg: Vec<&str> = addr.split(':').collect();
                        seg.last()
                            .unwrap_or(&"")
                            .parse::<u16>()
                            .ok()
                            .map(|p| format!("{} {}", parts[0].get(..3).unwrap_or(""), p))
                    })
                })
                .collect();
        }
    }
    vec![]
}

/// Run the audit for a server (name/label/public IP supplied by caller).
pub fn run(label: &str, public_ip: &str) -> AuditRow {
    let sudo = if sudo_nopass() { "yes" } else { "no" };
    let os = read_file("/etc/os-release")
        .and_then(|c| {
            c.lines().find(|l| l.starts_with("PRETTY_NAME")).map(|l| {
                l.split('=')
                    .nth(1)
                    .unwrap_or("")
                    .trim_matches('"')
                    .to_string()
            })
        })
        .unwrap_or_else(|| "unknown".into());
    let sshd = read_file("/etc/ssh/sshd_config").unwrap_or_default();
    let ssh_port = sshd_value(&sshd, "Port").unwrap_or_else(|| "22".into());
    let ssh_pw = sshd_value(&sshd, "PasswordAuthentication").unwrap_or_else(|| "default".into());
    let ssh_root = sshd_value(&sshd, "PermitRootLogin").unwrap_or_else(|| "default".into());
    let ports = listeners().join(",");
    AuditRow {
        ip: public_ip.to_string(),
        name: label.to_string(),
        sudo_nopass: sudo.into(),
        os,
        ssh_port,
        ssh_pw,
        ssh_root,
        ufw: ufw_status(),
        fail2ban: fail2ban_status(),
        docker: docker_status(),
        ports,
    }
}
