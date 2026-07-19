//! Pluggable command execution.
//!
//! The agent shells out to system tools (`curl`, `dig`, `ping`, `ssh`, ...).
//! To make those calls unit-testable, the probe module runs them through a
//! `CommandRunner` trait. The default `RealRunner` delegates to
//! `std::process::Command`; tests can supply a mock that returns canned
//! output without touching the filesystem or network.

use std::io::Result;
use std::process::Output;

/// Abstraction over spawning an external command and capturing its output.
///
/// Mirrors the subset of `std::process::Command` that the probe helpers use.
pub trait CommandRunner {
    /// Run `program` with `args`, returning captured stdout/stderr/status.
    fn run(&self, program: &str, args: &[&str]) -> Result<Output>;
}

/// Default runner that executes real commands via `std::process::Command`.
pub struct RealRunner;

impl CommandRunner for RealRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<Output> {
        std::process::Command::new(program).args(args).output()
    }
}

#[cfg(test)]
pub mod test_runner {
    use super::*;
    use std::collections::HashMap;
    use std::process::Output;
    use std::sync::Mutex;

    /// A mock runner keyed by `program args` -> canned stdout.
    ///
    /// Status is success; stderr empty. Used to unit-test probe parsing
    /// without real network/filesystem access.
    pub struct MockRunner {
        /// program -> (args joined by space) -> stdout bytes
        responses: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl MockRunner {
        pub fn new() -> Self {
            Self {
                responses: Mutex::new(HashMap::new()),
            }
        }

        /// Register `stdout` for `program arg1 arg2 ...`.
        pub fn expect(&self, program: &str, args: &[&str], stdout: &str) {
            let key = format!("{} {}", program, args.join(" "));
            self.responses
                .lock()
                .unwrap()
                .insert(key, stdout.as_bytes().to_vec());
        }
    }

    impl Default for MockRunner {
        fn default() -> Self {
            Self::new()
        }
    }

    impl CommandRunner for MockRunner {
        fn run(&self, program: &str, args: &[&str]) -> Result<Output> {
            let key = format!("{} {}", program, args.join(" "));
            let out = self
                .responses
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .unwrap_or_default();
            // Cross-platform success status (no unix-only ExitStatusExt).
            let status = std::process::Command::new("true")
                .status()
                .expect("`true` exists on unix/macos");
            Ok(Output {
                status,
                stdout: out,
                stderr: Vec::new(),
            })
        }
    }
}
