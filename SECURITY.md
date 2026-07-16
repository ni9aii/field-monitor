# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅         |

## Reporting a vulnerability

This tool is a **passive, read-only** monitor. It never proxies, tunnels, or
alters traffic, and it measures only operator-defined targets from
infrastructure the operator owns.

If you find a security issue (e.g. an unintended network egress, a way to make
it measure hosts the operator did not list, or a secret leaked through logs),
please report it privately:

- Open a **private security advisory** on GitHub
  (repo → Security → Advisories → "Report a vulnerability"), or
- Email the maintainer (see profile) with `[field-monitor security]` in the
  subject.

Please do **not** open a public issue for vulnerabilities.

## Out of scope

- Active probing / packet injection (Layer 3) — intentionally not implemented.
- Any circumvention or traffic-altering behaviour — never intended.
