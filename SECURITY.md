# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in iampg, please report it through [GitHub Security Advisories](https://github.com/LeRedTeam/iampg/security/advisories/new).

**Do NOT** open a public GitHub issue for security vulnerabilities.

## Response Timeline

- **Acknowledgment:** As soon as possible
- **Assessment:** Best effort, depends on severity
- **Patch:** As soon as possible, depending on severity

## Scope

The following are in scope:

- License validation bypass
- Command injection via CLI arguments
- Policy generation that grants unintended permissions
- Supply chain issues in the build/release pipeline

The following are out of scope:

- Policies generated from incorrect user input (garbage in, garbage out)
- AWS IAM behavior that differs from documentation
- Issues in dependencies (report upstream)

## Security Design

iampg follows these security principles:

- **No credential storage** — Uses ambient AWS credentials only
- **No network calls** — All processing is local
- **No telemetry** — Nothing is sent anywhere
- **Offline license validation** — Ed25519 signatures, no phone-home
- **Minimal dependencies** — 2 direct dependencies (cobra, yaml.v3)
