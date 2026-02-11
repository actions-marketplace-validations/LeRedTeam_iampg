# MVP Definition

## Version 1.0 Scope

### Mode 1: CLI Wrapper (`run`)

```bash
iampg run -- <command>
```

**Behavior:**
1. Start local proxy to capture AWS API calls
2. Execute wrapped command with proxy environment
3. Capture service, action, resource from each call
4. Generate minimal IAM policy JSON
5. Output to stdout (or file with --output)

**Options:**
- `--output <file>` — Write to file instead of stdout
- `--format json` — Output format (json only in MVP)
- `--verbose` — Show captured calls

### Mode 2: Log Parser (`parse`)

```bash
iampg parse --cloudtrail <file>
iampg parse --error "<message>"
iampg parse --stdin
```

**Behavior:**
1. Read CloudTrail JSON or AccessDenied error
2. Extract service, action, resource
3. Generate IAM policy JSON

**Options:**
- `--cloudtrail <file>` — Parse CloudTrail log file
- `--error <string>` — Parse AccessDenied error message
- `--stdin` — Read input from stdin
- `--output <file>` — Write to file
- `--format json` — Output format

---

## MVP Outputs

### Policy JSON

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "arn:aws:s3:::bucket/*"
    }
  ]
}
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error |
| 3 | Wrapped command failed (policy still generated) |

---

## Paid Features

| Feature | Status |
|---------|--------|
| License validation | ✅ Done |
| `refine` command | ✅ Done |
| Terraform output | ✅ Done |
| YAML output | ✅ Done |
| SARIF output | ✅ Done |
| Multi-run aggregation | ✅ Done |
| CI enforcement mode | ✅ Done |
| Wildcard detection | ✅ Done |
| Scoping suggestions | ✅ Done |
| Policy diff | ✅ Done |

## Not In Scope

- UI/dashboard
- Web interface
- SaaS backend
- Database
- User accounts
- Policy storage

---

## Technical Requirements

- Single binary distribution
- Cross-platform (Linux, macOS, Windows)
- No runtime dependencies
- No configuration required
- Deterministic output

---

## Success Criteria

MVP is complete when:
- [ ] `iampg run -- aws s3 ls` generates correct policy
- [ ] `iampg parse --cloudtrail` parses CloudTrail logs
- [ ] `iampg parse --error` parses AccessDenied messages
- [ ] Output is valid IAM policy JSON
- [ ] Works on Linux, macOS, Windows
- [ ] README documents all commands
- [ ] GitHub release with binaries

---

## Build Timeline Target

- Week 1-2: Core capture mechanism
- Week 3: Parse command
- Week 4: Polish, testing, release

**Total: 4 weeks to MVP**
