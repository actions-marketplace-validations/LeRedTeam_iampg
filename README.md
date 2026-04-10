<p align="center">
  <img src="https://leredteam.github.io/LeRedLogo.jpeg" alt="LeRedTeam" width="80">
</p>

# iampg — IAM Policy Guard

**Enforce least-privilege IAM in every PR.**

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](COPYING)
[![CI](https://github.com/LeRedTeam/iampg/actions/workflows/ci.yaml/badge.svg)](https://github.com/LeRedTeam/iampg/actions/workflows/ci.yaml)
[![Sponsor](https://img.shields.io/github/sponsors/LeRedTeam?label=Sponsor)](https://github.com/sponsors/LeRedTeam)

---

## Why This Matters

Over-permissioned IAM policies are one of the most common cloud security risks. They lead to:

- **Privilege escalation** — Attackers exploit broad permissions to move laterally
- **Audit failures** — Compliance reviews flag wildcard policies and unused permissions
- **Blast radius** — When credentials leak, over-permissioned roles cause maximum damage

iampg catches these problems **before merge**, not after a security incident.

---

## The Problem

Developers either:
- Over-permission with `AdministratorAccess` because debugging `AccessDenied` takes hours
- Copy-paste wildcard policies from StackOverflow and forget about them

**iampg** fixes both sides:
1. **Generate** minimal policies by observing real AWS API calls
2. **Enforce** least-privilege standards in your CI/CD pipeline before merge

---

## Who Is This For

- **Backend developers** deploying on AWS who don't want to guess IAM permissions
- **DevOps engineers** managing IAM roles across CI/CD pipelines
- **Small teams** without a dedicated security engineer
- **Startups** that need security basics without enterprise tooling

---

## Why iampg

- **CI/CD native** — Runs in your pipeline, not just locally
- **Enforces automatically** — Blocks PRs with over-permissioned policies
- **No infrastructure** — Single binary, no backend, no SaaS dependency
- **No credentials stored** — Uses your existing AWS credentials, never stores them
- **Multiple outputs** — JSON, YAML, Terraform HCL, SARIF for security scanners
- **Drift detection** — Compare policies between deployments
- **Offline license validation** — No phone-home, no network calls

---

## Quick Start: CI/CD Enforcement

Add policy enforcement to your pipeline in 30 seconds:

```yaml
# .github/workflows/iam-check.yml
name: IAM Policy Check

on: [pull_request]

jobs:
  enforce:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - uses: LeRedTeam/iampg@v1
        with:
          mode: refine
          input: infra/iam-policy.json
          enforce: true
          license-key: ${{ secrets.IAMPG_LICENSE_KEY }}
```

This fails the PR if the policy contains:
- Wildcard actions (`s3:*`)
- Wildcard resources (`*`)
- Dangerous permissions (`iam:CreateUser`, `iam:AttachPolicy`)
- Admin-level access

### Generate + Enforce (two-step)

```yaml
jobs:
  iam:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - uses: aws-actions/configure-aws-credentials@v6
        with:
          role-to-assume: ${{ secrets.AWS_ROLE }}
          aws-region: us-east-1

      # Step 1: Generate policy from actual AWS calls
      - uses: LeRedTeam/iampg@v1
        with:
          mode: run
          command: python deploy.py --dry-run
          output: generated-policy.json

      # Step 2: Enforce security standards
      - uses: LeRedTeam/iampg@v1
        with:
          mode: refine
          input: generated-policy.json
          enforce: true
          license-key: ${{ secrets.IAMPG_LICENSE_KEY }}
```

---

## Quick Start: CLI

```bash
# Install latest release
VERSION=$(curl -sSL -o /dev/null -w '%{url_effective}' https://github.com/LeRedTeam/iampg/releases/latest | grep -oE '[^/]+$')
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m); [ "$ARCH" = "x86_64" ] && ARCH="amd64"; [ "$ARCH" = "aarch64" ] && ARCH="arm64"
curl -sSL "https://github.com/LeRedTeam/iampg/releases/download/${VERSION}/iampg_${VERSION#v}_${OS}_${ARCH}.tar.gz" | tar xz
sudo mv iampg /usr/local/bin/

# Or build from source (note: license validation uses dev key, not production key)
go install github.com/LeRedTeam/iampg@latest
```

### Generate a policy

```bash
$ iampg run -- aws s3 cp data.csv s3://my-bucket/uploads/
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject"],
      "Resource": "arn:aws:s3:::my-bucket/uploads/data.csv"
    }
  ]
}
```

### Parse existing errors

```bash
# From an AccessDenied error
iampg parse --error "User: arn:aws:iam::123:user/dev is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key"

# From CloudTrail logs
iampg parse --cloudtrail trail.json

# From stdin
cat errors.log | iampg parse --stdin
```

### Analyze a policy (Pro)

```bash
$ iampg refine --input policy.json

Policy Analysis
===============

Statements: 2
Issues: 3

Issues Found:
  [wildcard-action] Statement grants all actions for service: s3:*
     -> Replace s3:* with specific actions
  [wildcard-resource] Statement applies to all resources (*)
     -> Scope to specific resource ARNs
  [dangerous-permission] Potentially dangerous permission: iam:CreateUser
     -> Can create new IAM users
```

### Detect drift (Pro)

```bash
$ iampg refine --input current.json --compare baseline.json

Policy Diff
===========

Added (2):
  + s3:DeleteObject on arn:aws:s3:::bucket/*
  + s3:PutObject on arn:aws:s3:::bucket/*
```

### Enforce in CI (Pro)

```bash
# Exit code 1 if security issues found
iampg refine --input policy.json --enforce
```

### Aggregate multiple runs (Pro)

```bash
iampg aggregate --files policy1.json,policy2.json --output combined.json
```

### Output formats

```bash
# JSON (default, free)
iampg run -- aws s3 ls

# YAML (Pro)
iampg run --format yaml -- aws s3 ls

# Terraform (Pro)
iampg run --format terraform --resource-name deploy_policy -- aws s3 ls

# SARIF for CI security scanners (Pro)
iampg run --format sarif -- aws s3 ls
```

---

## Commands

| Command | Description | Tier |
|---------|-------------|------|
| `run -- <cmd>` | Generate policy from AWS CLI command | Free |
| `parse` | Generate policy from CloudTrail logs or AccessDenied errors | Free |
| `refine` | Analyze policies for security issues, drift detection, CI enforcement | Pro |
| `aggregate` | Combine multiple policies into one | Pro |

---

## Pricing

| Feature | Free | Pro | Commercial |
|---------|------|-----|------------|
| | $0 | $19/mo or $149/yr | $149/yr |
| `run` + `parse` commands | yes | yes | yes |
| JSON output | yes | yes | yes |
| YAML / Terraform / SARIF output | | yes | yes |
| `refine` + `aggregate` commands | | yes | yes |
| Policy diff / drift detection | | yes | yes |
| CI enforcement (`--enforce`) | | yes | yes |
| AGPL-3.0 exemption | | | yes |

**Pro** is for individual developers and open source projects.
**Commercial** is for organizations that need an AGPL exemption for proprietary use.

**Purchase:**
- [Pro Monthly ($19/mo)](https://buy.stripe.com/14A8wQ6PpaC37SoexZ2cg03)
- [Pro Annual ($149/yr)](https://buy.stripe.com/7sY8wQ2z95hJc8E0H92cg00)
- [Commercial Annual ($149/yr)](https://buy.stripe.com/00w4gA0r1aC3fkQ61t2cg02)

After purchase you'll receive your license key by email. Set it as:

```bash
export IAMPG_LICENSE_KEY=your-license-key
```

---

## Supported Services

Tested against real AWS accounts:

Services with dedicated resource ARN extraction:

- S3 (`s3`, `s3api`)
- DynamoDB
- Lambda
- SQS
- SNS
- STS
- IAM
- Secrets Manager
- SSM Parameter Store
- CloudWatch Logs
- KMS

All other AWS services (EC2, ECS, Glue, Athena, etc.) are supported via generic action parsing with `Resource: "*"`.

---

## How It Works

1. **Run mode**: Parses AWS CLI arguments to determine IAM actions and extracts resource ARNs
2. **Parse mode**: Regex patterns extract service, action, and resource from errors/logs
3. **Refine mode**: Static analysis detects wildcards, dangerous permissions, and policy drift
4. **All processing is local**: No data sent anywhere

---

## Security

- **No credential storage** -- Uses your existing AWS credentials
- **No network calls** -- All processing happens locally
- **No telemetry** -- Nothing is sent anywhere
- **Offline license validation** -- Ed25519 signatures, no phone-home

---

## License

This project is licensed under [AGPL-3.0](COPYING).

**What this means:**
- You can freely use, modify, and distribute iampg
- If you modify iampg and offer it as a service, you must share your modifications
- Using iampg as a CLI tool or in CI/CD does **not** require sharing your code

**Commercial licenses** are available for organizations that need an AGPL exemption. See [Pricing](#pricing).

---

## Contributing

Issues and PRs welcome at [github.com/LeRedTeam/iampg](https://github.com/LeRedTeam/iampg).

By submitting a PR, you agree to license your contribution under AGPL-3.0.
