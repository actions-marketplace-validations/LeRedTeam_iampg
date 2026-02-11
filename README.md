# iampg - IAM Auto-Policy Generator

Generate minimal IAM policies by observing AWS API calls or parsing logs.

Stop guessing IAM permissions. Run your code, get your policy.

## GitHub Action

```yaml
- name: Generate IAM Policy
  uses: LeRedTeam/iampg@v1
  with:
    mode: parse
    cloudtrail: ./cloudtrail-logs.json
    output: policy.json

- name: Upload policy
  uses: actions/upload-artifact@v4
  with:
    name: iam-policy
    path: policy.json
```

## Installation

```bash
# Download latest release
curl -sSL https://github.com/LeRedTeam/iampg/releases/latest/download/iampg_$(uname -s)_$(uname -m).tar.gz | tar xz
chmod +x iampg
sudo mv iampg /usr/local/bin/

# Or build from source
go install github.com/LeRedTeam/iampg@latest
```

## Usage

### Capture from AWS CLI commands (Free)

```bash
# Run an AWS command and generate the required policy
iampg run -- aws s3 ls s3://my-bucket/
iampg run -- aws dynamodb put-item --table-name Users --item '{"id":{"S":"1"}}'

# Save to file
iampg run --output policy.json -- aws s3 cp file.txt s3://bucket/

# Verbose mode (show captured calls)
iampg run -v -- aws lambda invoke --function-name MyFunc out.json
```

### Parse AccessDenied errors (Free)

```bash
# Parse a single error message
iampg parse --error "User: arn:aws:iam::123:user/dev is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key"

# Parse multiple errors from a file
cat errors.log | iampg parse --stdin

# Parse CloudTrail logs
iampg parse --cloudtrail trail.json
```

### Output Formats

```bash
# JSON (free)
iampg run -- aws s3 ls s3://bucket/

# YAML (pro)
iampg run --format yaml -- aws s3 ls s3://bucket/

# Terraform (pro)
iampg run --format terraform --resource-name my_policy -- aws s3 ls s3://bucket/

# SARIF for CI integration (pro)
iampg run --format sarif -- aws s3 ls s3://bucket/
```

### Analyze & Refine Policies (Pro)

```bash
# Analyze a policy for security issues
iampg refine --input policy.json

# Compare policies (drift detection)
iampg refine --input current.json --compare baseline.json

# CI enforcement mode (exit 1 if issues found)
iampg refine --input policy.json --enforce
```

### Aggregate Multiple Policies (Pro)

```bash
# Combine policies from multiple runs
iampg aggregate --files policy1.json,policy2.json --output combined.json
```

## Commands

| Command | Description | Tier |
|---------|-------------|------|
| `run -- <cmd>` | Execute command and capture AWS API calls | Free |
| `parse` | Parse CloudTrail logs or AccessDenied errors | Free |
| `refine` | Analyze policies for security issues | Pro |
| `aggregate` | Combine multiple policies into one | Pro |

## Output Formats

| Format | Description | Tier |
|--------|-------------|------|
| `json` | Standard IAM policy JSON | Free |
| `yaml` | YAML policy document | Pro |
| `terraform` | Terraform aws_iam_policy resource | Pro |
| `sarif` | SARIF report for CI security scanners | Pro |

## Pro Features

- **Wildcard Detection**: Find overly broad `*` permissions
- **Scoping Suggestions**: Get recommendations to tighten permissions
- **Policy Diff**: Compare policies and detect drift
- **CI Enforcement**: Fail builds with overly broad policies
- **Multi-format Output**: YAML, Terraform, SARIF
- **Policy Aggregation**: Combine multiple policies

Set your license key:
```bash
export IAMPG_LICENSE_KEY=your-license-key
```

## Example Output

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
```

## How it works

**Run mode:** Parses AWS CLI arguments to determine which IAM actions are being invoked and extracts resource ARNs from the command.

**Parse mode:** Uses regex patterns to extract service, action, and resource from CloudTrail events or AccessDenied error messages.

**Refine mode:** Analyzes policies for security issues like wildcards, overly broad permissions, and dangerous actions.

## Security

- **No credential storage** - Uses your existing AWS credentials
- **No network calls** - All processing is local
- **No telemetry** - Nothing is sent anywhere
- **Offline license validation** - No phone-home required
