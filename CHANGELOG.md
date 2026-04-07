# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [1.0.0]

### Added
- `run` command: Generate IAM policies by observing AWS CLI calls
- `parse` command: Generate policies from CloudTrail logs and AccessDenied errors
- `refine` command: Analyze policies for security issues (Pro)
- `aggregate` command: Combine multiple policies (Pro)
- JSON, YAML, Terraform, SARIF output formats
- Policy diff and drift detection (Pro)
- CI enforcement mode with `--enforce` (Pro)
- Wildcard and dangerous permission detection (Pro)
- GitHub Action for CI/CD integration with run, parse, and refine modes
- Ed25519 offline license validation
- AGPL-3.0 license with commercial licensing option
- Cross-platform builds (Linux, macOS, Windows; amd64, arm64)
- Support for 12+ AWS services with 100+ via generic parsing
