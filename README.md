<div align="center">

# iac-guard

**One scan, one report and one verdict for your Infrastructure as Code.**

iac-guard runs **Gitleaks**, **Checkov** and **Semgrep** on your repository and merges their findings into a single report with a 0-100 security score. It returns a pass/fail verdict that can block a pull request.

[![Tests](https://github.com/chafiq753/iac-guard/actions/workflows/tests.yml/badge.svg?branch=tool)](https://github.com/chafiq753/iac-guard/actions/workflows/tests.yml)
[![Docker image](https://github.com/chafiq753/iac-guard/actions/workflows/docker.yml/badge.svg?branch=tool)](https://github.com/chafiq753/iac-guard/pkgs/container/iacguard)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

[Quick start](#quick-start) ·
[CLI](#command-line) ·
[Configuration](#configuration) ·
[GitHub Actions](#github-actions) ·
[How it works](#how-it-works)

</div>

---

## Why iac-guard?

Infrastructure code often reaches production without any security review. The same three kinds of problems keep slipping through:

| Problem | Example | Scanner |
|---|---|---|
| **Leaked secrets** | An AWS key committed by mistake, still present in Git history | Gitleaks |
| **Misconfigurations** | Public S3 bucket, unencrypted database, SSH open to `0.0.0.0/0` | Checkov |
| **Vulnerable code** | SQL injection, command injection in application code | Semgrep |

A good open-source scanner already exists for each of these. In practice they are hard to use together:

- Each one has its own output format, severity scale and exit-code behavior.
- They are usually wired into CI one at a time, or not at all.
- Their reports are informational only and rarely stop a risky change from being merged.

iac-guard runs all three, normalizes their output into **one schema** and applies **one blocking policy**, defined in a file committed to your repository.

## Features

- **Three scanners, one report.** Secrets, IaC misconfigurations and code vulnerabilities in a single table, sorted by severity.
- **Score and grade.** A 0-100 score with an A-F grade, so security posture can be compared across scans.
- **Pass/fail verdict.** A configurable severity threshold (`fail_on`) and well-defined exit codes, ready for CI.
- **Accepted risks with accountability.** An ignored finding must state a reason and can have an expiry date. When the date passes, the finding counts again.
- **Pull-request aware.** In a PR, Gitleaks only scans the commits of that PR, so old secrets from history don't block unrelated work.
- **GitHub native.** Inline annotations, a job summary, and SARIF upload to GitHub Code scanning with no limit on the number of alerts.
- **Secrets never displayed.** Gitleaks runs with `--redact`, and code snippets that contain a secret are masked in every output.
- **Runs anywhere.** As a Python CLI, as a Docker image with all scanners included, or as a GitHub Action.
- **Fully local.** No account, no API and no data leaves your machine. (Semgrep's `auto` ruleset downloads rules from semgrep.dev. A local ruleset can be used instead.)

## Quick start

### Docker (recommended: nothing else to install)

The image bundles iac-guard, Gitleaks, Checkov and Semgrep. It runs as a non-root user and supports amd64 and arm64.

```bash
docker run --rm -v "$PWD:/src:ro" ghcr.io/chafiq753/iacguard
```

To write a report file into your project, mount the folder read-write:

```bash
docker run --rm -v "$PWD:/src" ghcr.io/chafiq753/iacguard scan /src -f json -o /src/iacguard-report.json
```

> On Linux, add `--user "$(id -u):$(id -g)"` so the report is owned by you.
> On Windows PowerShell, use `-v "${PWD}:/src"`.

### pip

```bash
pip install iacguard
pip install checkov semgrep        # IaC and code scanners
# Gitleaks is a single binary: https://github.com/gitleaks/gitleaks/releases

iacguard doctor                    # checks which scanners are available
iacguard scan .
```

Requires Python 3.10+. Any scanner that is missing is reported, and the scan continues with the others. Use `--strict` to fail instead.

### Set up a repository

```bash
iacguard init            # creates .iacguard.yml
iacguard init --github   # also creates .github/workflows/iacguard.yml
```

## Command line

```text
iacguard scan [PATH]     Scan a folder (default: current directory)
iacguard show <#>        Show details of finding #N from the last scan
iacguard init            Create .iacguard.yml (and the GitHub workflow with --github)
iacguard doctor          Check that Gitleaks, Checkov, Semgrep and Git are installed
iacguard --version
```

### `iacguard scan`

| Option | Description |
|---|---|
| `--fail-on LEVEL` | Lowest severity that fails the scan: `critical`, `high`, `medium`, `low`, `info`, or `none` (report only). Default: `.iacguard.yml`, otherwise `high`. |
| `-f, --format` | `table` (default), `json` or `sarif`. |
| `-o, --output FILE` | Write the report to a file instead of stdout. |
| `--sarif FILE` | Also write a SARIF report, in addition to the main format. |
| `-t, --tools LIST` | Scanners to run, comma-separated, e.g. `checkov,gitleaks`. |
| `--strict` | Exit with code 2 if any scanner could not run. |
| `-d, --details` | Print full details (location, rule, remediation, code) for every finding. |
| `-c, --config FILE` | Configuration file (default: `.iacguard.yml` in the scanned folder). |
| `--since REF` | Gitleaks only scans commits after `REF`, e.g. `origin/main`. Set automatically in GitHub pull requests. |
| `--semgrep-config` | Semgrep rules: `auto` (online registry) or a local rules file. |
| `--no-annotations` | Disable GitHub annotations (useful when uploading SARIF). |

Findings are numbered in the table. Run `iacguard show 3` to see the file, line range, resource, rule, remediation advice and the offending code for finding #3.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Passed: no finding at or above the `fail_on` threshold |
| `1` | Blocked: at least one finding reaches the threshold |
| `2` | Error: no scanner could run, a scanner is missing with `--strict`, or the options are invalid |

When a finding blocks the scan *and* a scanner is missing, the exit code is `1`, because the issue that was found is real.

Progress messages and the verdict go to **stderr**. With `-f json` or `-f sarif`, stdout contains only the report, so it can be piped to other tools:

```bash
iacguard scan . -f json | jq '.summary'
```

## Configuration

Commit a `.iacguard.yml` at the root of the repository. Command-line options take precedence over this file.

```yaml
# Lowest severity that fails the scan: critical | high | medium | low | info | none
fail_on: high

# Paths whose findings are not counted (folders or glob patterns)
exclude:
  - examples/
  - "**/*_test.tf"

# Accepted risks. `reason` is mandatory (at least 10 characters).
ignore:
  - rule: CKV_AWS_144
    reason: "Non-critical data: cross-region replication not required"

  - rule: CKV_AWS_20                 # only for this path
    path: modules/public-website/
    reason: "Static public website: the bucket must be publicly readable"
    expires: 2026-12-31              # after this date, the finding counts again
```

Ignored findings still appear in the report: they are struck through and marked *ignored*, so nothing is hidden silently. When an exception has expired, the scan prints a warning and the finding counts again in the verdict.

## GitHub Actions

### Using the action

```yaml
name: iac-guard

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write          # needed for upload-sarif

jobs:
  iac-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # Gitleaks needs the Git history

      - uses: chafiq753/iac-guard@v1
        with:
          upload-sarif: true      # threshold, exclusions and exceptions come from .iacguard.yml
```

`iacguard init --github` generates this workflow for you.

**Inputs**

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Folder to scan, relative to the repository root |
| `fail-on` | *(config)* | Severity threshold. Empty: `.iacguard.yml`, otherwise `high` |
| `tools` | *(config)* | Comma-separated list of scanners. Empty: all three |
| `strict` | `true` | Fail if a scanner could not run |
| `report` | `iacguard-report.json` | Path of the JSON report |
| `upload-sarif` | `false` | Upload results to GitHub Code scanning |
| `sarif` | `iacguard.sarif` | Path of the SARIF report |
| `gitleaks-version` | `8.21.2` | Gitleaks version to install |

**Outputs:** `score`, `grade`, `blocked`, `findings`, `report`, `sarif`.

### What you get in a pull request

- **Inline alerts** on the changed lines, through Code scanning or annotations.
- **A job summary** with the score, the grade and the list of findings.
- **A failed check** when the threshold is reached.

### Blocking the merge

To prevent merging when the scan fails:

1. Go to **Settings → Rules → Rulesets → New branch ruleset**.
2. Target your default branch.
3. Enable **Require status checks to pass** and add the **`iac-guard`** check.

The check appears in the list after the workflow has run once.

> SARIF upload is free for public repositories. Private repositories need GitHub Advanced Security. Without it, the upload step fails but the verdict stays valid, and the inline annotations still work if you leave `upload-sarif: false`.

### Other CI systems

iac-guard is a CLI with standard exit codes, so it works in any pipeline:

```yaml
# GitLab CI
iac-guard:
  image:
    name: ghcr.io/chafiq753/iacguard:latest
    entrypoint: [""]
  script:
    - iacguard scan . -f json -o iacguard-report.json
  artifacts:
    when: always
    paths: [iacguard-report.json]
```

## How it works

```text
                ┌───────────┐
           ┌──► │ Gitleaks  │  secrets in files and Git history
           │    └───────────┘
 your repo ┼──► │ Checkov   │  Terraform, CloudFormation, Kubernetes, Dockerfile...
           │    └───────────┘
           └──► │ Semgrep   │  application code
                └───────────┘
                      │  three different formats
                      ▼
              normalize to one schema
         (severity, file, line, rule, remediation)
                      │
                      ▼
      apply .iacguard.yml (exclude / ignore / expiry)
                      │
                      ▼
          score 0-100 + grade A-F + verdict
                      │
        ┌─────────────┼──────────────┐
        ▼             ▼              ▼
     terminal     JSON / SARIF   exit code 0 / 1 / 2
```

### Severity

Without a Prisma Cloud account, Checkov does not report severities. iac-guard therefore assigns its own severity to Checkov rules, using this classification:

- **critical**: exploitable immediately by anyone, with maximum impact (full `*:*` IAM admin, world-writable storage, plaintext secret).
- **high**: a sensitive surface directly exposed to the Internet, or a known path to takeover (SSH/RDP/database open to the world, public bucket, IMDSv1, IAM privilege escalation).
- **medium**: the default. Encryption at rest, logging, TLS.
- **low**: hygiene and resilience (versioning, multi-AZ, rule descriptions).

If Checkov does provide a severity, it takes priority. Every secret found by Gitleaks is `critical`. Semgrep's `ERROR` / `WARNING` / `INFO` levels map to `high` / `medium` / `info`.

### Score

The score starts at 100 and each finding that counts removes points according to its severity:

| Severity | Penalty | | Score | Grade |
|---|---|---|---|---|
| critical | −25 | | 90-100 | A |
| high | −10 | | 75-89 | B |
| medium | −3 | | 60-74 | C |
| low | −1 | | 40-59 | D |
| info | 0 | | 0-39 | F |

The score never goes below 0. Ignored findings and excluded paths are not counted.

## Optional dashboard

This repository also contains a self-hosted web dashboard (`backend/`: FastAPI + PostgreSQL, `frontend/`: Next.js). It stores scan history and maps findings to compliance frameworks (Moroccan Law 09-08 / CNDP, Bank Al-Maghrib directives, CIS AWS Benchmark, ISO 27001). It also provides role-based access control and an audit log.

The dashboard is **not required**. The CLI and the GitHub Action are fully standalone, and the dashboard only consumes the JSON reports they produce.

## Development

```bash
git clone https://github.com/chafiq753/iac-guard
cd iac-guard
pip install -e ".[dev]" checkov semgrep
pytest -q
```

Tests marked `integration` run the real scanners and are skipped when a scanner is not installed.

Contributions are welcome: open an issue to discuss a change before submitting a pull request.

## Security

Please do not report security issues in public issues. See [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). iac-guard orchestrates third-party scanners ([Gitleaks](https://github.com/gitleaks/gitleaks), [Checkov](https://github.com/bridgecrewio/checkov), [Semgrep](https://github.com/semgrep/semgrep)), which are distributed under their own licenses.

---

<div align="center">
Built by <a href="https://www.linkedin.com/in/boulghallat-chafiq-565844335">Chafiq Boulghallat</a>
</div>
