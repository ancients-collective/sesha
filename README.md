# Sesha

[![Go Version](https://img.shields.io/badge/go-1.24-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License](https://img.shields.io/badge/license-Apache_2.0-blue)](https://github.com/ancients-collective/sesha/blob/main/LICENSE)
[![Latest Release](https://img.shields.io/badge/release-v1.0.8-brightgreen)](https://github.com/ancients-collective/sesha/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/ancients-collective/sesha)](https://goreportcard.com/report/github.com/ancients-collective/sesha)
[![GoDoc](https://pkg.go.dev/badge/github.com/ancients-collective/sesha)](https://pkg.go.dev/github.com/ancients-collective/sesha)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ancients-collective/sesha/badge)](https://scorecard.dev/viewer/?uri=github.com/ancients-collective/sesha)

**Sesha** - Catch drift, not feelings.

A secure, simple and extensible YAML-driven security auditing tool that runs declarative checks against
your Linux hosts and reports findings in human-readable or machine-parseable
formats.

Sesha contains synthetically generated code. 

## Features

- **13 built-in check functions** — file permissions, services, sysctls, kernel modules, mounts, and more
- **YAML-driven checks** — write checks as simple YAML files, no code required
- **Context-aware** — automatically detects OS, distro, and container/VM environment, then filters checks accordingly
- **Profile support** — server, workstation, container, or auto-detect
- **Severity overrides** — checks can adjust severity based on execution context
- **Acceptable blocks** — mark expected failures as accepted with documented reasons
- **3 output formats** — text (human-readable), JSON (SIEM ingestion), JSONL (log pipelines)
- **Single binary** — zero runtime dependencies, compiles to a static Go binary
- **Validate mode** — lint your YAML checks without executing them

## Quick Start

```bash
# Build
go build -o sesha ./cmd/sesha

# Run with the default checks directory
sudo ./sesha

# Run a single check
sudo ./sesha --id passwd_exists

# Show all results (not just findings)
sudo ./sesha --show all

# JSON output for automation
sudo ./sesha --format json -o scan.json

# Validate checks without running them
./sesha --validate ./checks
```

## Installation

### From Source

```bash
git clone https://github.com/ancients-collective/sesha.git
cd sesha
go build -o sesha ./cmd/sesha
sudo mv sesha /usr/local/bin/
```

### Requirements

- Go 1.24+ (build only)
- Linux (runtime)

## Usage

```text
Usage: sesha [options]

Options:
  -c,   --checks <dir>     Path to checks directory (default: ./checks)
  -s,   --show <mode>      Output filter: findings, all, fail, pass (default: findings)
        --severity <list>   Severity filter (comma-separated):
        --sev <list>          critical, high, medium, low, info
  -p,   --profile <type>   Intent profile: auto, all, server, workstation, container
        --explain           Show impact, explain, and break_risk details
  -f,   --format <type>    Output format: text, json, jsonl (default: text)
        --no-color          Disable colored output
  -o,   --output <file>    Write output to file (default: stdout)
  -q,   --quiet            Suppress output, exit code only (0/1/2)
        --verify            Verify checks directory integrity before running
        --id <check_id>     Run a single check by its ID
        --list-checks       List all available check IDs and exit
        --debug             Enable debug diagnostic output
        --validate <path>   Validate YAML check file(s) without execution
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | Clean — no findings |
| `1`  | Findings — one or more checks failed |
| `2`  | Errors — tool errors only (no findings) |

## Writing Checks

Checks are YAML files — one per file — placed in the checks directory. Here's a
minimal example:

```yaml
id: shadow_permissions
name: "Shadow file permissions"
description: "Verifies /etc/shadow has restrictive permissions (0640 or tighter)"
severity: high
category: authentication
supported_os:
  - linux

steps:
  - function: file_permissions_max
    args:
      path: /etc/shadow
      max_permissions: "0640"

remediation: |
  Set correct permissions on /etc/shadow:
    chmod 640 /etc/shadow
    chown root:shadow /etc/shadow
```

For the full schema, all 13 functions, and advanced features like conditional
steps and severity overrides, see the
[Writing Checks guide](docs/writing-checks.md).

### Available Functions

| Function | Description | Required Args |
|----------|-------------|---------------|
| `file_exists` | Check if a file exists | `path` |
| `file_permissions` | Check exact file permissions | `path`, `permissions` |
| `file_permissions_max` | Check maximum allowed permissions | `path`, `max_permissions` |
| `file_contains` | Check if a file contains a regex pattern | `path`, `pattern` |
| `file_not_contains` | Check if a file does not contain a pattern | `path`, `pattern` |
| `file_owner` | Check file ownership | `path`, `owner` |
| `port_listening` | Check if a TCP port is listening | `port` |
| `service_running` | Check if a systemd service is running | `name` |
| `service_enabled` | Check if a systemd service is enabled | `name` |
| `sysctl_value` | Check a sysctl parameter value | `key`, `expected` |
| `command_output_contains` | Run an allowlisted command and check output | `command`, `pattern` |
| `kernel_module_loaded` | Check if a kernel module is loaded | `name` |
| `mount_has_option` | Check if a mount point has an option | `mount_point`, `option` |

### Context-Aware Features

**Conditional steps** — run different steps based on OS or distro:

```yaml
steps:
  - function: service_running
    args:
      name: ufw
    when:
      distro: ubuntu
  - function: service_running
    args:
      name: firewalld
    when:
      distro: rhel
```

**Severity overrides** — adjust severity by context:

```yaml
severity: medium
severity_overrides:
  container: low
  workstation: info
```

**Acceptable blocks** — document expected failures:

```yaml
acceptable:
  when: [container]
  reason: "Containers typically don't run NTP directly"
```

## Project Structure

```text
sesha/
├── cmd/sesha/           # CLI entry point
├── internal/
│   ├── types/           # Shared types (TestDefinition, TestResult, ScanReport)
│   ├── engine/          # Execution engine, functions, security validation
│   ├── context/         # System detection (OS, distro, container/VM)
│   ├── loader/          # YAML check loader and validator
│   └── output/          # Output formatters (text, JSON, JSONL)
├── checks/              # Built-in security checks (YAML)
├── docs/                # Project documentation
├── site/                # GitHub Pages website (deployed via CI)
├── go.mod
└── README.md
```

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines on writing checks, submitting code, and running tests.

## Security

If you discover a vulnerability, please report it responsibly — see
[SECURITY.md](SECURITY.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Copyright 2025–2026 [Ancients Collective](https://github.com/ancients-collective).
