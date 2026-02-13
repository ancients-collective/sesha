# Writing Checks

This guide walks you through creating, testing, and contributing custom security
checks for sesha. You don't need to write any Go code — everything is YAML.

## Overview

A **check** is a YAML file that defines a single security assertion. Each check is self-contained — it describes *what* to verify, *when* it applies, *why* it matters, and *how* to fix a failure. sesha loads these files at runtime, so you never need to write or compile Go code.

Checks live in a directory (default: `./checks`). sesha recursively finds all `.yaml` and `.yml` files. You can organize them into subdirectories however you like:

```text
checks/
├── authentication/
│   ├── passwd_exists.yaml
│   └── shadow_permissions.yaml
├── ssh/
│   ├── sshd_running.yaml
│   └── ssh_port_listening.yaml
├── network/
│   └── ip_forward_disabled.yaml
└── custom/
    └── my_company_check.yaml
```

---

## Quick Start

Create a file called `checks/custom/my_check.yaml`:

```yaml
id: tmp_exists
name: /tmp directory exists
author: my-team
version: \"1.0\"
description: Verify that /tmp exists on the system.
severity: critical
category: filesystem
supported_os:
  - linux
tags:
  - hardening

steps:
  - function: file_exists
    args:
      path: /tmp

remediation: "Create /tmp: mkdir -m 1777 /tmp"
```

Validate it:

```bash
./sesha --validate checks/custom/my_check.yaml
```

Run it:

```bash
sudo ./sesha -c checks/custom --show all
```

---

## Check Schema Reference

Every check is a YAML file with the following fields. **Bold** fields are required.

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| **`id`** | string | Unique identifier. Must match `^[a-zA-Z0-9_-]+$`. Use `snake_case` by convention (e.g., `shadow_permissions`). |
| **`name`** | string | Human-readable name (3–100 characters). Shown in output. |
| **`description`** | string | Explains what this check verifies and why it matters. |
| **`severity`** | string | `critical`, `high`, `medium`, `low`, or `info`. |
| **`category`** | string | Grouping label (e.g., `authentication`, `ssh`, `network`). Used for output organization. |
| **`steps`** | list | One or more steps to execute. Each step calls a built-in function. At least one is required. |
| **`remediation`** | string | Actionable fix instructions shown when the check fails. |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `author` | string | Who created or maintains this check (e.g., `sesha-project`). |
| `version` | string | Version of the check definition (e.g., `"1.0"`). |
| `supported_os` | list | Limit to specific OSes: `linux`, `darwin`. Empty = all OSes. |
| `required_distro` | list | Limit to specific distros: `ubuntu`, `debian`, `rhel`, `alpine`, etc. Empty = all distros. |
| `environment` | string | Limit to an environment: `container`, `vm`, or `bare-metal`. |
| `profiles` | list | Intent profiles this check applies to: `server`, `workstation`, `container`. Empty = universal (runs for all profiles). |
| `requirements` | object | Privilege prerequisites. See [Requirements](#requirements). |
| `impact` | string | What an attacker gains if this check fails. Shown with `--explain`. |
| `explain` | string | Plain-language explanation of *why* this matters. Shown with `--explain`. |
| `break_risk` | string | What might break if the recommended fix is applied. Shown with `--explain`. |
| `likelihood` | string | Exploitation probability: `certain`, `likely`, `possible`, or `unlikely`. |
| `context_notes` | map | Environment-specific notes. Keys are environment types or profiles. |
| `severity_overrides` | map | Override severity per environment/profile. See [Severity Overrides](#severity-overrides). |
| `acceptable` | object | Define when a failure is considered acceptable. See [Acceptable Blocks](#acceptable-blocks). |
| `tags` | list | Freeform labels for filtering and organization. |
| `references` | list | URLs to related standards or documentation (must be valid URLs). |

---

## Steps

Each step calls a built-in function with arguments. Steps execute in order. The check **fails on the first failing step** and **passes only if all executed steps pass**.

```yaml
steps:
  - function: file_exists
    args:
      path: /etc/passwd

  - function: file_permissions_max
    args:
      path: /etc/passwd
      max_permissions: "0644"
```

### Step Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `function` | string | Yes | Name of the built-in function to call. |
| `args` | map | Yes | Arguments passed to the function. Each function has its own required args. |
| `when` | object | No | Conditional — only execute this step if the system matches. See [Conditional Steps](#conditional-steps). |

---

## Built-in Functions

sesha ships with 13 built-in functions. You cannot define custom functions in YAML — all checks must use these.

### file_exists

Checks if a file exists at the given path.

| Arg | Type | Required | Description |
|-----|------|----------|-------------|
| `path` | string | Yes | Absolute file path. |
| `expect_exists` | bool | No | Set to `false` to assert the file does *not* exist. Default: `true`. |

```yaml
# Check a file exists
- function: file_exists
  args:
    path: /etc/passwd

# Check a file does NOT exist
- function: file_exists
  args:
    path: /etc/hosts.equiv
    expect_exists: false
```

### file_permissions

Checks that a file has **exact** permissions.

| Arg | Type | Required | Description |
|-----|------|----------|-------------|
| `path` | string | Yes | Absolute file path. |
| `permissions` | string | Yes | Octal permission string (e.g., `"0644"`). Must be quoted. |

```yaml
- function: file_permissions
  args:
    path: /etc/crontab
    permissions: "0600"
```

### file_permissions_max

Checks that file permissions **do not exceed** a maximum. Passes if actual permissions are equal to or stricter than the maximum. Prefer this over `file_permissions` when you don't need an exact match.

| Arg | Type | Required | Description |
|-----|------|----------|-------------|
| `path` | string | Yes | Absolute file path. |
| `max_permissions` | string | Yes | Maximum allowed octal permissions (e.g., `"0640"`). Must be quoted. |

```yaml
# Passes for 0600, 0640, 0400 — fails for 0644, 0777
- function: file_permissions_max
  args:
    path: /etc/shadow
    max_permissions: "0640"
```

### file_contains

Checks that a file contains content matching a **regex** pattern.

| Arg | Type | Required | Description |
|-----|------|----------|-------------|
| `path` | string | Yes | Absolute file path. |
| `pattern` | string | Yes | Go-flavored regex pattern (RE2 syntax). |

```yaml
- function: file_contains
  args:
    path: /etc/login.defs
    pattern: "^PASS_MAX_DAYS\\s+[0-9]+"
```

> **Note:** YAML requires escaping backslashes. Use `\\s` for `\s`, `\\d` for `\d`, etc.

### file_not_contains

Checks that a file does **not** contain content matching a regex. The inverse of `file_contains`.

| Arg | Type | Required | Description |
|-----|------|----------|-------------|
| `path` | string | Yes | Absolute file path. |
| `pattern` | string | Yes | Regex pattern that should *not* match. |

```yaml
- function: file_not_contains
  args:
    path: /etc/shadow
    pattern: "^[^:]+::"
```

### file_owner

Checks file ownership (UID and GID).

| Arg | Type | Required | Description |
|-----|------|----------|-------------|
| `path` | string | Yes | Absolute file path. |
| `owner` | string | Yes | `"uid:gid"` or `"user:group"` format (e.g., `"root:root"` or `"0:0"`). |

```yaml
- function: file_owner
  args:
    path: /etc/passwd
    owner: "root:root"
```

### port_listening

Checks if a TCP port is listening on `127.0.0.1`.

| Arg | Type | Required | Description |
|-----|------|----------|-------------|
| `port` | int | Yes | TCP port number (1–65535). |

```yaml
- function: port_listening
  args:
    port: 22
```

### service_running

Checks if a systemd service is active (running).

| Arg | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | string | Yes | Service name (e.g., `sshd`, `ufw`). |
| `expect_running` | bool | No | Set to `false` to assert the service is *not* running. Default: `true`. |

```yaml
# Check service IS running
- function: service_running
  args:
    name: sshd

# Check service is NOT running
- function: service_running
  args:
    name: telnetd
    expect_running: false
```

### service_enabled

Checks if a systemd service is enabled (starts at boot).

| Arg | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | string | Yes | Service name. |
| `expect_enabled` | bool | No | Set to `false` to assert the service is *not* enabled. Default: `true`. |

```yaml
- function: service_enabled
  args:
    name: systemd-journald
```

### sysctl_value

Reads a sysctl parameter from `/proc/sys` and compares it to an expected value.

| Arg | Type | Required | Description |
|-----|------|----------|-------------|
| `key` | string | Yes | Sysctl key using dot notation (e.g., `net.ipv4.ip_forward`). |
| `expected` | string | Yes | Expected value as a string. |

```yaml
- function: sysctl_value
  args:
    key: net.ipv4.ip_forward
    expected: "0"
```

### command_output_contains

Runs an **allowlisted** command and checks the output against a regex. The command must be in sesha's security allowlist (see [Command Allowlist](#command-allowlist)).

| Arg | Type | Required | Description |
|-----|------|----------|-------------|
| `command` | string | Yes | Command name (must be in allowlist). |
| `args` | list | No | Command arguments (must use allowed flags). |
| `pattern` | string | Yes | Regex to match against stdout. |

```yaml
- function: command_output_contains
  args:
    command: timedatectl
    args:
      - status
    pattern: "NTP service: active|System clock synchronized: yes"
```

### kernel_module_loaded

Checks if a kernel module is loaded by reading `/proc/modules`.

| Arg | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | string | Yes | Kernel module name. |
| `expect_loaded` | bool | No | Set to `false` to assert the module is *not* loaded. Default: `true`. |

```yaml
# Check a dangerous module is NOT loaded
- function: kernel_module_loaded
  args:
    name: cramfs
    expect_loaded: false
```

### mount_has_option

Checks if a mount point has a specific mount option by reading `/proc/mounts`.

| Arg | Type | Required | Description |
|-----|------|----------|-------------|
| `mount_point` | string | Yes | Mount point path (e.g., `/tmp`). |
| `option` | string | Yes | Mount option to check for (e.g., `nodev`, `nosuid`, `noexec`). |

```yaml
- function: mount_has_option
  args:
    mount_point: /tmp
    option: nodev
```

---

## Context-Aware Features

### Conditional Steps

Use `when` to run a step only on certain systems. All specified fields must match (AND logic). Missing fields are ignored.

| Field | Matches against |
|-------|-----------------|
| `os` | Operating system (`linux`, `darwin`) |
| `distro` | Linux distribution ID (`ubuntu`, `rhel`, `alpine`, etc.) |
| `environment` | Environment type (`container`, `vm`, `bare-metal`) |

```yaml
steps:
  # This step only runs on Ubuntu
  - function: service_running
    args:
      name: ufw
    when:
      distro: ubuntu

  # This step only runs on RHEL
  - function: service_running
    args:
      name: firewalld
    when:
      distro: rhel
```

If all steps are skipped by conditions, the check result is `skip` with the message "no steps executed."

### Severity Overrides

Adjust the effective severity based on environment or profile. The original severity is preserved in the output.

```yaml
severity: high
severity_overrides:
  container: low          # Less critical inside containers
  workstation: medium     # Moderate concern on workstations
```

Override resolution order: environment type is checked first, then intent profile. Only valid severity values (`info`, `low`, `medium`, `high`, `critical`) are accepted.

### Acceptable Blocks

Mark a check failure as "accepted" in specific contexts. The check still runs, but the result status changes from `fail` to `accepted` with the documented reason.

```yaml
acceptable:
  when:
    - container
    - workstation
  reason: "Container networking is managed by the host kernel."
```

Valid `when` tokens: `container`, `vm`, `bare-metal`, `server`, `workstation`.

### Context Notes

Add environment-specific notes that appear in the output alongside the check result.

```yaml
context_notes:
  container: "Time synchronization is inherited from the host."
  workstation: "SSH may be intentionally disabled."
```

### Requirements

Document privilege prerequisites so users understand when root is needed.

```yaml
requirements:
  privilege: root          # "standard", "elevated", or "root"
  note: "Reading /etc/shadow requires root or shadow group membership."
```

---

## Command Allowlist

For security, `command_output_contains` can only run pre-approved commands. These are the allowed commands and their permitted flags:

| Command | Allowed Flags | Max Positional Args |
|---------|---------------|---------------------|
| `systemctl` | `status`, `is-active`, `is-enabled`, `is-failed` | 2 |
| `stat` | `-c`, `--format` | 1 |
| `ss` | `-tlnp`, `-t`, `-l`, `-n`, `-p` | 0 |
| `ufw` | `status` | 0 |
| `iptables` | `-L`, `-n`, `--list` | 1 |
| `auditctl` | `-l` | 0 |
| `timedatectl` | `status`, `show` | 1 |
| `loginctl` | `show-session` | 1 |

Commands not on this list are rejected. Shell invocation (`sh -c`, `bash -c`) is never allowed.

Allowed commands are resolved via `exec.LookPath` at startup. If a command is not found on `$PATH`, a hardcoded fallback path is tried (e.g., `/usr/bin/systemctl`). If neither resolves, checks using that command will fail with a clear error.

---

## Complete Example

Here is a fully-featured check using most available fields:

```yaml
id: ip_forward_disabled
name: IP forwarding is disabled
author: sesha-project
version: "1.0"
description: Verify that IPv4 forwarding is disabled on non-router systems.
severity: medium
category: network
supported_os:
  - linux
profiles:
  - server
  - workstation

requirements:
  privilege: standard
  note: Reads from /proc/sys which is world-readable.

steps:
  - function: sysctl_value
    args:
      key: net.ipv4.ip_forward
      expected: "0"

impact: An attacker on a compromised host can route traffic between networks.
explain: IP forwarding should be disabled unless the system acts as a router.
break_risk: Disabling may break Docker networking or VPN configurations.
likelihood: possible

context_notes:
  container: IP forwarding is controlled by the host, not the container.

severity_overrides:
  container: info

acceptable:
  when:
    - container
  reason: Container networking is managed by the host kernel.

tags:
  - cis-benchmark
  - network-hardening

references:
  - https://www.cisecurity.org/benchmark/distribution_independent_linux

remediation: |
  Disable IP forwarding:
    sysctl -w net.ipv4.ip_forward=0
  Persist across reboots:
    echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.d/99-sesha.conf
    sysctl --system
```

---

## Validating Checks

Always validate your checks before running them.

### Validate a single file

```bash
./sesha --validate checks/custom/my_check.yaml
```

### Validate an entire directory

```bash
./sesha --validate checks/
```

Validation verifies:
- YAML syntax is valid
- All required fields are present and correctly typed
- `id` matches the allowed pattern (`^[a-zA-Z0-9_-]+$`)
- `severity` is one of the five valid levels
- `supported_os` values are `linux` or `darwin`
- `environment` is `container`, `vm`, or `bare-metal`
- `profiles` are `server`, `workstation`, or `container`
- `likelihood` is `certain`, `likely`, `possible`, or `unlikely`
- `references` are valid URLs
- Every step uses a registered built-in function
- `severity_overrides` values are valid severity levels
- `acceptable.when` tokens are valid environment types or profile names

### Verify directory integrity

Use `--verify` at runtime to check file ownership and permissions:

```bash
sudo ./sesha --verify -c checks/
```

This warns about:
- World-writable or group-writable check directories
- World-writable YAML files
- Symlinks pointing outside the checks directory

---

## Testing Checks

### Run a single check

```bash
sudo ./sesha --id my_check_id --show all
```

The `--id` flag forces the check to run even if it would normally be skipped by profile or OS filters, and automatically sets `--show all` so you see the result regardless of status.

### See full details

```bash
sudo ./sesha --id my_check_id --show all --explain
```

The `--explain` flag displays `impact`, `explain`, and `break_risk` fields for failing or accepted checks.

### Test with a specific profile

```bash
sudo ./sesha --id my_check_id --profile container --show all
```

This lets you verify how your check behaves under different intent profiles (severity overrides, acceptable blocks, profile-based skipping).

### Test with tag filtering

```bash
sudo ./sesha --tags cis-benchmark --show all
```

The `--tags` flag filters checks to only run those with at least one matching tag. Comma-separate multiple tags to match checks with any of the listed tags (OR logic).

### Test with severity filtering

```bash
sudo ./sesha --sev critical,high --show all
```

### JSON output for inspection

```bash
sudo ./sesha --id my_check_id --format json 2>/dev/null | python3 -m json.tool
```

JSON output includes all fields — severity overrides, context notes, accepted reasons, duration, and file paths — making it useful for debugging check behavior.

### Run the test suite

If you're contributing checks to the project, run the full test suite to make
sure your check integrates correctly:

```bash
go test ./... -race
```

The test suite verifies that every YAML file in the `checks/` directory loads
without errors and has a unique ID. The loader also enforces unique IDs at load
time — if two files share the same `id`, the second file is skipped with an
error.

---

## Common Patterns

### Check a config directive exists

```yaml
steps:
  - function: file_contains
    args:
      path: /etc/ssh/sshd_config
      pattern: "^PermitRootLogin\\s+no"
```

### Check a config directive is absent

```yaml
steps:
  - function: file_not_contains
    args:
      path: /etc/ssh/sshd_config
      pattern: "^PermitRootLogin\\s+yes"
```

### Check with distro-specific steps

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

### Check a dangerous module is disabled

```yaml
steps:
  - function: kernel_module_loaded
    args:
      name: usb_storage
      expect_loaded: false
```

### Check a service is stopped and disabled

```yaml
steps:
  - function: service_running
    args:
      name: telnetd
      expect_running: false
  - function: service_enabled
    args:
      name: telnetd
      expect_enabled: false
```

### Check mount hardening

```yaml
steps:
  - function: mount_has_option
    args:
      mount_point: /tmp
      option: nodev
  - function: mount_has_option
    args:
      mount_point: /tmp
      option: nosuid
  - function: mount_has_option
    args:
      mount_point: /tmp
      option: noexec
```

---

## Things to Watch Out For

1. **Quote octal permissions.** YAML treats bare `0644` as an integer (420 in decimal). Always quote permission strings: `"0644"`.

2. **Escape regex backslashes.** In YAML strings, use `\\s`, `\\d`, `\\b` etc. A single `\s` in a double-quoted string is interpreted as a literal `s`.

3. **Paths must be absolute.** All file paths must start with `/`. Relative paths are rejected as a security measure.

4. **Steps fail fast.** The first failing step stops execution — subsequent steps don't run. Put your most-likely-to-fail step first if you want meaningful failure messages.

5. **Conditional steps use AND logic.** If you specify both `os: linux` and `distro: ubuntu` in a `when` block, both must match. There's no OR logic within a single `when` — use separate steps instead.

6. **Empty profiles means universal.** A check with no `profiles` field runs for all profiles. A check with `profiles: [server]` only runs when the active profile is `server`.

7. **`--id` bypasses filters.** When you use `--id`, the check runs even if the current OS, distro, or profile wouldn't normally match. Conditional steps (`when`) within the check still apply.

8. **Severity overrides apply regardless of result.** The effective severity is adjusted whether the check passes or fails, so JSON output always reflects the contextual severity.
