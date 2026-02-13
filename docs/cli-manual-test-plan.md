# CLI Manual Test Plan

This document provides step-by-step instructions for manually testing every
sesha CLI flag, option, and common combination. It uses disposable YAML check
files that you create in a temporary directory so the built-in `checks/` are not
modified.

> **Prerequisites**
>
> - A compiled `sesha` binary (run `go build -o sesha ./cmd/sesha`).
> - Linux system (most checks target Linux).
> - Root access (`sudo`) for checks that read privileged files.
> - The binary path is referenced as `./sesha` throughout — adjust if yours is
>   elsewhere.

---

## 1. Setup — Create Test Check Files

Create a temporary directory and populate it with purpose-built YAML checks.
Each file exercises a specific aspect of the engine and is labeled clearly.

```bash
mkdir -p /tmp/sesha-manual-checks
```

### 1.1 `pass.yaml` — Always passes

```bash
cat >/tmp/sesha-manual-checks/pass.yaml <<'YAML'
id: manual_pass
name: "Manual Pass"
description: "Always passes by checking /etc/passwd exists"
severity: low
category: filesystem
supported_os:
  - linux
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "No action needed — /etc/passwd should always exist."
YAML
```

### 1.2 `fail.yaml` — Always fails

```bash
cat >/tmp/sesha-manual-checks/fail.yaml <<'YAML'
id: manual_fail
name: "Manual Fail"
description: "Always fails by looking for a nonexistent file"
severity: high
category: filesystem
supported_os:
  - linux
steps:
  - function: file_exists
    args:
      path: /tmp/sesha-does-not-exist-ever
remediation: "Intentional failure — no fix required."
YAML
```

### 1.3 `critical_fail.yaml` — Critical-severity failure

```bash
cat >/tmp/sesha-manual-checks/critical_fail.yaml <<'YAML'
id: manual_critical
name: "Critical Fail"
description: "Critical severity check that always fails"
severity: critical
category: filesystem
supported_os:
  - linux
steps:
  - function: file_exists
    args:
      path: /tmp/sesha-critical-missing
remediation: "Intentional critical failure — no fix required."
YAML
```

### 1.4 `info_pass.yaml` — Info-severity pass

```bash
cat >/tmp/sesha-manual-checks/info_pass.yaml <<'YAML'
id: manual_info
name: "Info Pass"
description: "Info-level check that always passes"
severity: info
category: filesystem
supported_os:
  - linux
steps:
  - function: file_exists
    args:
      path: /etc/hostname
remediation: "No action needed."
YAML
```

### 1.5 `medium_perms.yaml` — Permission check (requires root)

```bash
cat >/tmp/sesha-manual-checks/medium_perms.yaml <<'YAML'
id: manual_perms
name: "Shadow Permissions"
description: "Check /etc/shadow has max 0640 permissions"
severity: medium
category: authentication
supported_os:
  - linux
requirements:
  privilege: elevated
  note: "Stat on /etc/shadow may need elevated privileges."
steps:
  - function: file_permissions_max
    args:
      path: /etc/shadow
      max_permissions: "0640"
remediation: "Run: chmod 0640 /etc/shadow"
YAML
```

### 1.6 `multi_step.yaml` — Multi-step check (pass then fail)

```bash
cat >/tmp/sesha-manual-checks/multi_step.yaml <<'YAML'
id: manual_multi_step
name: "Multi-Step Fail Fast"
description: "First step passes, second step fails — demonstrates fail-fast"
severity: medium
category: filesystem
supported_os:
  - linux
steps:
  - function: file_exists
    args:
      path: /etc/passwd
  - function: file_exists
    args:
      path: /tmp/sesha-second-step-missing
remediation: "Second step is intentionally failing."
YAML
```

### 1.7 `explain_check.yaml` — Check with explain/impact/break_risk

```bash
cat >/tmp/sesha-manual-checks/explain_check.yaml <<'YAML'
id: manual_explain
name: "Explain Fields Demo"
description: "Demonstrates --explain output fields"
severity: high
category: network
supported_os:
  - linux
steps:
  - function: file_exists
    args:
      path: /tmp/sesha-explain-missing
impact: "An attacker could exploit a missing config to escalate privileges."
explain: "This check exists solely to demonstrate the --explain flag output."
break_risk: "Fixing this could restart the network daemon."
likelihood: possible
remediation: "Review and recreate the missing configuration file."
YAML
```

### 1.8 `profile_server.yaml` — Server profile only

```bash
cat >/tmp/sesha-manual-checks/profile_server.yaml <<'YAML'
id: manual_server_only
name: "Server-Only Check"
description: "Only runs under the server profile"
severity: low
category: general
supported_os:
  - linux
profiles:
  - server
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "No action needed."
YAML
```

### 1.9 `profile_container.yaml` — Container profile only

```bash
cat >/tmp/sesha-manual-checks/profile_container.yaml <<'YAML'
id: manual_container_only
name: "Container-Only Check"
description: "Only runs under the container profile"
severity: low
category: general
supported_os:
  - linux
profiles:
  - container
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "No action needed."
YAML
```

### 1.10 `severity_override.yaml` — Severity overrides and context notes

```bash
cat >/tmp/sesha-manual-checks/severity_override.yaml <<'YAML'
id: manual_sev_override
name: "Severity Override Demo"
description: "High severity normally, info in containers"
severity: high
category: network
supported_os:
  - linux
profiles:
  - server
  - container
steps:
  - function: file_exists
    args:
      path: /tmp/sesha-sev-override-missing
context_notes:
  container: "This is irrelevant inside containers."
  workstation: "Not applicable on workstations."
severity_overrides:
  container: info
  workstation: low
remediation: "Intentional failure for testing overrides."
YAML
```

### 1.11 `acceptable.yaml` — Acceptable-block check

```bash
cat >/tmp/sesha-manual-checks/acceptable.yaml <<'YAML'
id: manual_acceptable
name: "Acceptable Block Demo"
description: "Failure is marked 'accepted' in container/workstation contexts"
severity: medium
category: general
supported_os:
  - linux
steps:
  - function: file_exists
    args:
      path: /tmp/sesha-acceptable-missing
acceptable:
  when:
    - container
    - workstation
  reason: "This is expected to be absent in non-server environments."
remediation: "Create the file if running on a server."
YAML
```

### 1.12 `darwin_only.yaml` — macOS only (should be skipped on Linux)

```bash
cat >/tmp/sesha-manual-checks/darwin_only.yaml <<'YAML'
id: manual_darwin_only
name: "macOS-Only Check"
description: "This check only applies to macOS — should skip on Linux"
severity: low
category: general
supported_os:
  - darwin
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "No action needed."
YAML
```

### 1.13 `conditional_steps.yaml` — Steps with `when` conditions

```bash
cat >/tmp/sesha-manual-checks/conditional_steps.yaml <<'YAML'
id: manual_conditional
name: "Conditional Steps Demo"
description: "Uses distro-conditional steps"
severity: low
category: general
supported_os:
  - linux
steps:
  - function: file_exists
    args:
      path: /etc/debian_version
    when:
      distro: debian
  - function: file_exists
    args:
      path: /etc/debian_version
    when:
      distro: ubuntu
  - function: file_exists
    args:
      path: /etc/redhat-release
    when:
      distro: rhel
remediation: "Check your distro release file."
YAML
```

### 1.14 `file_contains_check.yaml` — Regex pattern matching

```bash
cat >/tmp/sesha-manual-checks/file_contains_check.yaml <<'YAML'
id: manual_file_contains
name: "File Contains Regex"
description: "Checks /etc/passwd contains a root entry"
severity: low
category: authentication
supported_os:
  - linux
steps:
  - function: file_contains
    args:
      path: /etc/passwd
      pattern: "^root:"
remediation: "Ensure root user exists in /etc/passwd."
YAML
```

### 1.15 `file_not_contains_check.yaml` — Negative regex match

```bash
cat >/tmp/sesha-manual-checks/file_not_contains_check.yaml <<'YAML'
id: manual_file_not_contains
name: "File Not Contains Regex"
description: "Checks /etc/passwd does not contain a bogus user"
severity: low
category: authentication
supported_os:
  - linux
steps:
  - function: file_not_contains
    args:
      path: /etc/passwd
      pattern: "^bogus_user_xyz_abc:"
remediation: "Remove the bogus user entry."
YAML
```

### 1.16 `file_owner_check.yaml` — Ownership check

```bash
cat >/tmp/sesha-manual-checks/file_owner_check.yaml <<'YAML'
id: manual_file_owner
name: "File Owner Check"
description: "Checks /etc/passwd is owned by root:root"
severity: low
category: filesystem
supported_os:
  - linux
steps:
  - function: file_owner
    args:
      path: /etc/passwd
      owner: "root:root"
remediation: "Run: chown root:root /etc/passwd"
YAML
```

### 1.17 `sysctl_check.yaml` — Sysctl value check

```bash
cat >/tmp/sesha-manual-checks/sysctl_check.yaml <<'YAML'
id: manual_sysctl
name: "Sysctl Value Check"
description: "Reads net.ipv4.ip_forward from /proc/sys"
severity: medium
category: network
supported_os:
  - linux
steps:
  - function: sysctl_value
    args:
      key: net.ipv4.ip_forward
      expected: "0"
remediation: "sysctl -w net.ipv4.ip_forward=0"
YAML
```

### 1.18 `tags_refs.yaml` — Tags and references

```bash
cat >/tmp/sesha-manual-checks/tags_refs.yaml <<'YAML'
id: manual_tags_refs
name: "Tags and References Demo"
description: "Includes tags and reference URLs for JSON inspection"
severity: info
category: general
supported_os:
  - linux
steps:
  - function: file_exists
    args:
      path: /etc/passwd
tags:
  - cis-benchmark
  - manual-test
references:
  - https://www.cisecurity.org/benchmark/distribution_independent_linux
remediation: "No action needed."
YAML
```

---

## 2. Intentionally Broken Check Files

These files test the validator and error handling. They should **not** pass
`--validate` and in some cases should produce load errors at runtime.

### 2.1 `broken_missing_id.yaml` — Missing required `id` field

```bash
cat >/tmp/sesha-manual-checks/broken_missing_id.yaml <<'YAML'
name: "Missing ID"
description: "This check is missing the required id field"
severity: low
category: general
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "Fix the YAML."
YAML
```

### 2.2 `broken_bad_severity.yaml` — Invalid severity value

```bash
cat >/tmp/sesha-manual-checks/broken_bad_severity.yaml <<'YAML'
id: broken_bad_severity
name: "Bad Severity"
description: "Uses an invalid severity value"
severity: extreme
category: general
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "Fix the severity."
YAML
```

### 2.3 `broken_no_steps.yaml` — No steps defined

```bash
cat >/tmp/sesha-manual-checks/broken_no_steps.yaml <<'YAML'
id: broken_no_steps
name: "No Steps"
description: "This check has no steps array"
severity: low
category: general
steps: []
remediation: "Add at least one step."
YAML
```

### 2.4 `broken_unknown_function.yaml` — Unknown built-in function

```bash
cat >/tmp/sesha-manual-checks/broken_unknown_function.yaml <<'YAML'
id: broken_unknown_func
name: "Unknown Function"
description: "References a function that doesn't exist"
severity: low
category: general
steps:
  - function: does_not_exist
    args:
      path: /etc/passwd
remediation: "Use a valid function."
YAML
```

### 2.5 `broken_bad_yaml.yaml` — Malformed YAML syntax

```bash
cat >/tmp/sesha-manual-checks/broken_bad_yaml.yaml <<'YAML'
id: broken_bad_yaml
name: "Bad YAML"
description: "This has invalid YAML syntax
severity: low
  category general
steps
  - function: file_exists
YAML
```

### 2.6 `broken_bad_id.yaml` — Invalid ID characters

```bash
cat >/tmp/sesha-manual-checks/broken_bad_id.yaml <<'YAML'
id: "broken bad id!!"
name: "Bad ID Characters"
description: "ID contains spaces and special characters"
severity: low
category: general
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "Fix the ID."
YAML
```

### 2.7 `broken_missing_remediation.yaml` — Missing required `remediation`

```bash
cat >/tmp/sesha-manual-checks/broken_missing_remediation.yaml <<'YAML'
id: broken_no_remediation
name: "Missing Remediation"
description: "This check has no remediation field"
severity: low
category: general
steps:
  - function: file_exists
    args:
      path: /etc/passwd
YAML
```

### 2.8 `broken_bad_reference.yaml` — Invalid reference URL

```bash
cat >/tmp/sesha-manual-checks/broken_bad_reference.yaml <<'YAML'
id: broken_bad_ref
name: "Bad Reference URL"
description: "References field contains an invalid URL"
severity: low
category: general
steps:
  - function: file_exists
    args:
      path: /etc/passwd
references:
  - not-a-url
remediation: "Fix the reference URL."
YAML
```

### 2.9 `broken_bad_os.yaml` — Invalid `supported_os` value

```bash
cat >/tmp/sesha-manual-checks/broken_bad_os.yaml <<'YAML'
id: broken_bad_os
name: "Bad Supported OS"
description: "Uses an invalid OS value"
severity: low
category: general
supported_os:
  - windows
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "Use linux or darwin."
YAML
```

### 2.10 `broken_bad_profile.yaml` — Invalid profile value

```bash
cat >/tmp/sesha-manual-checks/broken_bad_profile.yaml <<'YAML'
id: broken_bad_profile
name: "Bad Profile"
description: "Uses an invalid profile value"
severity: low
category: general
profiles:
  - laptop
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "Use server, workstation, or container."
YAML
```

---

## 3. Test Cases

For every test below, the command assumes you are in the sesha project root.
Replace `./sesha` with the path to your binary if different.

### 3.1 `--validate` — YAML Validation

#### 3.1.1 Validate a single valid file

```bash
./sesha --validate /tmp/sesha-manual-checks/pass.yaml
```

**Expected:** `✓ /tmp/sesha-manual-checks/pass.yaml is valid` — exit code `0`.

#### 3.1.2 Validate a single broken file (missing id)

```bash
./sesha --validate /tmp/sesha-manual-checks/broken_missing_id.yaml
```

**Expected:** Validation error mentioning missing required field `id` — exit code `1`.

#### 3.1.3 Validate a single broken file (bad YAML syntax)

```bash
./sesha --validate /tmp/sesha-manual-checks/broken_bad_yaml.yaml
```

**Expected:** YAML parse error — exit code `1`.

#### 3.1.4 Validate a single broken file (unknown function)

```bash
./sesha --validate /tmp/sesha-manual-checks/broken_unknown_function.yaml
```

**Expected:** Error about unknown function `does_not_exist` — exit code `1`.

#### 3.1.5 Validate a directory (mixed valid/broken)

```bash
./sesha --validate /tmp/sesha-manual-checks/
```

**Expected:** Multiple validation errors listed (one per broken file). Exit code `1`. Valid files are not flagged.

#### 3.1.6 Validate nonexistent path

```bash
./sesha --validate /tmp/does-not-exist
```

**Expected:** Error about inaccessible path — exit code `1`.

---

### 3.2 `--checks` / `-c` — Custom Checks Directory

> For tests 3.2 through 3.15, first create a clean directory with only valid
> checks so broken files don't pollute results:
>
> ```bash
> mkdir -p /tmp/sesha-valid-checks
> cp /tmp/sesha-manual-checks/pass.yaml \
>    /tmp/sesha-manual-checks/fail.yaml \
>    /tmp/sesha-manual-checks/critical_fail.yaml \
>    /tmp/sesha-manual-checks/info_pass.yaml \
>    /tmp/sesha-manual-checks/medium_perms.yaml \
>    /tmp/sesha-manual-checks/multi_step.yaml \
>    /tmp/sesha-manual-checks/explain_check.yaml \
>    /tmp/sesha-manual-checks/profile_server.yaml \
>    /tmp/sesha-manual-checks/profile_container.yaml \
>    /tmp/sesha-manual-checks/severity_override.yaml \
>    /tmp/sesha-manual-checks/acceptable.yaml \
>    /tmp/sesha-manual-checks/darwin_only.yaml \
>    /tmp/sesha-manual-checks/conditional_steps.yaml \
>    /tmp/sesha-manual-checks/file_contains_check.yaml \
>    /tmp/sesha-manual-checks/file_not_contains_check.yaml \
>    /tmp/sesha-manual-checks/file_owner_check.yaml \
>    /tmp/sesha-manual-checks/sysctl_check.yaml \
>    /tmp/sesha-manual-checks/tags_refs.yaml \
>    /tmp/sesha-valid-checks/
> ```

#### 3.2.1 Use long flag

```bash
sudo ./sesha --checks /tmp/sesha-valid-checks --show all
```

**Expected:** Runs all valid checks from the temp directory. Results are printed for every check.

#### 3.2.2 Use shorthand flag

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --show all
```

**Expected:** Identical output to 3.2.1.

#### 3.2.3 Missing checks directory

```bash
./sesha -c /tmp/nonexistent-dir
```

**Expected:** Error message — `No checks found in /tmp/nonexistent-dir` — exit code `1`.

#### 3.2.4 Empty checks directory

```bash
mkdir -p /tmp/sesha-empty && ./sesha -c /tmp/sesha-empty
```

**Expected:** `No checks found` error — exit code `1`.

---

### 3.3 `--show` / `-s` — Output Filter

#### 3.3.1 Default (findings only)

```bash
sudo ./sesha -c /tmp/sesha-valid-checks
```

**Expected:** Only failing (and error) checks are displayed. Passing and skipped checks are not listed in the findings section.

#### 3.3.2 `--show all`

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --show all
```

**Expected:** Every check result is displayed — pass, fail, skip, error, accepted.

#### 3.3.3 `--show pass`

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --show pass
```

**Expected:** Only passing checks are displayed.

#### 3.3.4 `--show fail`

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --show fail
```

**Expected:** Only failing checks are displayed (not errors, not accepted).

#### 3.3.5 `-s` shorthand

```bash
sudo ./sesha -c /tmp/sesha-valid-checks -s all
```

**Expected:** Same as `--show all`.

#### 3.3.6 Invalid `--show` value

```bash
./sesha -c /tmp/sesha-valid-checks --show invalid
```

**Expected:** Error — `Invalid --show value "invalid"` — exit code `1`.

---

### 3.4 `--severity` / `--sev` — Severity Filter

#### 3.4.1 Single severity

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --sev critical --show all
```

**Expected:** Only checks with `critical` severity are shown.

#### 3.4.2 Multiple severities (comma-separated)

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --severity high,critical --show all
```

**Expected:** Only `high` and `critical` checks appear.

#### 3.4.3 Filter to `info` only

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --sev info --show all
```

**Expected:** Only `info` severity checks shown (e.g., `manual_info`).

#### 3.4.4 Invalid severity value

```bash
./sesha -c /tmp/sesha-valid-checks --sev extreme
```

**Expected:** Error — `Invalid --severity flag: invalid severity values: extreme` — exit code `1`.

#### 3.4.5 Mixed valid and invalid

```bash
./sesha -c /tmp/sesha-valid-checks --sev high,bogus
```

**Expected:** Error mentioning `bogus` as invalid — exit code `1`.

---

### 3.5 `--profile` / `-p` — Intent Profile

#### 3.5.1 Default (`auto`)

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --show all
```

**Expected:** Profile is auto-detected. Profile-restricted checks (e.g., `manual_container_only`) may be skipped depending on your environment.

#### 3.5.2 Explicit `server` profile

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --profile server --show all
```

**Expected:** `manual_server_only` runs and passes. `manual_container_only` is skipped.

#### 3.5.3 Explicit `container` profile

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --profile container --show all
```

**Expected:** `manual_container_only` runs and passes. `manual_server_only` is skipped.

#### 3.5.4 Profile `all` — runs everything

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --profile all --show all
```

**Expected:** All checks run regardless of profile restrictions. Nothing is skipped due to profile.

#### 3.5.5 `-p` shorthand

```bash
sudo ./sesha -c /tmp/sesha-valid-checks -p container --show all
```

**Expected:** Same as `--profile container`.

#### 3.5.6 Invalid profile

```bash
./sesha -c /tmp/sesha-valid-checks --profile laptop
```

**Expected:** Error — `Invalid --profile value "laptop"` — exit code `1`.

---

### 3.6 `--id` — Run a Single Check

#### 3.6.1 Run a passing check by ID

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --id manual_pass
```

**Expected:** Only `manual_pass` runs, result is `pass`. Output filter is automatically set to `all`.

#### 3.6.2 Run a failing check by ID

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --id manual_fail
```

**Expected:** Only `manual_fail` runs, result is `fail`. Exit code `1`.

#### 3.6.3 Run a check that would normally be skipped (forces execution)

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --id manual_darwin_only
```

**Expected:** `manual_darwin_only` runs despite being marked `darwin`-only. `--id` bypasses OS/profile filters. The check should still pass (it checks `/etc/passwd` which exists on Linux).

#### 3.6.4 Nonexistent ID

```bash
./sesha -c /tmp/sesha-valid-checks --id nonexistent_check
```

**Expected:** Error — `No check found with ID "nonexistent_check"`. May show "Did you mean:" suggestions. Exit code `1`.

#### 3.6.5 Typo in ID triggers suggestions

```bash
./sesha -c /tmp/sesha-valid-checks --id manual_pas
```

**Expected:** Error with suggestion — `Did you mean: manual_pass`.

---

### 3.7 `--list-checks` — List Available Check IDs

#### 3.7.1 List all checks

```bash
./sesha -c /tmp/sesha-valid-checks --list-checks
```

**Expected:** Printed table of all check IDs, severities, and names. Exit code `0`.

#### 3.7.2 List filtered by profile

```bash
./sesha -c /tmp/sesha-valid-checks --list-checks -p server
```

**Expected:** Only checks applicable to the `server` profile are listed. `manual_container_only` is excluded.

#### 3.7.3 List with `--profile all`

```bash
./sesha -c /tmp/sesha-valid-checks --list-checks -p all
```

**Expected:** Every check is listed regardless of profile restrictions.

---

### 3.8 `--explain` — Show Impact Details

#### 3.8.1 With a failing check that has explain fields

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --id manual_explain --explain
```

**Expected:** Output includes `impact`, `explain`, and `break_risk` detail blocks beneath the failing check result.

#### 3.8.2 Without `--explain`

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --id manual_explain
```

**Expected:** Impact/explain/break_risk details are **not** shown.

#### 3.8.3 Explain on a passing check

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --id manual_pass --explain
```

**Expected:** The check passes. Explain details are typically shown only for failures/findings; verify no crash occurs and output is clean.

---

### 3.9 `--format` / `-f` — Output Format

#### 3.9.1 Default (text)

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --show all
```

**Expected:** Human-readable colored text output with severity badges.

#### 3.9.2 JSON format

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --show all --format json 2>/dev/null | python3 -m json.tool
```

**Expected:** Valid JSON object with `version`, `timestamp`, `system`, `filters`, `summary`, and `results` keys. All results include check metadata.

#### 3.9.3 JSONL format

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --show all --format jsonl 2>/dev/null | head -5
```

**Expected:** One JSON object per line. First line is the scan metadata, subsequent lines are individual results.

#### 3.9.4 `-f` shorthand

```bash
sudo ./sesha -c /tmp/sesha-valid-checks -f json --show all 2>/dev/null | python3 -m json.tool
```

**Expected:** Same as `--format json`.

#### 3.9.5 Invalid format

```bash
./sesha -c /tmp/sesha-valid-checks --format xml
```

**Expected:** Error — `Invalid --format value "xml"` — exit code `1`.

---

### 3.10 `--output` / `-o` — Write to File

#### 3.10.1 Write text to file

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --show all -o /tmp/sesha-output.txt
```

**Expected:** Output written to `/tmp/sesha-output.txt`. Stderr shows completion message with counts. File contains uncolored text.

```bash
cat /tmp/sesha-output.txt
```

#### 3.10.2 Write JSON to file

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --show all -f json -o /tmp/sesha-output.json
```

**Expected:** `/tmp/sesha-output.json` contains valid JSON.

```bash
python3 -m json.tool /tmp/sesha-output.json | head -20
```

#### 3.10.3 Write JSONL to file

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --show all -f jsonl -o /tmp/sesha-output.jsonl
```

**Expected:** `/tmp/sesha-output.jsonl` contains one JSON object per line.

```bash
wc -l /tmp/sesha-output.jsonl
```

#### 3.10.4 Write to unwritable path

```bash
./sesha -c /tmp/sesha-valid-checks -o /root/nope.txt
```

**Expected:** Error — `Failed to create output file` — exit code `1`.

---

### 3.11 `--no-color` — Disable Colored Output

#### 3.11.1 With `--no-color`

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --show all --no-color | cat
```

**Expected:** Output has no ANSI escape sequences. Verify by scanning for real ESC bytes:

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --show all --no-color 2>/dev/null | grep -cP '\x1b\['
```

**Expected:** Count is `0` (no escape codes).

> **Note:** Do not use `cat -v | grep '^['` — the `🛡` shield emoji contains
> byte `0x9B` in its UTF-8 encoding, which `cat -v` renders as `M-^[`,
> producing a false positive. `grep -P '\x1b\['` checks for real ESC (0x1B)
> bytes directly.

#### 3.11.2 Without `--no-color` (default)

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --show all
```

**Expected:** Output includes ANSI color codes when stdout is a terminal.

---

### 3.12 `--quiet` / `-q` — Suppress Output

#### 3.12.1 Quiet with passing checks only

First, create a directory with only passing checks:

```bash
mkdir -p /tmp/sesha-pass-only
cp /tmp/sesha-manual-checks/pass.yaml /tmp/sesha-pass-only/
```

```bash
sudo ./sesha -c /tmp/sesha-pass-only -q; echo "Exit: $?"
```

**Expected:** No output. Exit code `0` (clean).

#### 3.12.2 Quiet with failures

```bash
sudo ./sesha -c /tmp/sesha-valid-checks -q; echo "Exit: $?"
```

**Expected:** No output. Exit code `1` (findings present).

#### 3.12.3 `-q` shorthand

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --quiet; echo "Exit: $?"
```

**Expected:** Same as `-q`.

#### 3.12.4 Use in scripts

```bash
if sudo ./sesha -c /tmp/sesha-pass-only -q; then
  echo "System is clean"
else
  echo "Findings detected"
fi
```

**Expected:** Prints `System is clean`.

```bash
if sudo ./sesha -c /tmp/sesha-valid-checks -q; then
  echo "System is clean"
else
  echo "Findings detected"
fi
```

**Expected:** Prints `Findings detected`.

---

### 3.13 `--verify` — Directory Integrity Check

#### 3.13.1 Verify a normal temp directory

```bash
sudo ./sesha --verify -c /tmp/sesha-valid-checks --show all
```

**Expected:** If the temp directory has safe permissions, the scan proceeds normally. If `/tmp` has world-writable permissions on the check directory, you may see integrity warnings and the scan aborts.

#### 3.13.2 Verify with a world-writable file

```bash
cp /tmp/sesha-manual-checks/pass.yaml /tmp/sesha-valid-checks/writable_test.yaml
chmod 0666 /tmp/sesha-valid-checks/writable_test.yaml
sudo ./sesha --verify -c /tmp/sesha-valid-checks --show all
```

**Expected:** Warning about world-writable YAML file. Scan aborts — exit code `1`.

**Cleanup:**

```bash
rm /tmp/sesha-valid-checks/writable_test.yaml
```

---

### 3.14 `--debug` — Debug Diagnostic Output

#### 3.14.1 Debug mode

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --debug --show all 2>&1 | head -30
```

**Expected:** Additional diagnostic output on stderr showing system detection details (OS, distro, environment type, etc.).

---

### 3.15 Exit Codes

#### 3.15.1 Exit code `0` — clean scan

```bash
sudo ./sesha -c /tmp/sesha-pass-only -q; echo "Exit: $?"
```

**Expected:** `Exit: 0`

#### 3.15.2 Exit code `1` — findings present

```bash
sudo ./sesha -c /tmp/sesha-valid-checks -q; echo "Exit: $?"
```

**Expected:** `Exit: 1` (because `manual_fail`, `manual_critical`, etc. fail).

---

### 3.16 `--tags` — Filter by Tags

First, add tags to the test check files:

```bash
cat >/tmp/sesha-valid-checks/tagged_web.yaml <<'YAML'
id: manual_tagged_web
name: "Tagged Web Check"
description: "Check with web-server tag"
severity: medium
category: web
supported_os:
  - linux
tags:
  - web-server
  - hardening
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "No action needed."
YAML

cat >/tmp/sesha-valid-checks/tagged_cis.yaml <<'YAML'
id: manual_tagged_cis
name: "Tagged CIS Check"
description: "Check with cis-benchmark tag"
severity: high
category: compliance
supported_os:
  - linux
tags:
  - cis-benchmark
  - compliance
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "No action needed."
YAML
```

#### 3.16.1 Filter by single tag

```bash
./sesha --list-checks --tags web-server -c /tmp/sesha-valid-checks
```

**Expected:** Only `manual_tagged_web` is listed. Untagged and differently-tagged checks are excluded.

#### 3.16.2 Filter by multiple tags (OR logic)

```bash
./sesha --list-checks --tags web-server,cis-benchmark -c /tmp/sesha-valid-checks
```

**Expected:** Both `manual_tagged_web` and `manual_tagged_cis` are listed. Untagged checks are excluded.

#### 3.16.3 Filter by nonexistent tag

```bash
./sesha --list-checks --tags nonexistent-tag -c /tmp/sesha-valid-checks
```

**Expected:** No checks listed (0 available).

#### 3.16.4 Tags filter applies to scan execution

```bash
sudo ./sesha --tags hardening --show all -c /tmp/sesha-valid-checks
```

**Expected:** Only `manual_tagged_web` runs (it has the `hardening` tag). All other checks are skipped.

#### 3.16.5 No `--tags` flag — all checks run

```bash
./sesha --list-checks -c /tmp/sesha-valid-checks
```

**Expected:** All checks listed, including tagged and untagged.

---

## 4. Flag Combinations

These tests verify that multiple flags compose correctly.

### 4.1 `--id` + `--explain`

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --id manual_explain --explain
```

**Expected:** Single check runs with full explain/impact/break_risk details shown.

### 4.2 `--id` + `--format json`

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --id manual_fail --format json 2>/dev/null | python3 -m json.tool
```

**Expected:** JSON output with a single result entry for `manual_fail`.

### 4.3 `--severity` + `--show all`

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --sev low --show all
```

**Expected:** Only `low`-severity checks shown (both pass and fail).

### 4.4 `--severity` + `--show fail`

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --sev high,critical --show fail
```

**Expected:** Only `high` and `critical` severity checks that failed.

### 4.5 `--profile` + `--severity`

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --profile server --sev medium --show all
```

**Expected:** Only medium-severity checks that apply to the server profile.

### 4.6 `--format json` + `--output`

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --format json --show all -o /tmp/sesha-combo.json
cat /tmp/sesha-combo.json | python3 -m json.tool | head -20
```

**Expected:** Valid JSON written to file. Stderr shows completion summary.

### 4.7 `--format jsonl` + `--output` + `--quiet` (quiet beats output)

```bash
sudo ./sesha -c /tmp/sesha-valid-checks -f jsonl -o /tmp/sesha-quiet.jsonl -q; echo "Exit: $?"
```

**Expected:** With `--quiet`, output is suppressed. The file may still be written but no console output is shown. Exit code reflects findings.

### 4.8 `--no-color` + `--format text`

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --no-color --show all 2>&1 | grep -cP '\x1b\['
```

**Expected:** Count is `0` — zero ANSI escape codes in combined stdout+stderr.

### 4.9 `--id` + `--profile` (id overrides profile skipping)

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --id manual_container_only --profile server
```

**Expected:** `manual_container_only` runs even though the active profile is `server`. `--id` bypasses profile/OS filters.

### 4.10 `--list-checks` + `--severity` (severity does not filter list)

```bash
./sesha -c /tmp/sesha-valid-checks --list-checks --sev critical
```

**Expected:** `--list-checks` shows all available checks (severity filter applies at scan time, not list time). All IDs appear.

### 4.11 `--show all` + `--explain` (full verbose output)

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --show all --explain
```

**Expected:** All results shown with explain/impact/break_risk blocks on items that have them.

### 4.12 `--profile container` + acceptable block behavior

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --profile container --id manual_acceptable --show all
```

**Expected:** The `manual_acceptable` check fails but status is `accepted` because the acceptable block matches `container`. The reason is shown in the output.

### 4.13 `--debug` + `--format json`

```bash
sudo ./sesha -c /tmp/sesha-valid-checks --debug --format json --show all 2>/dev/null | python3 -m json.tool | head -10
```

**Expected:** Debug output goes to stderr (discarded by `2>/dev/null`). Stdout contains clean valid JSON.

---

## 5. Edge Cases

### 5.1 No flags at all (defaults)

```bash
sudo ./sesha -c /tmp/sesha-valid-checks
```

**Expected:** Uses defaults: `--show findings`, `--profile auto`, `--format text`. Only findings are shown.

### 5.2 Help / usage text

```bash
./sesha --help 2>&1 | head -20
```

**Expected:** Prints the ASCII banner and usage information with all available flags.

### 5.3 Double-dash flag termination

```bash
./sesha -c /tmp/sesha-valid-checks -- --show all
```

**Expected:** `--show all` is not parsed as a flag. Behavior depends on the flag parser — verify no crash.

### 5.4 Duplicate check IDs

Create two files with the same `id`:

```bash
cp /tmp/sesha-manual-checks/pass.yaml /tmp/sesha-valid-checks/pass_dupe.yaml
sudo ./sesha -c /tmp/sesha-valid-checks --show all 2>&1 | grep -i "dupe\|duplicate\|skip"
```

**Expected:** Load warning about duplicate ID — the second file is skipped.

**Cleanup:**

```bash
rm /tmp/sesha-valid-checks/pass_dupe.yaml
```

### 5.5 Subdirectory organization

```bash
mkdir -p /tmp/sesha-valid-checks/subdir
cp /tmp/sesha-manual-checks/pass.yaml /tmp/sesha-valid-checks/subdir/nested_pass.yaml
sed -i 's/manual_pass/nested_pass/' /tmp/sesha-valid-checks/subdir/nested_pass.yaml
sudo ./sesha -c /tmp/sesha-valid-checks --list-checks | grep nested_pass
```

**Expected:** `nested_pass` appears — sesha recursively finds checks in subdirectories.

**Cleanup:**

```bash
rm -rf /tmp/sesha-valid-checks/subdir
```

---

## 6. Cleanup

Remove all temporary test files when finished:

```bash
rm -rf /tmp/sesha-manual-checks /tmp/sesha-valid-checks /tmp/sesha-pass-only
rm -f /tmp/sesha-output.txt /tmp/sesha-output.json /tmp/sesha-output.jsonl
rm -f /tmp/sesha-combo.json /tmp/sesha-quiet.jsonl
rm -rf /tmp/sesha-empty
```

---

## Summary of Expected Exit Codes

| Scenario | Exit Code |
|----------|-----------|
| All checks pass | `0` |
| One or more checks fail | `1` |
| Only errors (no failures) | `2` |
| Invalid flag value | `1` |
| No checks found | `1` |
| Validation errors (`--validate`) | `1` |
| `--list-checks` | `0` |

## Flag Quick Reference

| Flag | Short | Values | Default |
|------|-------|--------|---------|
| `--checks` | `-c` | directory path | `./checks` |
| `--show` | `-s` | `findings`, `all`, `fail`, `pass` | `findings` |
| `--severity` | `--sev` | comma-separated: `critical`, `high`, `medium`, `low`, `info` | (none) |
| `--profile` | `-p` | `auto`, `all`, `server`, `workstation`, `container` | `auto` |
| `--explain` | — | boolean | `false` |
| `--format` | `-f` | `text`, `json`, `jsonl` | `text` |
| `--no-color` | — | boolean | `false` |
| `--output` | `-o` | file path | stdout |
| `--quiet` | `-q` | boolean | `false` |
| `--id` | — | check ID string | (none) |
| `--list-checks` | — | boolean | `false` |
| `--debug` | — | boolean | `false` |
| `--verify` | — | boolean | `false` |
| `--validate` | — | file or directory path | (none) |
