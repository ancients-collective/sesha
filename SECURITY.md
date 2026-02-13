# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in sesha, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, use GitHub's built-in security advisory feature:

1. Go to the [Security tab](https://github.com/ancients-collective/sesha/security)
2. Click **Report a vulnerability**
3. Provide as much detail as you can — steps to reproduce, affected versions, and potential impact

## What Qualifies

- Path traversal in check loading or file operations
- Command injection through check definitions
- Bypasses of the command allowlist
- Information disclosure through error messages
- Privilege escalation vectors

## What Doesn't Qualify

- Checks that fail on your system (that's the tool working as intended)
- Missing checks for specific security benchmarks (please open a feature request instead)
- Issues in third-party dependencies (report upstream, but feel free to let us know too)

## Response Timeline

We aim to acknowledge reports within **48 hours** and provide a fix or
mitigation plan within **7 days** for confirmed vulnerabilities.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |
