package output

import (
	"time"

	"github.com/ancients-collective/sesha/internal/types"
)

// testTimestamp is a fixed time for deterministic test output.
var testTimestamp = time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)

// newTestReport builds a representative ScanReport for testing.
func newTestReport() *types.ScanReport {
	return &types.ScanReport{
		Version:   "1.0.0",
		Timestamp: testTimestamp,
		System: types.ScanSystem{
			Hostname:      "test-host",
			OS:            "linux",
			OSVersion:     "6.1.0",
			Arch:          "amd64",
			DistroID:      "ubuntu",
			DistroVersion: "22.04",
			DistroFamily:  "debian",
			EnvType:       "bare-metal",
			Profile:       "server",
			IsRoot:        true,
		},
		Filters: types.ScanFilters{
			Show:    "findings",
			Profile: "server",
		},
		Summary: types.ScanSummary{
			TotalChecks: 5,
			Passed:      2,
			Failed:      2,
			Skipped:     1,
			Errors:      0,
			Accepted:    0,
			DurationMS:  123,
		},
		Results: []types.TestResult{
			{
				ID:          "passwd_exists",
				Name:        "Password file exists",
				Category:    "authentication",
				Severity:    "low",
				Status:      types.StatusPass,
				Message:     "file exists: /etc/passwd",
				DurationMS:  1,
				Remediation: "Create /etc/passwd",
				Impact:      "Without /etc/passwd, user authentication breaks entirely",
				Explain:     "The passwd file maps usernames to UIDs",
				BreakRisk:   "No risk — this check only verifies the file exists",
			},
			{
				ID:          "ssh_root_login",
				Name:        "SSH Root Login Disabled",
				Category:    "ssh",
				Severity:    "critical",
				Status:      types.StatusFail,
				Message:     "pattern not found: PermitRootLogin no",
				DurationMS:  3,
				Remediation: "Set PermitRootLogin to no in /etc/ssh/sshd_config",
				Impact:      "Attacker can brute-force root password",
				Explain:     "Root login via SSH is dangerous",
				BreakRisk:   "May lock out users who rely on root SSH",
			},
			{
				ID:         "cramfs_disabled",
				Name:       "cramfs module disabled",
				Category:   "kernel",
				Severity:   "medium",
				Status:     types.StatusSkip,
				Message:    "OS \"darwin\" not in supported list [linux]",
				DurationMS: 0,
			},
			{
				ID:               "shadow_perms",
				Name:             "Shadow file permissions",
				Category:         "authentication",
				Severity:         "low",
				OriginalSeverity: "high",
				Status:           types.StatusFail,
				Message:          "permissions mismatch: /etc/shadow has 0644, expected 0640",
				DurationMS:       2,
				Remediation:      "chmod 640 /etc/shadow",
			},
			{
				ID:          "sshd_running",
				Name:        "SSHD service running",
				Category:    "ssh",
				Severity:    "info",
				Status:      types.StatusPass,
				Message:     "service is running",
				DurationMS:  5,
				Remediation: "Start sshd service",
			},
		},
	}
}

// newCleanReport builds a report with no failures.
func newCleanReport() *types.ScanReport {
	return &types.ScanReport{
		Version:   "1.0.0",
		Timestamp: testTimestamp,
		System: types.ScanSystem{
			Hostname: "clean-host",
			OS:       "linux",
			EnvType:  "bare-metal",
			Profile:  "server",
			IsRoot:   true,
		},
		Filters: types.ScanFilters{
			Show: "findings",
		},
		Summary: types.ScanSummary{
			TotalChecks: 2,
			Passed:      2,
			DurationMS:  50,
		},
		Results: []types.TestResult{
			{
				ID:         "check_a",
				Name:       "Check A",
				Category:   "test",
				Severity:   "low",
				Status:     types.StatusPass,
				DurationMS: 1,
			},
			{
				ID:         "check_b",
				Name:       "Check B",
				Category:   "test",
				Severity:   "medium",
				Status:     types.StatusPass,
				DurationMS: 2,
			},
		},
	}
}

// newAcceptedReport builds a report with an accepted failure.
func newAcceptedReport() *types.ScanReport {
	return &types.ScanReport{
		Version:   "1.0.0",
		Timestamp: testTimestamp,
		System: types.ScanSystem{
			Hostname: "container-host",
			OS:       "linux",
			EnvType:  "container",
			Profile:  "container",
			IsRoot:   true,
		},
		Filters: types.ScanFilters{
			Show: "all",
		},
		Summary: types.ScanSummary{
			TotalChecks: 1,
			Accepted:    1,
			DurationMS:  10,
		},
		Results: []types.TestResult{
			{
				ID:             "ssh_port",
				Name:           "SSH port listening",
				Category:       "ssh",
				Severity:       "info",
				Status:         types.StatusAccepted,
				AcceptedReason: "Containers use exec/attach instead of SSH",
				ContextNote:    "SSH is typically not needed inside containers",
				DurationMS:     3,
				Remediation:    "Start sshd",
			},
		},
	}
}

// newEmptyReport builds a report with zero results.
func newEmptyReport() *types.ScanReport {
	return &types.ScanReport{
		Version:   "1.0.0",
		Timestamp: testTimestamp,
		System: types.ScanSystem{
			Hostname: "empty-host",
			OS:       "linux",
			EnvType:  "bare-metal",
			IsRoot:   true,
		},
		Summary: types.ScanSummary{
			TotalChecks: 0,
			DurationMS:  1,
		},
		Results: []types.TestResult{},
	}
}
