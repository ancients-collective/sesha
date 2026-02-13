package types

import (
	"testing"
)

func TestResultStatus_Values(t *testing.T) {
	tests := []struct {
		name   string
		status ResultStatus
		want   string
	}{
		{"pass", StatusPass, "pass"},
		{"fail", StatusFail, "fail"},
		{"skip", StatusSkip, "skip"},
		{"error", StatusError, "error"},
		{"accepted", StatusAccepted, "accepted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.status) != tt.want {
				t.Errorf("got %q, want %q", tt.status, tt.want)
			}
		})
	}
}

func TestTestDefinition_RequiredFields(t *testing.T) {
	td := TestDefinition{
		ID:          "test_check_01",
		Name:        "Test Check",
		Description: "A test check",
		Severity:    "low",
		Category:    "test",
		Steps: []TestStep{
			{
				Function: "file_exists",
				Args:     map[string]interface{}{"path": "/etc/passwd"},
			},
		},
		Remediation: "No action needed.",
	}

	if td.ID != "test_check_01" {
		t.Errorf("ID = %q, want %q", td.ID, "test_check_01")
	}
	if td.Name != "Test Check" {
		t.Errorf("Name = %q, want %q", td.Name, "Test Check")
	}
	if len(td.Steps) != 1 {
		t.Errorf("Steps count = %d, want 1", len(td.Steps))
	}
	if td.Steps[0].Function != "file_exists" {
		t.Errorf("Step function = %q, want %q", td.Steps[0].Function, "file_exists")
	}
}

func TestTestResult_Fields(t *testing.T) {
	r := TestResult{
		ID:       "test_01",
		Name:     "Test",
		Status:   StatusPass,
		Category: "test",
		Severity: "low",
		Message:  "all good",
	}

	if r.Status != StatusPass {
		t.Errorf("Status = %q, want %q", r.Status, StatusPass)
	}
	if r.Message != "all good" {
		t.Errorf("Message = %q, want %q", r.Message, "all good")
	}
}

func TestScanReport_Fields(t *testing.T) {
	report := ScanReport{
		Version: "1.0.0",
		System: ScanSystem{
			Hostname: "test-host",
			OS:       "linux",
			EnvType:  "bare-metal",
		},
		Summary: ScanSummary{
			TotalChecks: 10,
			Passed:      8,
			Failed:      1,
			Skipped:     1,
		},
	}

	if report.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", report.Version, "1.0.0")
	}
	if report.System.Hostname != "test-host" {
		t.Errorf("Hostname = %q, want %q", report.System.Hostname, "test-host")
	}
	if report.Summary.TotalChecks != 10 {
		t.Errorf("TotalChecks = %d, want %d", report.Summary.TotalChecks, 10)
	}
}

func TestAcceptableBlock_Fields(t *testing.T) {
	ab := AcceptableBlock{
		When:   []string{"container"},
		Reason: "Ephemeral container, host controls this.",
	}

	if len(ab.When) != 1 || ab.When[0] != "container" {
		t.Errorf("When = %v, want [container]", ab.When)
	}
	if ab.Reason != "Ephemeral container, host controls this." {
		t.Errorf("Reason = %q", ab.Reason)
	}
}

func TestConditionBlock_Fields(t *testing.T) {
	cb := ConditionBlock{
		OS:     "linux",
		Distro: "ubuntu",
	}

	if cb.OS != "linux" {
		t.Errorf("OS = %q, want %q", cb.OS, "linux")
	}
	if cb.Distro != "ubuntu" {
		t.Errorf("Distro = %q, want %q", cb.Distro, "ubuntu")
	}
	if cb.Environment != "" {
		t.Errorf("Environment = %q, want empty", cb.Environment)
	}
}

func TestRequirements_Fields(t *testing.T) {
	req := Requirements{
		Privilege: "root",
		Note:      "Needs access to /etc/shadow",
	}

	if req.Privilege != "root" {
		t.Errorf("Privilege = %q, want %q", req.Privilege, "root")
	}
	if req.Note != "Needs access to /etc/shadow" {
		t.Errorf("Note = %q", req.Note)
	}
}

func TestScanFilters_Fields(t *testing.T) {
	sf := ScanFilters{
		CheckID: "my_check",
		Profile: "server",
	}

	if sf.CheckID != "my_check" {
		t.Errorf("CheckID = %q, want %q", sf.CheckID, "my_check")
	}
	if sf.Profile != "server" {
		t.Errorf("Profile = %q, want %q", sf.Profile, "server")
	}
}
