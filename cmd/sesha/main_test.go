package main

import (
	"testing"

	"github.com/ancients-collective/sesha/internal/types"
	"github.com/stretchr/testify/assert"
)

// ── parseSeverityFilter tests ────────────────────────────────────────

func TestParseSeverityFilter_Empty(t *testing.T) {
	filter, err := parseSeverityFilter("")
	assert.NoError(t, err)
	assert.Nil(t, filter)
}

func TestParseSeverityFilter_SingleValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"critical", "critical"},
		{"high", "high"},
		{"medium", "medium"},
		{"low", "low"},
		{"info", "info"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			filter, err := parseSeverityFilter(tt.input)
			assert.NoError(t, err)
			assert.True(t, filter[tt.want])
			assert.Len(t, filter, 1)
		})
	}
}

func TestParseSeverityFilter_MultipleValues(t *testing.T) {
	filter, err := parseSeverityFilter("critical,high")
	assert.NoError(t, err)
	assert.True(t, filter["critical"])
	assert.True(t, filter["high"])
	assert.False(t, filter["medium"])
	assert.Len(t, filter, 2)
}

func TestParseSeverityFilter_AllValues(t *testing.T) {
	filter, err := parseSeverityFilter("critical,high,medium,low,info")
	assert.NoError(t, err)
	assert.Len(t, filter, 5)
}

func TestParseSeverityFilter_WithSpaces(t *testing.T) {
	filter, err := parseSeverityFilter(" critical , high ")
	assert.NoError(t, err)
	assert.True(t, filter["critical"])
	assert.True(t, filter["high"])
}

func TestParseSeverityFilter_CaseInsensitive(t *testing.T) {
	filter, err := parseSeverityFilter("CRITICAL,High,Medium")
	assert.NoError(t, err)
	assert.True(t, filter["critical"])
	assert.True(t, filter["high"])
	assert.True(t, filter["medium"])
}

func TestParseSeverityFilter_InvalidValue(t *testing.T) {
	_, err := parseSeverityFilter("critical,urgent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "urgent")
}

func TestParseSeverityFilter_AllInvalid(t *testing.T) {
	_, err := parseSeverityFilter("extreme,urgent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "extreme")
	assert.Contains(t, err.Error(), "urgent")
}

func TestParseSeverityFilter_EmptyAfterTrim(t *testing.T) {
	filter, err := parseSeverityFilter("  ,  ,  ")
	assert.NoError(t, err)
	assert.Nil(t, filter)
}

// ── shouldDisplay tests ──────────────────────────────────────────────

func TestShouldDisplay_Findings(t *testing.T) {
	tests := []struct {
		status types.ResultStatus
		want   bool
	}{
		{types.StatusFail, true},
		{types.StatusError, true},
		{types.StatusPass, false},
		{types.StatusSkip, false},
		{types.StatusAccepted, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			r := types.TestResult{Status: tt.status, Severity: "high"}
			assert.Equal(t, tt.want, shouldDisplay(r, "findings", nil))
		})
	}
}

func TestShouldDisplay_All(t *testing.T) {
	for _, status := range []types.ResultStatus{
		types.StatusFail, types.StatusPass, types.StatusSkip, types.StatusError, types.StatusAccepted,
	} {
		r := types.TestResult{Status: status, Severity: "high"}
		assert.True(t, shouldDisplay(r, "all", nil), "all should display %s", status)
	}
}

func TestShouldDisplay_Fail(t *testing.T) {
	tests := []struct {
		status types.ResultStatus
		want   bool
	}{
		{types.StatusFail, true},
		{types.StatusError, false},
		{types.StatusPass, false},
		{types.StatusSkip, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			r := types.TestResult{Status: tt.status, Severity: "high"}
			assert.Equal(t, tt.want, shouldDisplay(r, "fail", nil))
		})
	}
}

func TestShouldDisplay_Pass(t *testing.T) {
	tests := []struct {
		status types.ResultStatus
		want   bool
	}{
		{types.StatusPass, true},
		{types.StatusFail, false},
		{types.StatusError, false},
		{types.StatusSkip, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			r := types.TestResult{Status: tt.status, Severity: "high"}
			assert.Equal(t, tt.want, shouldDisplay(r, "pass", nil))
		})
	}
}

func TestShouldDisplay_SeverityFilter(t *testing.T) {
	filter := map[string]bool{"critical": true, "high": true}

	// High severity fail → shown
	r1 := types.TestResult{Status: types.StatusFail, Severity: "high"}
	assert.True(t, shouldDisplay(r1, "findings", filter))

	// Medium severity fail → filtered out
	r2 := types.TestResult{Status: types.StatusFail, Severity: "medium"}
	assert.False(t, shouldDisplay(r2, "findings", filter))

	// High severity pass → not shown in findings mode
	r3 := types.TestResult{Status: types.StatusPass, Severity: "high"}
	assert.False(t, shouldDisplay(r3, "findings", filter))

	// High severity pass → shown in all mode
	assert.True(t, shouldDisplay(r3, "all", filter))
}

func TestShouldDisplay_NilFilter(t *testing.T) {
	// Nil filter means no severity filtering — all severities pass
	r := types.TestResult{Status: types.StatusFail, Severity: "info"}
	assert.True(t, shouldDisplay(r, "findings", nil))
}

// ── Exit code logic tests ────────────────────────────────────────────

func TestExitCodeLogic(t *testing.T) {
	// This tests the exit code calculation logic (not actual os.Exit)
	tests := []struct {
		name     string
		fail     int
		errCount int
		wantCode int
	}{
		{"clean", 0, 0, 0},
		{"findings", 3, 0, 1},
		{"errors only", 0, 2, 2},
		{"findings and errors", 1, 1, 1}, // findings take priority
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := 0
			if tt.fail > 0 {
				code = 1
			} else if tt.errCount > 0 {
				code = 2
			}
			assert.Equal(t, tt.wantCode, code)
		})
	}
}

// ── parseFlags tests ─────────────────────────────────────────────────

func TestParseFlags_Defaults(t *testing.T) {
	cfg, err := parseFlags([]string{})
	assert.NoError(t, err)
	assert.Equal(t, "", cfg.ChecksDir)
	assert.False(t, cfg.ChecksExplicit)
	assert.Equal(t, "findings", cfg.Show)
	assert.Equal(t, "", cfg.Severity)
	assert.False(t, cfg.Verify)
	assert.Equal(t, "auto", cfg.Profile)
	assert.False(t, cfg.Explain)
	assert.Equal(t, "text", cfg.Format)
	assert.False(t, cfg.NoColor)
	assert.Equal(t, "", cfg.OutputFile)
	assert.False(t, cfg.Quiet)
	assert.Equal(t, "", cfg.CheckID)
	assert.False(t, cfg.ListChecks)
	assert.False(t, cfg.Debug)
	assert.Equal(t, "", cfg.Validate)
	assert.Equal(t, "", cfg.Tags)
}

func TestParseFlags_ChecksExplicit(t *testing.T) {
	cfg, err := parseFlags([]string{"-c", "/custom/path"})
	assert.NoError(t, err)
	assert.Equal(t, "/custom/path", cfg.ChecksDir)
	assert.True(t, cfg.ChecksExplicit)
}

func TestParseFlags_ChecksExplicitLong(t *testing.T) {
	cfg, err := parseFlags([]string{"--checks", "/custom/path"})
	assert.NoError(t, err)
	assert.Equal(t, "/custom/path", cfg.ChecksDir)
	assert.True(t, cfg.ChecksExplicit)
}

func TestParseFlags_ChecksNotExplicit(t *testing.T) {
	cfg, err := parseFlags([]string{"--show", "all"})
	assert.NoError(t, err)
	assert.Equal(t, "", cfg.ChecksDir)
	assert.False(t, cfg.ChecksExplicit)
}

func TestParseFlags_AllLongFlags(t *testing.T) {
	cfg, err := parseFlags([]string{
		"--checks", "/custom/checks",
		"--show", "all",
		"--severity", "critical,high",
		"--verify",
		"--profile", "server",
		"--explain",
		"--format", "json",
		"--no-color",
		"--output", "/tmp/out.json",
		"--quiet",
		"--id", "ssh_port",
		"--list-checks",
		"--debug",
		"--validate", "/some/path",
		"--tags", "web-server,cis-benchmark",
	})
	assert.NoError(t, err)
	assert.Equal(t, "/custom/checks", cfg.ChecksDir)
	assert.Equal(t, "all", cfg.Show)
	assert.Equal(t, "critical,high", cfg.Severity)
	assert.True(t, cfg.Verify)
	assert.Equal(t, "server", cfg.Profile)
	assert.True(t, cfg.Explain)
	assert.Equal(t, "json", cfg.Format)
	assert.True(t, cfg.NoColor)
	assert.Equal(t, "/tmp/out.json", cfg.OutputFile)
	assert.True(t, cfg.Quiet)
	assert.Equal(t, "ssh_port", cfg.CheckID)
	assert.True(t, cfg.ListChecks)
	assert.True(t, cfg.Debug)
	assert.Equal(t, "/some/path", cfg.Validate)
	assert.Equal(t, "web-server,cis-benchmark", cfg.Tags)
}

func TestParseFlags_ShortFlags(t *testing.T) {
	cfg, err := parseFlags([]string{
		"-c", "/short/checks",
		"-s", "pass",
		"--sev", "low",
		"-p", "container",
		"-f", "jsonl",
		"-o", "/tmp/short.json",
		"-q",
	})
	assert.NoError(t, err)
	assert.Equal(t, "/short/checks", cfg.ChecksDir)
	assert.Equal(t, "pass", cfg.Show)
	assert.Equal(t, "low", cfg.Severity)
	assert.Equal(t, "container", cfg.Profile)
	assert.Equal(t, "jsonl", cfg.Format)
	assert.Equal(t, "/tmp/short.json", cfg.OutputFile)
	assert.True(t, cfg.Quiet)
}

func TestParseFlags_UnknownFlag(t *testing.T) {
	_, err := parseFlags([]string{"--nonexistent-flag"})
	assert.Error(t, err)
}

func TestParseFlags_RejectsEnterpriseFlags(t *testing.T) {
	enterpriseFlags := []string{
		"--waivers", "--no-cloud", "--runbook", "--category", "--tag",
	}
	for _, f := range enterpriseFlags {
		t.Run(f, func(t *testing.T) {
			_, err := parseFlags([]string{f})
			assert.Error(t, err, "flag %s should not be accepted", f)
		})
	}
}
