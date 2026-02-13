package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ancients-collective/sesha/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestExecutor(ctx types.SystemContext) *Executor {
	registry := NewFunctionRegistry(nil)
	return NewExecutor(registry, ctx)
}

func linuxContext() types.SystemContext {
	return types.SystemContext{
		OS:            types.OSInfo{Name: "linux", Version: "6.1.0", Arch: "amd64"},
		Distro:        types.DistroInfo{ID: "ubuntu", Version: "22.04", Family: "debian"},
		Environment:   types.EnvInfo{Type: "bare-metal"},
		IntentProfile: "server",
	}
}

func TestExecutor_AllStepsPass(t *testing.T) {
	dir := t.TempDir()
	createTestFile(t, dir, "testfile", "hello world", 0o644)

	exec := newTestExecutor(linuxContext())
	test := types.TestDefinition{
		ID:          "test_pass",
		Name:        "All Steps Pass",
		Severity:    "high",
		Category:    "test",
		Remediation: "fix it",
		Steps: []types.TestStep{
			{
				Function: "file_exists",
				Args:     map[string]interface{}{"path": dir + "/testfile"},
			},
			{
				Function: "file_permissions",
				Args:     map[string]interface{}{"path": dir + "/testfile", "permissions": "0644"},
			},
		},
	}

	result := exec.RunTest(test)

	assert.Equal(t, types.StatusPass, result.Status)
	assert.Equal(t, "test_pass", result.ID)
	assert.Equal(t, "All Steps Pass", result.Name)
	assert.Equal(t, "high", result.Severity)
	assert.Equal(t, "test", result.Category)
	assert.Equal(t, "fix it", result.Remediation)
	assert.True(t, result.Duration > 0)
}

func TestExecutor_FirstStepFails(t *testing.T) {
	exec := newTestExecutor(linuxContext())
	test := types.TestDefinition{
		ID:          "test_fail",
		Name:        "First Step Fails",
		Severity:    "critical",
		Category:    "test",
		Remediation: "fix it",
		Steps: []types.TestStep{
			{
				Function: "file_exists",
				Args:     map[string]interface{}{"path": "/nonexistent/file"},
			},
			{
				Function: "file_exists",
				Args:     map[string]interface{}{"path": "/etc/passwd"},
			},
		},
	}

	result := exec.RunTest(test)

	assert.Equal(t, types.StatusFail, result.Status)
	assert.Contains(t, result.Message, "does not exist")
}

func TestExecutor_SkipWrongOS(t *testing.T) {
	ctx := types.SystemContext{OS: types.OSInfo{Name: "darwin"}}
	exec := NewExecutor(NewFunctionRegistry(nil), ctx)

	test := types.TestDefinition{
		ID:          "linux_only",
		Name:        "Linux Only Test",
		Severity:    "medium",
		Category:    "test",
		SupportedOS: []string{"linux"},
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": "/etc/passwd"}},
		},
		Remediation: "fix it",
	}

	result := exec.RunTest(test)

	assert.Equal(t, types.StatusSkip, result.Status)
	assert.Contains(t, result.Message, "darwin")
	assert.True(t, result.Duration > 0)
}

func TestExecutor_SkipWrongDistro(t *testing.T) {
	ctx := types.SystemContext{
		OS:     types.OSInfo{Name: "linux"},
		Distro: types.DistroInfo{ID: "rhel"},
	}
	exec := NewExecutor(NewFunctionRegistry(nil), ctx)

	test := types.TestDefinition{
		ID:             "ubuntu_only",
		Name:           "Ubuntu Only Test",
		Severity:       "low",
		Category:       "test",
		RequiredDistro: []string{"ubuntu", "debian"},
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": "/etc/passwd"}},
		},
		Remediation: "fix it",
	}

	result := exec.RunTest(test)

	assert.Equal(t, types.StatusSkip, result.Status)
	assert.Contains(t, result.Message, "rhel")
}

func TestExecutor_SkipWrongProfile(t *testing.T) {
	ctx := types.SystemContext{
		OS:            types.OSInfo{Name: "linux"},
		IntentProfile: "workstation",
	}
	exec := NewExecutor(NewFunctionRegistry(nil), ctx)

	test := types.TestDefinition{
		ID:       "server_only",
		Name:     "Server Only Test",
		Severity: "high",
		Category: "test",
		Profiles: []string{"server"},
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": "/etc/passwd"}},
		},
		Remediation: "fix it",
	}

	result := exec.RunTest(test)

	assert.Equal(t, types.StatusSkip, result.Status)
	assert.Contains(t, result.Message, "workstation")
}

func TestExecutor_ConditionalStepSkipped(t *testing.T) {
	dir := t.TempDir()
	createTestFile(t, dir, "testfile", "content", 0o644)

	exec := newTestExecutor(linuxContext())
	test := types.TestDefinition{
		ID:       "conditional_test",
		Name:     "Conditional Step Test",
		Severity: "medium",
		Category: "test",
		Steps: []types.TestStep{
			{
				Function: "file_exists",
				Args:     map[string]interface{}{"path": dir + "/testfile"},
			},
			{
				Function: "file_exists",
				Args:     map[string]interface{}{"path": "/darwin/only"},
				When:     &types.ConditionBlock{OS: "darwin"},
			},
		},
		Remediation: "fix it",
	}

	result := exec.RunTest(test)

	assert.Equal(t, types.StatusPass, result.Status)
}

func TestExecutor_AllStepsConditionalSkipped(t *testing.T) {
	ctx := types.SystemContext{OS: types.OSInfo{Name: "linux"}}
	exec := NewExecutor(NewFunctionRegistry(nil), ctx)

	test := types.TestDefinition{
		ID:       "all_skipped",
		Name:     "All Steps Skipped",
		Severity: "low",
		Category: "test",
		Steps: []types.TestStep{
			{
				Function: "file_exists",
				Args:     map[string]interface{}{"path": "/some/path"},
				When:     &types.ConditionBlock{OS: "darwin"},
			},
			{
				Function: "file_exists",
				Args:     map[string]interface{}{"path": "/other/path"},
				When:     &types.ConditionBlock{OS: "windows"},
			},
		},
		Remediation: "fix it",
	}

	result := exec.RunTest(test)

	assert.Equal(t, types.StatusSkip, result.Status)
	assert.Contains(t, result.Message, "no steps executed")
}

func TestExecutor_FunctionError(t *testing.T) {
	exec := newTestExecutor(linuxContext())
	test := types.TestDefinition{
		ID:       "error_test",
		Name:     "Error Test",
		Severity: "high",
		Category: "test",
		Steps: []types.TestStep{
			{
				Function: "file_permissions",
				Args:     map[string]interface{}{},
			},
		},
		Remediation: "fix it",
	}

	result := exec.RunTest(test)

	assert.Equal(t, types.StatusError, result.Status)
	assert.NotEmpty(t, result.Message)
}

func TestExecutor_MetadataCopied(t *testing.T) {
	dir := t.TempDir()
	createTestFile(t, dir, "testfile", "content", 0o644)

	exec := newTestExecutor(linuxContext())
	test := types.TestDefinition{
		ID:          "metadata_test",
		Name:        "Metadata Copy Test",
		Severity:    "critical",
		Category:    "security",
		Remediation: "Do something specific",
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": dir + "/testfile"}},
		},
	}

	result := exec.RunTest(test)

	assert.Equal(t, "metadata_test", result.ID)
	assert.Equal(t, "Metadata Copy Test", result.Name)
	assert.Equal(t, "critical", result.Severity)
	assert.Equal(t, "security", result.Category)
	assert.Equal(t, "Do something specific", result.Remediation)
}

func TestExecutor_DurationRecorded(t *testing.T) {
	exec := newTestExecutor(linuxContext())
	test := types.TestDefinition{
		ID:       "duration_test",
		Name:     "Duration Test",
		Severity: "info",
		Category: "test",
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": "/tmp"}},
		},
		Remediation: "fix it",
	}

	result := exec.RunTest(test)
	assert.True(t, result.Duration > 0)
}

func TestExecutor_DistroConditionalStep(t *testing.T) {
	dir := t.TempDir()
	createTestFile(t, dir, "testfile", "content", 0o644)

	ctx := linuxContext()
	exec := NewExecutor(NewFunctionRegistry(nil), ctx)

	test := types.TestDefinition{
		ID:       "distro_conditional",
		Name:     "Distro Conditional",
		Severity: "medium",
		Category: "test",
		Steps: []types.TestStep{
			{
				Function: "file_exists",
				Args:     map[string]interface{}{"path": dir + "/testfile"},
				When:     &types.ConditionBlock{Distro: "ubuntu"},
			},
			{
				Function: "file_exists",
				Args:     map[string]interface{}{"path": "/rhel/only"},
				When:     &types.ConditionBlock{Distro: "rhel"},
			},
		},
		Remediation: "fix it",
	}

	result := exec.RunTest(test)
	assert.Equal(t, types.StatusPass, result.Status)
}

// createTestFile is a helper to create a file with specific permissions in a temp dir.
func createTestFile(t *testing.T, dir, name, content string, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), perm))
	require.NoError(t, os.Chmod(path, perm))
	return path
}

// --- Context-Aware Executor Tests ---

func TestExecutor_SeverityOverride_ByEnvironment(t *testing.T) {
	exec := newTestExecutor(types.SystemContext{
		OS:          types.OSInfo{Name: "linux"},
		Environment: types.EnvInfo{Type: "container"},
	})

	test := types.TestDefinition{
		ID:          "sev_override_env",
		Name:        "Severity Override By Env",
		Severity:    "high",
		Category:    "test",
		Remediation: "fix it",
		SeverityOverrides: map[string]string{
			"container": "low",
		},
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": "/nonexistent"}},
		},
	}

	result := exec.RunTest(test)

	assert.Equal(t, types.StatusFail, result.Status)
	assert.Equal(t, "low", result.Severity)
	assert.Equal(t, "high", result.OriginalSeverity)
}

func TestExecutor_SeverityOverride_ByProfile(t *testing.T) {
	exec := newTestExecutor(types.SystemContext{
		OS:            types.OSInfo{Name: "linux"},
		Environment:   types.EnvInfo{Type: "bare-metal"},
		IntentProfile: "workstation",
	})

	test := types.TestDefinition{
		ID:          "sev_override_profile",
		Name:        "Severity Override By Profile",
		Severity:    "critical",
		Category:    "test",
		Remediation: "fix it",
		SeverityOverrides: map[string]string{
			"workstation": "medium",
		},
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": "/nonexistent"}},
		},
	}

	result := exec.RunTest(test)

	assert.Equal(t, "medium", result.Severity)
	assert.Equal(t, "critical", result.OriginalSeverity)
}

func TestExecutor_SeverityOverride_EnvTakesPrecedenceOverProfile(t *testing.T) {
	exec := newTestExecutor(types.SystemContext{
		OS:            types.OSInfo{Name: "linux"},
		Environment:   types.EnvInfo{Type: "container"},
		IntentProfile: "server",
	})

	test := types.TestDefinition{
		ID:          "sev_precedence",
		Name:        "Env Beats Profile",
		Severity:    "high",
		Category:    "test",
		Remediation: "fix it",
		SeverityOverrides: map[string]string{
			"container": "info",
			"server":    "medium",
		},
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": "/nonexistent"}},
		},
	}

	result := exec.RunTest(test)
	assert.Equal(t, "info", result.Severity)
	assert.Equal(t, "high", result.OriginalSeverity)
}

func TestExecutor_NoSeverityOverride(t *testing.T) {
	exec := newTestExecutor(linuxContext())
	test := types.TestDefinition{
		ID:          "no_override",
		Name:        "No Override",
		Severity:    "high",
		Category:    "test",
		Remediation: "fix it",
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": "/nonexistent"}},
		},
	}

	result := exec.RunTest(test)
	assert.Equal(t, "high", result.Severity)
	assert.Empty(t, result.OriginalSeverity)
}

func TestExecutor_ContextNote_Applied(t *testing.T) {
	exec := newTestExecutor(types.SystemContext{
		OS:          types.OSInfo{Name: "linux"},
		Environment: types.EnvInfo{Type: "container"},
	})

	test := types.TestDefinition{
		ID:          "ctx_note",
		Name:        "Context Note Test",
		Severity:    "medium",
		Category:    "test",
		Remediation: "fix it",
		ContextNotes: map[string]string{
			"container": "Less relevant in ephemeral containers",
		},
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": "/nonexistent"}},
		},
	}

	result := exec.RunTest(test)
	assert.Equal(t, "Less relevant in ephemeral containers", result.ContextNote)
}

func TestExecutor_AcceptableBlock_Matches(t *testing.T) {
	exec := newTestExecutor(types.SystemContext{
		OS:          types.OSInfo{Name: "linux"},
		Environment: types.EnvInfo{Type: "container"},
	})

	test := types.TestDefinition{
		ID:          "acceptable_match",
		Name:        "Acceptable Match",
		Severity:    "medium",
		Category:    "test",
		Remediation: "fix it",
		Acceptable: &types.AcceptableBlock{
			When:   []string{"container"},
			Reason: "Not applicable in containers",
		},
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": "/nonexistent"}},
		},
	}

	result := exec.RunTest(test)
	assert.Equal(t, types.StatusAccepted, result.Status)
	assert.Equal(t, "Not applicable in containers", result.AcceptedReason)
}

func TestExecutor_AcceptableBlock_NoMatch(t *testing.T) {
	exec := newTestExecutor(types.SystemContext{
		OS:          types.OSInfo{Name: "linux"},
		Environment: types.EnvInfo{Type: "bare-metal"},
	})

	test := types.TestDefinition{
		ID:          "acceptable_nomatch",
		Name:        "Acceptable No Match",
		Severity:    "medium",
		Category:    "test",
		Remediation: "fix it",
		Acceptable: &types.AcceptableBlock{
			When:   []string{"container"},
			Reason: "Not applicable in containers",
		},
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": "/nonexistent"}},
		},
	}

	result := exec.RunTest(test)
	assert.Equal(t, types.StatusFail, result.Status)
	assert.Empty(t, result.AcceptedReason)
}

func TestExecutor_AcceptableBlock_MatchesByProfile(t *testing.T) {
	exec := newTestExecutor(types.SystemContext{
		OS:            types.OSInfo{Name: "linux"},
		Environment:   types.EnvInfo{Type: "bare-metal"},
		IntentProfile: "workstation",
	})

	test := types.TestDefinition{
		ID:          "acceptable_profile",
		Name:        "Acceptable By Profile",
		Severity:    "medium",
		Category:    "test",
		Remediation: "fix it",
		Acceptable: &types.AcceptableBlock{
			When:   []string{"workstation"},
			Reason: "Acceptable on workstations",
		},
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": "/nonexistent"}},
		},
	}

	result := exec.RunTest(test)
	assert.Equal(t, types.StatusAccepted, result.Status)
	assert.Equal(t, "Acceptable on workstations", result.AcceptedReason)
}

func TestExecutor_ImpactCopiedToResult(t *testing.T) {
	exec := newTestExecutor(linuxContext())
	test := types.TestDefinition{
		ID:          "impact_test",
		Name:        "Impact Test",
		Severity:    "high",
		Category:    "test",
		Remediation: "fix it",
		Impact:      "Attacker gains root shell access",
		Explain:     "Root login allows direct access without audit trail",
		BreakRisk:   "May break automated deployment scripts",
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": "/nonexistent"}},
		},
	}

	result := exec.RunTest(test)
	assert.Equal(t, "Attacker gains root shell access", result.Impact)
	assert.Equal(t, "Root login allows direct access without audit trail", result.Explain)
	assert.Equal(t, "May break automated deployment scripts", result.BreakRisk)
}

func TestExecutor_PassingTestGetsContextOverrides(t *testing.T) {
	dir := t.TempDir()
	createTestFile(t, dir, "testfile", "content", 0o644)

	exec := newTestExecutor(types.SystemContext{
		OS:          types.OSInfo{Name: "linux"},
		Environment: types.EnvInfo{Type: "container"},
	})

	test := types.TestDefinition{
		ID:          "pass_with_override",
		Name:        "Passing With Override",
		Severity:    "high",
		Category:    "test",
		Remediation: "fix it",
		SeverityOverrides: map[string]string{
			"container": "low",
		},
		ContextNotes: map[string]string{
			"container": "Less important in containers",
		},
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": dir + "/testfile"}},
		},
	}

	result := exec.RunTest(test)
	assert.Equal(t, types.StatusPass, result.Status)
	assert.Equal(t, "low", result.Severity)
	assert.Equal(t, "high", result.OriginalSeverity)
	assert.Equal(t, "Less important in containers", result.ContextNote)
}

func TestExecutor_ForceRun_BypassesOSFilter(t *testing.T) {
	dir := t.TempDir()
	createTestFile(t, dir, "testfile", "hello world", 0o644)

	exec := newTestExecutor(linuxContext())
	exec.ForceRun = true

	test := types.TestDefinition{
		ID:          "darwin_only",
		Name:        "Darwin Only Check",
		Severity:    "medium",
		Category:    "test",
		Remediation: "fix it",
		SupportedOS: []string{"darwin"},
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": dir + "/testfile"}},
		},
	}

	result := exec.RunTest(test)
	assert.NotEqual(t, types.StatusSkip, result.Status, "ForceRun should bypass OS filter")
	assert.Equal(t, types.StatusPass, result.Status)
}

func TestExecutor_ForceRun_BypassesProfileFilter(t *testing.T) {
	dir := t.TempDir()
	createTestFile(t, dir, "testfile", "content", 0o644)

	exec := newTestExecutor(types.SystemContext{
		OS:            types.OSInfo{Name: "linux"},
		IntentProfile: "server",
	})
	exec.ForceRun = true

	test := types.TestDefinition{
		ID:          "container_only",
		Name:        "Container Only Check",
		Severity:    "medium",
		Category:    "test",
		Remediation: "fix it",
		Profiles:    []string{"container"},
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": dir + "/testfile"}},
		},
	}

	result := exec.RunTest(test)
	assert.NotEqual(t, types.StatusSkip, result.Status)
	assert.Equal(t, types.StatusPass, result.Status)
}

func TestExecutor_ForceRun_False_StillSkips(t *testing.T) {
	exec := newTestExecutor(linuxContext())

	test := types.TestDefinition{
		ID:          "darwin_only",
		Name:        "Darwin Only Check",
		Severity:    "medium",
		Category:    "test",
		Remediation: "fix it",
		SupportedOS: []string{"darwin"},
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": "/tmp/anything"}},
		},
	}

	result := exec.RunTest(test)
	assert.Equal(t, types.StatusSkip, result.Status)
}

// ── extractFilePath tests ────────────────────────────────────────────

func TestExtractFilePath_FileCheck(t *testing.T) {
	test := types.TestDefinition{
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": "/etc/ssh/sshd_config"}},
		},
	}
	assert.Equal(t, "/etc/ssh/sshd_config", extractFilePath(test))
}

func TestExtractFilePath_MultipleSteps_TakesFirst(t *testing.T) {
	test := types.TestDefinition{
		Steps: []types.TestStep{
			{Function: "file_permissions", Args: map[string]interface{}{"path": "/etc/passwd", "permissions": "0644"}},
			{Function: "file_owner", Args: map[string]interface{}{"path": "/etc/shadow", "owner": "root"}},
		},
	}
	assert.Equal(t, "/etc/passwd", extractFilePath(test))
}

func TestExtractFilePath_NonFileCheck(t *testing.T) {
	test := types.TestDefinition{
		Steps: []types.TestStep{
			{Function: "service_running", Args: map[string]interface{}{"name": "auditd"}},
		},
	}
	assert.Empty(t, extractFilePath(test))
}

func TestExtractFilePath_NoSteps(t *testing.T) {
	test := types.TestDefinition{}
	assert.Empty(t, extractFilePath(test))
}

func TestExtractFilePath_EmptyPath(t *testing.T) {
	test := types.TestDefinition{
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": ""}},
		},
	}
	assert.Empty(t, extractFilePath(test))
}

func TestExtractFilePath_NonStringPath(t *testing.T) {
	test := types.TestDefinition{
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": 42}},
		},
	}
	assert.Empty(t, extractFilePath(test))
}

func TestExtractFilePath_NilArgs(t *testing.T) {
	test := types.TestDefinition{
		Steps: []types.TestStep{
			{Function: "file_exists", Args: nil},
		},
	}
	assert.Empty(t, extractFilePath(test))
}

func TestExtractFilePath_MixedSteps_SkipsNonFile(t *testing.T) {
	test := types.TestDefinition{
		Steps: []types.TestStep{
			{Function: "service_running", Args: map[string]interface{}{"name": "sshd"}},
			{Function: "file_contains", Args: map[string]interface{}{"path": "/etc/ssh/sshd_config", "pattern": "PermitRootLogin"}},
		},
	}
	assert.Equal(t, "/etc/ssh/sshd_config", extractFilePath(test))
}

func TestRunTest_SetsFilePath(t *testing.T) {
	dir := t.TempDir()
	createTestFile(t, dir, "config.conf", "setting=yes", 0o644)

	exec := newTestExecutor(linuxContext())
	test := types.TestDefinition{
		ID:          "filepath_test",
		Name:        "FilePath Populated",
		Severity:    "low",
		Category:    "test",
		Remediation: "fix it",
		Steps: []types.TestStep{
			{Function: "file_exists", Args: map[string]interface{}{"path": dir + "/config.conf"}},
		},
	}

	result := exec.RunTest(test)
	assert.Equal(t, types.StatusPass, result.Status)
	assert.Equal(t, dir+"/config.conf", result.FilePath)
}
