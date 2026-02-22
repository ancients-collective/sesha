package loader

import (
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testKnownFunctions = []string{
	"file_exists",
	"file_permissions",
	"file_contains",
	"port_listening",
	"service_running",
}

func writeYAML(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

const validTestYAML = `id: ssh_root_login
name: "SSH Root Login Disabled"
description: "Verifies that root login via SSH is disabled"
severity: high
category: ssh
supported_os:
  - linux
steps:
  - function: file_contains
    args:
      path: /etc/ssh/sshd_config
      pattern: "^PermitRootLogin\\s+no"
remediation: "Set PermitRootLogin to no in /etc/ssh/sshd_config"
`

func TestLoadTest_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := writeYAML(t, dir, "ssh_root_login.yaml", validTestYAML)

	loader := New(testKnownFunctions)
	test, err := loader.LoadTest(path)

	require.NoError(t, err)
	assert.Equal(t, "ssh_root_login", test.ID)
	assert.Equal(t, "SSH Root Login Disabled", test.Name)
	assert.Equal(t, "high", test.Severity)
	assert.Equal(t, "ssh", test.Category)
	assert.Equal(t, []string{"linux"}, test.SupportedOS)
	assert.Len(t, test.Steps, 1)
	assert.Equal(t, "file_contains", test.Steps[0].Function)
	assert.Nil(t, test.Steps[0].When)
}

func TestLoadTest_WithConditionalStep(t *testing.T) {
	yaml := `id: firewall_check
name: "Firewall Active"
description: "Checks if firewall is running"
severity: medium
category: firewall
steps:
  - function: service_running
    args:
      name: ufw
    when:
      os: linux
      distro: ubuntu
  - function: service_running
    args:
      name: firewalld
    when:
      os: linux
      distro: rhel
remediation: "Enable your firewall service"
`
	dir := t.TempDir()
	path := writeYAML(t, dir, "firewall.yaml", yaml)

	loader := New(testKnownFunctions)
	test, err := loader.LoadTest(path)

	require.NoError(t, err)
	assert.Len(t, test.Steps, 2)
	require.NotNil(t, test.Steps[0].When)
	assert.Equal(t, "linux", test.Steps[0].When.OS)
	assert.Equal(t, "ubuntu", test.Steps[0].When.Distro)
	require.NotNil(t, test.Steps[1].When)
	assert.Equal(t, "rhel", test.Steps[1].When.Distro)
}

func TestLoadTest_AllOptionalFields(t *testing.T) {
	yaml := `id: full_test
name: "Full Featured Test"
description: "Tests all optional fields"
severity: critical
category: system
supported_os:
  - linux
  - darwin
required_distro:
  - ubuntu
  - debian
environment: container
profiles:
  - server
  - workstation
tags:
  - security
  - hardening
references:
  - https://example.com/cis-benchmark
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "Ensure /etc/passwd exists"
`
	dir := t.TempDir()
	path := writeYAML(t, dir, "full.yaml", yaml)

	loader := New(testKnownFunctions)
	test, err := loader.LoadTest(path)

	require.NoError(t, err)
	assert.Equal(t, []string{"linux", "darwin"}, test.SupportedOS)
	assert.Equal(t, []string{"ubuntu", "debian"}, test.RequiredDistro)
	assert.Equal(t, "container", test.Environment)
	assert.Equal(t, []string{"server", "workstation"}, test.Profiles)
	assert.Equal(t, []string{"security", "hardening"}, test.Tags)
	assert.Equal(t, []string{"https://example.com/cis-benchmark"}, test.References)
}

func TestLoadTest_FileNotFound(t *testing.T) {
	loader := New(testKnownFunctions)
	_, err := loader.LoadTest("/nonexistent/path.yaml")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to stat")
}

func TestLoadTest_InvalidYAMLSyntax(t *testing.T) {
	dir := t.TempDir()
	path := writeYAML(t, dir, "bad.yaml", "id: [unterminated\n  broken: yaml: :")

	loader := New(testKnownFunctions)
	_, err := loader.LoadTest(path)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse YAML")
}

func TestLoadTest_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		errorMsg string
	}{
		{
			name:     "missing severity",
			yaml:     "id: test1\nname: \"Test Name\"\ndescription: \"desc\"\ncategory: cat\nsteps:\n  - function: file_exists\n    args:\n      path: /tmp\nremediation: \"fix it\"",
			errorMsg: "Severity",
		},
		{
			name:     "missing steps",
			yaml:     "id: test1\nname: \"Test Name\"\ndescription: \"desc\"\nseverity: high\ncategory: cat\nremediation: \"fix it\"",
			errorMsg: "Steps",
		},
		{
			name:     "empty steps array",
			yaml:     "id: test1\nname: \"Test Name\"\ndescription: \"desc\"\nseverity: high\ncategory: cat\nsteps: []\nremediation: \"fix it\"",
			errorMsg: "Steps",
		},
		{
			name:     "missing remediation",
			yaml:     "id: test1\nname: \"Test Name\"\ndescription: \"desc\"\nseverity: high\ncategory: cat\nsteps:\n  - function: file_exists\n    args:\n      path: /tmp",
			errorMsg: "Remediation",
		},
		{
			name:     "missing function in step",
			yaml:     "id: test1\nname: \"Test Name\"\ndescription: \"desc\"\nseverity: high\ncategory: cat\nsteps:\n  - args:\n      path: /tmp\nremediation: \"fix it\"",
			errorMsg: "Function",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeYAML(t, dir, "test.yaml", tt.yaml)

			loader := New(testKnownFunctions)
			_, err := loader.LoadTest(path)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorMsg)
		})
	}
}

func TestLoadTest_InvalidSeverity(t *testing.T) {
	yaml := `id: test1
name: "Test Name"
description: "desc"
severity: urgent
category: cat
steps:
  - function: file_exists
    args:
      path: /tmp
remediation: "fix it"`

	dir := t.TempDir()
	path := writeYAML(t, dir, "test.yaml", yaml)

	loader := New(testKnownFunctions)
	_, err := loader.LoadTest(path)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Severity")
}

func TestLoadTest_InvalidID(t *testing.T) {
	tests := []struct {
		name string
		id   string
	}{
		{"spaces", "test with spaces"},
		{"special chars", "test@#$%"},
		{"dots", "test.name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := `id: "` + tt.id + `"
name: "Test Name"
description: "desc"
severity: high
category: cat
steps:
  - function: file_exists
    args:
      path: /tmp
remediation: "fix it"`

			dir := t.TempDir()
			path := writeYAML(t, dir, "test.yaml", yaml)

			loader := New(testKnownFunctions)
			_, err := loader.LoadTest(path)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "ID")
		})
	}
}

func TestLoadTest_ValidIDFormats(t *testing.T) {
	tests := []struct {
		name string
		id   string
	}{
		{"alphanumeric", "test123"},
		{"underscores", "ssh_root_login"},
		{"hyphens", "ssh-root-login"},
		{"mixed", "ssh_root-login_v2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := `id: ` + tt.id + `
name: "Test Name"
description: "desc"
severity: high
category: cat
steps:
  - function: file_exists
    args:
      path: /tmp
remediation: "fix it"`

			dir := t.TempDir()
			path := writeYAML(t, dir, "test.yaml", yaml)

			loader := New(testKnownFunctions)
			test, err := loader.LoadTest(path)

			require.NoError(t, err)
			assert.Equal(t, tt.id, test.ID)
		})
	}
}

func TestLoadTest_InvalidOS(t *testing.T) {
	yaml := `id: test1
name: "Test Name"
description: "desc"
severity: high
category: cat
supported_os:
  - windows
steps:
  - function: file_exists
    args:
      path: /tmp
remediation: "fix it"`

	dir := t.TempDir()
	path := writeYAML(t, dir, "test.yaml", yaml)

	loader := New(testKnownFunctions)
	_, err := loader.LoadTest(path)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "SupportedOS")
}

func TestLoadTest_UnknownFunction(t *testing.T) {
	yaml := `id: test1
name: "Test Name"
description: "desc"
severity: high
category: cat
steps:
  - function: hack_system
    args:
      target: everything
remediation: "fix it"`

	dir := t.TempDir()
	path := writeYAML(t, dir, "test.yaml", yaml)

	loader := New(testKnownFunctions)
	_, err := loader.LoadTest(path)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown function")
	assert.Contains(t, err.Error(), "hack_system")
}

func TestLoadTest_UnknownFunctionWithEmptyKnown(t *testing.T) {
	yaml := `id: test1
name: "Test Name"
description: "desc"
severity: high
category: cat
steps:
  - function: file_exists
    args:
      path: /tmp
remediation: "fix it"`

	dir := t.TempDir()
	path := writeYAML(t, dir, "test.yaml", yaml)

	loader := New([]string{})
	_, err := loader.LoadTest(path)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown function")
}

func TestLoadDirectory_RecursiveLoad(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "ssh/root_login.yaml", validTestYAML)
	writeYAML(t, dir, "ssh/protocol.yaml", `id: ssh_protocol
name: "SSH Protocol Version"
description: "Check SSH protocol version"
severity: medium
category: ssh
steps:
  - function: file_contains
    args:
      path: /etc/ssh/sshd_config
      pattern: "^Protocol 2"
remediation: "Set Protocol 2 in sshd_config"
`)
	writeYAML(t, dir, "firewall/ufw.yaml", `id: ufw_active
name: "UFW Active"
description: "Check UFW is active"
severity: high
category: firewall
steps:
  - function: service_running
    args:
      name: ufw
remediation: "Enable UFW"
`)

	loader := New(testKnownFunctions)
	tests, errs := loader.LoadDirectory(dir)

	assert.Empty(t, errs)
	assert.Len(t, tests, 3)
}

func TestLoadDirectory_MixedFiles(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "test.yaml", validTestYAML)
	writeYAML(t, dir, "readme.txt", "This is not YAML")
	writeYAML(t, dir, "config.json", `{"key": "value"}`)

	loader := New(testKnownFunctions)
	tests, errs := loader.LoadDirectory(dir)

	assert.Empty(t, errs)
	assert.Len(t, tests, 1)
}

func TestLoadDirectory_YMLExtension(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "test.yml", validTestYAML)

	loader := New(testKnownFunctions)
	tests, errs := loader.LoadDirectory(dir)

	assert.Empty(t, errs)
	assert.Len(t, tests, 1)
}

func TestLoadDirectory_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	loader := New(testKnownFunctions)
	tests, errs := loader.LoadDirectory(dir)

	assert.Empty(t, errs)
	assert.Empty(t, tests)
}

func TestLoadDirectory_InvalidFileContinuesLoading(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "good.yaml", validTestYAML)
	writeYAML(t, dir, "bad.yaml", "id: [broken yaml")

	loader := New(testKnownFunctions)
	tests, errs := loader.LoadDirectory(dir)

	assert.Len(t, errs, 1)
	assert.Len(t, tests, 1)
}

func TestLoadDirectory_NonexistentDirectory(t *testing.T) {
	loader := New(testKnownFunctions)
	_, errs := loader.LoadDirectory("/nonexistent/directory")

	assert.NotEmpty(t, errs)
}

func TestNew_NilFunctionsDefaultsToEmpty(t *testing.T) {
	loader := New(nil)
	assert.NotNil(t, loader)

	dir := t.TempDir()
	path := writeYAML(t, dir, "test.yaml", validTestYAML)
	_, err := loader.LoadTest(path)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown function")
}

func TestLoadTest_StepMissingArgs(t *testing.T) {
	yaml := `id: test1
name: "Test Name"
description: "desc"
severity: high
category: cat
steps:
  - function: file_exists
remediation: "fix it"`

	dir := t.TempDir()
	path := writeYAML(t, dir, "test.yaml", yaml)

	loader := New(testKnownFunctions)
	_, err := loader.LoadTest(path)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Args")
}

func TestLoadTest_NameTooShort(t *testing.T) {
	yaml := `id: test1
name: "Ab"
description: "desc"
severity: high
category: cat
steps:
  - function: file_exists
    args:
      path: /tmp
remediation: "fix it"`

	dir := t.TempDir()
	path := writeYAML(t, dir, "test.yaml", yaml)

	loader := New(testKnownFunctions)
	_, err := loader.LoadTest(path)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Name")
}

func TestLoadTest_InvalidEnvironment(t *testing.T) {
	yaml := `id: test1
name: "Test Name"
description: "desc"
severity: high
category: cat
environment: spacecraft
steps:
  - function: file_exists
    args:
      path: /tmp
remediation: "fix it"`

	dir := t.TempDir()
	path := writeYAML(t, dir, "test.yaml", yaml)

	loader := New(testKnownFunctions)
	_, err := loader.LoadTest(path)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Environment")
}

func TestLoadTest_InvalidProfile(t *testing.T) {
	yaml := `id: test1
name: "Test Name"
description: "desc"
severity: high
category: cat
profiles:
  - desktop
steps:
  - function: file_exists
    args:
      path: /tmp
remediation: "fix it"`

	dir := t.TempDir()
	path := writeYAML(t, dir, "test.yaml", yaml)

	loader := New(testKnownFunctions)
	_, err := loader.LoadTest(path)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Profiles")
}

func TestLoadTest_InvalidReference(t *testing.T) {
	yaml := `id: test1
name: "Test Name"
description: "desc"
severity: high
category: cat
references:
  - not-a-url
steps:
  - function: file_exists
    args:
      path: /tmp
remediation: "fix it"`

	dir := t.TempDir()
	path := writeYAML(t, dir, "test.yaml", yaml)

	loader := New(testKnownFunctions)
	_, err := loader.LoadTest(path)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "References")
}

func TestLoadTest_PreservesOrder(t *testing.T) {
	yaml := `id: ordered_test
name: "Ordered Steps Test"
description: "Steps should preserve order"
severity: medium
category: test
steps:
  - function: file_exists
    args:
      path: /first
  - function: file_permissions
    args:
      path: /second
      permissions: "0644"
  - function: file_contains
    args:
      path: /third
      pattern: "test"
remediation: "fix it"`

	dir := t.TempDir()
	path := writeYAML(t, dir, "test.yaml", yaml)

	loader := New(testKnownFunctions)
	test, err := loader.LoadTest(path)

	require.NoError(t, err)
	require.Len(t, test.Steps, 3)
	assert.Equal(t, "file_exists", test.Steps[0].Function)
	assert.Equal(t, "file_permissions", test.Steps[1].Function)
	assert.Equal(t, "file_contains", test.Steps[2].Function)
}

func TestKnownFunctions_Injected(t *testing.T) {
	yaml := `id: test1
name: "Test Name"
description: "desc"
severity: high
category: cat
steps:
  - function: custom_check
    args:
      target: something
remediation: "fix it"`

	dir := t.TempDir()
	path := writeYAML(t, dir, "test.yaml", yaml)

	loader1 := New(testKnownFunctions)
	_, err := loader1.LoadTest(path)
	require.Error(t, err)

	loader2 := New([]string{"custom_check"})
	test, err := loader2.LoadTest(path)
	require.NoError(t, err)
	assert.Equal(t, "custom_check", test.Steps[0].Function)
}

// --- Validation tests for context-aware fields ---

func TestLoadTest_SeverityOverrides_Valid(t *testing.T) {
	yaml := `id: test_sev_override
name: "Test Severity Override"
description: "Test"
severity: high
category: test
supported_os: [linux]
severity_overrides:
  container: low
  workstation: medium
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "fix it"`

	dir := t.TempDir()
	path := writeYAML(t, dir, "test.yaml", yaml)
	loader := New(testKnownFunctions)
	test, err := loader.LoadTest(path)
	require.NoError(t, err)
	assert.Equal(t, "low", test.SeverityOverrides["container"])
	assert.Equal(t, "medium", test.SeverityOverrides["workstation"])
}

func TestLoadTest_SeverityOverrides_InvalidValue(t *testing.T) {
	yaml := `id: test_bad_override
name: "Test Bad Override"
description: "Test"
severity: high
category: test
supported_os: [linux]
severity_overrides:
  container: "extreme"
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "fix it"`

	dir := t.TempDir()
	path := writeYAML(t, dir, "test.yaml", yaml)
	loader := New(testKnownFunctions)
	_, err := loader.LoadTest(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "severity_overrides")
	assert.Contains(t, err.Error(), "extreme")
}

func TestLoadTest_Acceptable_Valid(t *testing.T) {
	yaml := `id: test_acceptable
name: "Test Acceptable"
description: "Test"
severity: medium
category: test
supported_os: [linux]
acceptable:
  when: [container, workstation]
  reason: "Not applicable in this context"
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "fix it"`

	dir := t.TempDir()
	path := writeYAML(t, dir, "test.yaml", yaml)
	loader := New(testKnownFunctions)
	test, err := loader.LoadTest(path)
	require.NoError(t, err)
	require.NotNil(t, test.Acceptable)
	assert.Equal(t, []string{"container", "workstation"}, test.Acceptable.When)
	assert.Equal(t, "Not applicable in this context", test.Acceptable.Reason)
}

func TestLoadTest_Acceptable_InvalidWhenToken(t *testing.T) {
	yaml := `id: test_bad_acceptable
name: "Test Bad Acceptable"
description: "Test"
severity: medium
category: test
supported_os: [linux]
acceptable:
  when: [kubernetes]
  reason: "Bad token"
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "fix it"`

	dir := t.TempDir()
	path := writeYAML(t, dir, "test.yaml", yaml)
	loader := New(testKnownFunctions)
	_, err := loader.LoadTest(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acceptable.when")
	assert.Contains(t, err.Error(), "kubernetes")
}

func TestLoadTest_ImpactFields_Loaded(t *testing.T) {
	yaml := `id: test_impact
name: "Test Impact"
description: "Test"
severity: high
category: test
supported_os: [linux]
impact: "Attacker gains root shell"
explain: "Root login bypasses audit trail"
break_risk: "May break automated deployments"
likelihood: likely
context_notes:
  container: "Less relevant in containers"
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "fix it"`

	dir := t.TempDir()
	path := writeYAML(t, dir, "test.yaml", yaml)
	loader := New(testKnownFunctions)
	test, err := loader.LoadTest(path)
	require.NoError(t, err)
	assert.Equal(t, "Attacker gains root shell", test.Impact)
	assert.Equal(t, "Root login bypasses audit trail", test.Explain)
	assert.Equal(t, "May break automated deployments", test.BreakRisk)
	assert.Equal(t, "likely", test.Likelihood)
	assert.Equal(t, "Less relevant in containers", test.ContextNotes["container"])
}

func TestLoadTest_Likelihood_Invalid(t *testing.T) {
	yaml := `id: test_bad_likelihood
name: "Test Bad Likelihood"
description: "Test"
severity: high
category: test
supported_os: [linux]
likelihood: guaranteed
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "fix it"`

	dir := t.TempDir()
	path := writeYAML(t, dir, "test.yaml", yaml)
	loader := New(testKnownFunctions)
	_, err := loader.LoadTest(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Likelihood")
}

func TestLoadDirectory_DuplicateID(t *testing.T) {
	dir := t.TempDir()
	yaml1 := `id: dup_check
name: "First Check"
description: "First check with this ID"
severity: low
category: test
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "fix it"`

	yaml2 := `id: dup_check
name: "Second Check"
description: "Second check with same ID"
severity: high
category: test
steps:
  - function: file_exists
    args:
      path: /etc/shadow
remediation: "fix it"`

	writeYAML(t, dir, "a_first.yaml", yaml1)
	writeYAML(t, dir, "b_second.yaml", yaml2)

	loader := New(testKnownFunctions)
	tests, errs := loader.LoadDirectory(dir)

	assert.Len(t, tests, 1, "should keep only the first occurrence")
	assert.Equal(t, "First Check", tests[0].Name)
	require.Len(t, errs, 1, "should report one duplicate error")
	assert.Contains(t, errs[0].Error(), "duplicate check ID")
	assert.Contains(t, errs[0].Error(), "dup_check")
}

func TestValidateDirectory_DuplicateID(t *testing.T) {
	dir := t.TempDir()
	yaml1 := `id: dup_val
name: "First Check"
description: "First check"
severity: low
category: test
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "fix it"`

	yaml2 := `id: dup_val
name: "Second Check"
description: "Second check"
severity: high
category: test
steps:
  - function: file_exists
    args:
      path: /etc/shadow
remediation: "fix it"`

	writeYAML(t, dir, "a_first.yaml", yaml1)
	writeYAML(t, dir, "b_second.yaml", yaml2)

	loader := New(testKnownFunctions)
	errs := loader.ValidateDirectory(dir)

	require.Len(t, errs, 1, "should report one duplicate error")
	assert.Contains(t, errs[0].Error(), "duplicate check ID")
	assert.Contains(t, errs[0].Error(), "dup_val")
}

// --- LoadFromFS tests ---

func TestLoadFromFS_SingleFile(t *testing.T) {
	fsys := fstest.MapFS{
		"ssh/root_login.yaml": &fstest.MapFile{Data: []byte(validTestYAML)},
	}

	loader := New(testKnownFunctions)
	tests, errs := loader.LoadFromFS(fsys)

	assert.Empty(t, errs)
	require.Len(t, tests, 1)
	assert.Equal(t, "ssh_root_login", tests[0].ID)
}

func TestLoadFromFS_MultipleSubdirectories(t *testing.T) {
	fsys := fstest.MapFS{
		"ssh/root_login.yaml": &fstest.MapFile{Data: []byte(validTestYAML)},
		"firewall/ufw.yaml": &fstest.MapFile{Data: []byte(`id: ufw_active
name: "UFW Active"
description: "Check UFW is active"
severity: high
category: firewall
steps:
  - function: service_running
    args:
      name: ufw
remediation: "Enable UFW"
`)},
	}

	loader := New(testKnownFunctions)
	tests, errs := loader.LoadFromFS(fsys)

	assert.Empty(t, errs)
	assert.Len(t, tests, 2)
}

func TestLoadFromFS_InvalidYAMLContinuesLoading(t *testing.T) {
	fsys := fstest.MapFS{
		"ssh/root_login.yaml": &fstest.MapFile{Data: []byte(validTestYAML)},
		"bad/broken.yaml":     &fstest.MapFile{Data: []byte("id: [broken yaml")},
	}

	loader := New(testKnownFunctions)
	tests, errs := loader.LoadFromFS(fsys)

	assert.Len(t, errs, 1)
	assert.Len(t, tests, 1)
	assert.Equal(t, "ssh_root_login", tests[0].ID)
}

func TestLoadFromFS_DuplicateIDs(t *testing.T) {
	fsys := fstest.MapFS{
		"a/first.yaml":  &fstest.MapFile{Data: []byte(validTestYAML)},
		"b/second.yaml": &fstest.MapFile{Data: []byte(validTestYAML)},
	}

	loader := New(testKnownFunctions)
	tests, errs := loader.LoadFromFS(fsys)

	assert.Len(t, tests, 1, "should keep only the first occurrence")
	require.Len(t, errs, 1, "should report one duplicate error")
	assert.Contains(t, errs[0].Error(), "duplicate check ID")
	assert.Contains(t, errs[0].Error(), "ssh_root_login")
}

func TestLoadFromFS_EmptyFS(t *testing.T) {
	fsys := fstest.MapFS{}

	loader := New(testKnownFunctions)
	tests, errs := loader.LoadFromFS(fsys)

	assert.Empty(t, errs)
	assert.Empty(t, tests)
}

func TestLoadFromFS_NonYAMLFilesSkipped(t *testing.T) {
	fsys := fstest.MapFS{
		"ssh/root_login.yaml": &fstest.MapFile{Data: []byte(validTestYAML)},
		"readme.txt":          &fstest.MapFile{Data: []byte("not yaml")},
		"config.json":         &fstest.MapFile{Data: []byte(`{"key": "value"}`)},
		"embed.go":            &fstest.MapFile{Data: []byte("package checks")},
	}

	loader := New(testKnownFunctions)
	tests, errs := loader.LoadFromFS(fsys)

	assert.Empty(t, errs)
	assert.Len(t, tests, 1)
}
