package engine_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ancients-collective/sesha/internal/engine"
	"github.com/ancients-collective/sesha/internal/loader"
	"github.com/ancients-collective/sesha/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration tests wire all components together with ZERO mocks:
//   FunctionRegistry -> Loader (with real function names) -> Executor -> TestResult

func TestIntegration_FullPassingPipeline(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)

	functionNames := registry.FunctionNames()
	require.NotEmpty(t, functionNames, "registry should have functions")
	require.Contains(t, functionNames, "file_exists")
	require.Contains(t, functionNames, "file_permissions")
	require.Contains(t, functionNames, "file_contains")

	ldr := loader.New(functionNames)

	dir := t.TempDir()
	testFile := filepath.Join(dir, "integration_target")
	require.NoError(t, os.WriteFile(testFile, []byte("sesha integration test content"), 0o644))

	yamlContent := `id: integration_file_check
name: "Integration File Check"
description: "Full pipeline integration test"
severity: medium
category: file-permissions
supported_os:
  - linux
  - darwin
steps:
  - function: file_exists
    args:
      path: "` + testFile + `"
  - function: file_permissions
    args:
      path: "` + testFile + `"
      permissions: "0644"
  - function: file_contains
    args:
      path: "` + testFile + `"
      pattern: "sesha integration test"
remediation: "Create the test file with correct permissions"
`
	yamlPath := filepath.Join(dir, "test.yaml")
	require.NoError(t, os.WriteFile(yamlPath, []byte(yamlContent), 0o644))

	testDef, err := ldr.LoadTest(yamlPath)
	require.NoError(t, err)
	assert.Equal(t, "integration_file_check", testDef.ID)
	assert.Len(t, testDef.Steps, 3)

	ctx := types.SystemContext{
		OS:            types.OSInfo{Name: "linux", Version: "6.1.0", Arch: "amd64"},
		Distro:        types.DistroInfo{ID: "ubuntu", Version: "22.04", Family: "debian"},
		Environment:   types.EnvInfo{Type: "bare-metal"},
		IntentProfile: "server",
	}

	exec := engine.NewExecutor(registry, ctx)

	result := exec.RunTest(testDef)

	assert.Equal(t, types.StatusPass, result.Status, "test should pass: %s", result.Message)
	assert.Equal(t, "integration_file_check", result.ID)
	assert.Equal(t, "Integration File Check", result.Name)
	assert.Equal(t, "medium", result.Severity)
	assert.Equal(t, "file-permissions", result.Category)
	assert.True(t, result.Duration > 0, "duration should be recorded")
}

func TestIntegration_AutoSkipOnWrongContext(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	ldr := loader.New(registry.FunctionNames())

	dir := t.TempDir()
	yamlContent := `id: linux_only
name: "Linux Only Test"
description: "Should skip on non-linux"
severity: high
category: system
supported_os:
  - linux
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "fix it"
`
	yamlPath := filepath.Join(dir, "test.yaml")
	require.NoError(t, os.WriteFile(yamlPath, []byte(yamlContent), 0o644))

	testDef, err := ldr.LoadTest(yamlPath)
	require.NoError(t, err)

	ctx := types.SystemContext{
		OS: types.OSInfo{Name: "windows", Version: "10", Arch: "amd64"},
	}
	exec := engine.NewExecutor(registry, ctx)
	result := exec.RunTest(testDef)

	assert.Equal(t, types.StatusSkip, result.Status)
	assert.NotEmpty(t, result.Message)
	assert.Contains(t, result.Message, "windows")
}

func TestIntegration_InvalidYAMLRejectedAtLoadTime(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	ldr := loader.New(registry.FunctionNames())

	dir := t.TempDir()
	yamlContent := `id: malicious_test
name: "Malicious Test"
description: "References nonexistent function"
severity: high
category: attack
steps:
  - function: execute_shell_command
    args:
      cmd: "rm -rf /"
remediation: "fix it"
`
	yamlPath := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(yamlPath, []byte(yamlContent), 0o644))

	_, err := ldr.LoadTest(yamlPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown function")
	assert.Contains(t, err.Error(), "execute_shell_command")
}

func TestIntegration_ConditionalStepSkipping(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	ldr := loader.New(registry.FunctionNames())

	dir := t.TempDir()
	testFile := filepath.Join(dir, "exists")
	require.NoError(t, os.WriteFile(testFile, []byte("content"), 0o644))

	yamlContent := `id: conditional_steps
name: "Conditional Steps Test"
description: "Tests conditional step execution"
severity: medium
category: test
steps:
  - function: file_exists
    args:
      path: "` + testFile + `"
    when:
      os: linux
  - function: file_exists
    args:
      path: "/darwin/only/path"
    when:
      os: darwin
remediation: "fix it"
`
	yamlPath := filepath.Join(dir, "test.yaml")
	require.NoError(t, os.WriteFile(yamlPath, []byte(yamlContent), 0o644))

	testDef, err := ldr.LoadTest(yamlPath)
	require.NoError(t, err)

	ctx := types.SystemContext{
		OS: types.OSInfo{Name: "linux", Version: "6.1.0", Arch: "amd64"},
	}
	exec := engine.NewExecutor(registry, ctx)
	result := exec.RunTest(testDef)

	assert.Equal(t, types.StatusPass, result.Status,
		"test should pass: matching step succeeds, non-matching step skipped")
}

func TestIntegration_DirectoryLoadAndExecute(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	ldr := loader.New(registry.FunctionNames())

	dir := t.TempDir()
	testFile := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(testFile, []byte("test content"), 0o644))

	testsDir := filepath.Join(dir, "tests")
	require.NoError(t, os.MkdirAll(testsDir, 0o755))

	yaml1 := `id: check_file
name: "Check File Exists"
description: "Verifies file exists"
severity: low
category: test
steps:
  - function: file_exists
    args:
      path: "` + testFile + `"
remediation: "fix it"
`
	yaml2 := `id: check_perms
name: "Check File Permissions"
description: "Verifies file permissions"
severity: medium
category: test
steps:
  - function: file_permissions
    args:
      path: "` + testFile + `"
      permissions: "0644"
remediation: "fix it"
`
	require.NoError(t, os.WriteFile(filepath.Join(testsDir, "check1.yaml"), []byte(yaml1), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(testsDir, "check2.yaml"), []byte(yaml2), 0o644))

	tests, errs := ldr.LoadDirectory(testsDir)
	assert.Empty(t, errs)
	require.Len(t, tests, 2)

	ctx := types.SystemContext{
		OS: types.OSInfo{Name: "linux", Version: "6.1.0", Arch: "amd64"},
	}
	exec := engine.NewExecutor(registry, ctx)

	for _, testDef := range tests {
		result := exec.RunTest(testDef)
		assert.Equal(t, types.StatusPass, result.Status,
			"test %q should pass: %s", testDef.ID, result.Message)
		assert.True(t, result.Duration > 0)
	}
}

func TestIntegration_LoaderUsesRegistryFunctionNames(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	functionNames := registry.FunctionNames()

	for _, fn := range functionNames {
		t.Run(fn, func(t *testing.T) {
			dir := t.TempDir()
			yaml := `id: test_` + fn + `
name: "Test ` + fn + `"
description: "Tests that ` + fn + ` is accepted by loader"
severity: info
category: test
steps:
  - function: ` + fn + `
    args:
      path: /tmp
remediation: "fix it"
`
			yamlPath := filepath.Join(dir, "test.yaml")
			require.NoError(t, os.WriteFile(yamlPath, []byte(yaml), 0o644))

			ldr := loader.New(functionNames)
			_, err := ldr.LoadTest(yamlPath)
			require.NoError(t, err, "function %q should be accepted by loader", fn)
		})
	}
}

func TestIntegration_DistroFilterPipeline(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	ldr := loader.New(registry.FunctionNames())

	dir := t.TempDir()
	testFile := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(testFile, []byte("content"), 0o644))

	yaml := `id: ubuntu_only
name: "Ubuntu Only Test"
description: "Only runs on Ubuntu"
severity: medium
category: test
required_distro:
  - ubuntu
  - debian
steps:
  - function: file_exists
    args:
      path: "` + testFile + `"
remediation: "fix it"
`
	yamlPath := filepath.Join(dir, "test.yaml")
	require.NoError(t, os.WriteFile(yamlPath, []byte(yaml), 0o644))

	testDef, err := ldr.LoadTest(yamlPath)
	require.NoError(t, err)

	ubuntuCtx := types.SystemContext{
		OS:     types.OSInfo{Name: "linux"},
		Distro: types.DistroInfo{ID: "ubuntu"},
	}
	result := engine.NewExecutor(registry, ubuntuCtx).RunTest(testDef)
	assert.Equal(t, types.StatusPass, result.Status)

	rhelCtx := types.SystemContext{
		OS:     types.OSInfo{Name: "linux"},
		Distro: types.DistroInfo{ID: "rhel"},
	}
	result = engine.NewExecutor(registry, rhelCtx).RunTest(testDef)
	assert.Equal(t, types.StatusSkip, result.Status)
	assert.Contains(t, result.Message, "rhel")
}

func TestIntegration_ProfilePipeline(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	ldr := loader.New(registry.FunctionNames())

	dir := t.TempDir()
	testFile := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(testFile, []byte("content"), 0o644))

	yaml := `id: server_check
name: "Server Check"
description: "Only runs on servers"
severity: high
category: test
profiles:
  - server
steps:
  - function: file_exists
    args:
      path: "` + testFile + `"
remediation: "fix it"
`
	yamlPath := filepath.Join(dir, "test.yaml")
	require.NoError(t, os.WriteFile(yamlPath, []byte(yaml), 0o644))

	testDef, err := ldr.LoadTest(yamlPath)
	require.NoError(t, err)

	serverCtx := types.SystemContext{
		OS:            types.OSInfo{Name: "linux"},
		IntentProfile: "server",
	}
	result := engine.NewExecutor(registry, serverCtx).RunTest(testDef)
	assert.Equal(t, types.StatusPass, result.Status)

	workstationCtx := types.SystemContext{
		OS:            types.OSInfo{Name: "linux"},
		IntentProfile: "workstation",
	}
	result = engine.NewExecutor(registry, workstationCtx).RunTest(testDef)
	assert.Equal(t, types.StatusSkip, result.Status)
	assert.Contains(t, result.Message, "workstation")
}
