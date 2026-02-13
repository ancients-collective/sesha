package engine_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ancients-collective/sesha/internal/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===== file_not_contains =====

func TestFileNotContains_PatternAbsent(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "config")
	require.NoError(t, os.WriteFile(f, []byte("PermitRootLogin no\nPasswordAuthentication yes\n"), 0o644))

	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("file_not_contains", map[string]interface{}{
		"path":    f,
		"pattern": "PermitEmptyPasswords\\s+yes",
	})
	require.NoError(t, err)
	assert.True(t, pass)
	assert.Contains(t, detail, "not found")
}

func TestFileNotContains_PatternPresent(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "config")
	require.NoError(t, os.WriteFile(f, []byte("PermitEmptyPasswords yes\n"), 0o644))

	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("file_not_contains", map[string]interface{}{
		"path":    f,
		"pattern": "PermitEmptyPasswords\\s+yes",
	})
	require.NoError(t, err)
	assert.False(t, pass)
	assert.Contains(t, detail, "unwanted pattern found")
}

func TestFileNotContains_FileNotFound(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("file_not_contains", map[string]interface{}{
		"path":    "/nonexistent/path",
		"pattern": "test",
	})
	require.NoError(t, err)
	assert.False(t, pass)
	assert.Contains(t, detail, "cannot read file")
}

func TestFileNotContains_InvalidRegex(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "config")
	require.NoError(t, os.WriteFile(f, []byte("test"), 0o644))

	registry := engine.NewFunctionRegistry(nil)
	_, _, err := registry.Call("file_not_contains", map[string]interface{}{
		"path":    f,
		"pattern": "[invalid",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid regex pattern")
}

func TestFileNotContains_MissingArgs(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	_, _, err := registry.Call("file_not_contains", map[string]interface{}{
		"path": "/tmp",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pattern")
}

// ===== file_owner =====

func TestFileOwner_CorrectOwner(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "owned")
	require.NoError(t, os.WriteFile(f, []byte("test"), 0o644))

	info, err := os.Lstat(f)
	require.NoError(t, err)
	uid, gid := engine.GetFileOwnerIDs(info)

	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("file_owner", map[string]interface{}{
		"path":  f,
		"owner": fmt.Sprintf("%d:%d", uid, gid),
	})
	require.NoError(t, err)
	assert.True(t, pass, "detail: %s", detail)
}

func TestFileOwner_WrongOwner(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "owned")
	require.NoError(t, os.WriteFile(f, []byte("test"), 0o644))

	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("file_owner", map[string]interface{}{
		"path":  f,
		"owner": "99999:99999",
	})
	require.NoError(t, err)
	assert.False(t, pass)
	assert.Contains(t, detail, "owner mismatch")
}

func TestFileOwner_FileNotFound(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("file_owner", map[string]interface{}{
		"path":  "/nonexistent/file",
		"owner": "0:0",
	})
	require.NoError(t, err)
	assert.False(t, pass)
	assert.Contains(t, detail, "cannot stat")
}

func TestFileOwner_NamedOwner(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "owned")
	require.NoError(t, os.WriteFile(f, []byte("test"), 0o644))

	registry := engine.NewFunctionRegistry(nil)
	_, _, err := registry.Call("file_owner", map[string]interface{}{
		"path":  f,
		"owner": "root:root",
	})
	require.NoError(t, err)
}

func TestFileOwner_InvalidFormat(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "owned")
	require.NoError(t, os.WriteFile(f, []byte("test"), 0o644))

	registry := engine.NewFunctionRegistry(nil)
	_, _, err := registry.Call("file_owner", map[string]interface{}{
		"path":  f,
		"owner": "invalid",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "format")
}

func TestFileOwner_MissingArgs(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	_, _, err := registry.Call("file_owner", map[string]interface{}{
		"path": "/tmp",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "owner")
}

// ===== sysctl_value =====

func TestSysctlValue_MatchingValue(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("sysctl_value", map[string]interface{}{
		"key":      "kernel.ostype",
		"expected": "Linux",
	})
	require.NoError(t, err)
	assert.True(t, pass, "detail: %s", detail)
	assert.Contains(t, detail, "Linux")
}

func TestSysctlValue_NonMatchingValue(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("sysctl_value", map[string]interface{}{
		"key":      "kernel.ostype",
		"expected": "Windows",
	})
	require.NoError(t, err)
	assert.False(t, pass)
	assert.Contains(t, detail, "expected")
}

func TestSysctlValue_NonexistentKey(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("sysctl_value", map[string]interface{}{
		"key":      "totally.fake.key",
		"expected": "0",
	})
	require.NoError(t, err)
	assert.False(t, pass)
	assert.Contains(t, detail, "cannot read")
}

func TestSysctlValue_MissingArgs(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	_, _, err := registry.Call("sysctl_value", map[string]interface{}{
		"key": "kernel.ostype",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected")
}

// ===== service_enabled =====

func TestServiceEnabled_MissingArg(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	_, _, err := registry.Call("service_enabled", map[string]interface{}{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name")
}

func TestServiceEnabled_NonexistentService(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("service_enabled", map[string]interface{}{
		"name": "sesha-totally-fake-service",
	})
	require.NoError(t, err)
	assert.False(t, pass)
	assert.Contains(t, detail, "not enabled")
}

// ===== command_output_contains =====

func TestCommandOutputContains_MissingArgs(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	_, _, err := registry.Call("command_output_contains", map[string]interface{}{
		"command": "stat",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pattern")
}

func TestCommandOutputContains_DisallowedCommand(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	_, _, err := registry.Call("command_output_contains", map[string]interface{}{
		"command": "rm",
		"args":    []interface{}{"-rf", "/"},
		"pattern": ".*",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not in allowlist")
}

func TestCommandOutputContains_InvalidRegex(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	_, _, err := registry.Call("command_output_contains", map[string]interface{}{
		"command": "stat",
		"args":    []interface{}{"-c", "%a", "/tmp"},
		"pattern": "[invalid",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid regex pattern")
}

func TestCommandOutputContains_MatchFound(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	// timedatectl status produces output on most Linux systems.
	pass, detail, err := registry.Call("command_output_contains", map[string]interface{}{
		"command": "timedatectl",
		"args":    []interface{}{"status"},
		"pattern": "Time zone|timezone|Local time",
	})
	if err != nil {
		t.Skipf("timedatectl not available: %v", err)
	}
	if strings.Contains(detail, "exited with error") {
		t.Skipf("timedatectl not functional in this environment: %s", detail)
	}
	assert.True(t, pass)
	assert.Contains(t, detail, "matches pattern")
}

func TestCommandOutputContains_NoMatch(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("command_output_contains", map[string]interface{}{
		"command": "timedatectl",
		"args":    []interface{}{"status"},
		"pattern": "THIS_WILL_NEVER_MATCH_12345",
	})
	if err != nil {
		t.Skipf("timedatectl not available: %v", err)
	}
	if strings.Contains(detail, "exited with error") {
		t.Skipf("timedatectl not functional in this environment: %s", detail)
	}
	assert.False(t, pass)
	assert.Contains(t, detail, "does not match pattern")
}

// ===== kernel_module_loaded =====

func TestKernelModuleLoaded_MissingArg(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	_, _, err := registry.Call("kernel_module_loaded", map[string]interface{}{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name")
}

func TestKernelModuleLoaded_NonexistentModule(t *testing.T) {
	skipWithoutProcModules(t)
	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("kernel_module_loaded", map[string]interface{}{
		"name": "sesha_totally_fake_module",
	})
	require.NoError(t, err)
	assert.False(t, pass)
	assert.Contains(t, detail, "not loaded")
}

func TestKernelModuleLoaded_ProcModulesReadable(t *testing.T) {
	skipWithoutProcModules(t)
	registry := engine.NewFunctionRegistry(nil)
	pass, _, err := registry.Call("kernel_module_loaded", map[string]interface{}{
		"name": "dccp",
	})
	require.NoError(t, err)
	_ = pass
}

func TestKernelModuleLoaded_ExpectNotLoaded_FakeModule(t *testing.T) {
	skipWithoutProcModules(t)
	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("kernel_module_loaded", map[string]interface{}{
		"name":          "sesha_totally_fake_module",
		"expect_loaded": false,
	})
	require.NoError(t, err)
	assert.True(t, pass, "non-existent module should pass when expect_loaded=false")
	assert.Contains(t, detail, "not loaded")
	assert.Contains(t, detail, "as expected")
}

func TestKernelModuleLoaded_ExpectNotLoaded_DefaultIsTrue(t *testing.T) {
	skipWithoutProcModules(t)
	registry := engine.NewFunctionRegistry(nil)
	pass, _, err := registry.Call("kernel_module_loaded", map[string]interface{}{
		"name": "sesha_totally_fake_module",
	})
	require.NoError(t, err)
	assert.False(t, pass, "non-existent module should fail when expect_loaded defaults to true")
}

func skipWithoutProcModules(t *testing.T) {
	t.Helper()
	if _, err := os.ReadFile("/proc/modules"); err != nil {
		t.Skipf("skipping: /proc/modules not readable: %v", err)
	}
}

// ===== mount_has_option =====

func TestMountHasOption_RootFilesystem(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("mount_has_option", map[string]interface{}{
		"mount_point": "/",
		"option":      "rw",
	})
	require.NoError(t, err)
	_ = pass
	_ = detail
}

func TestMountHasOption_NonexistentMount(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("mount_has_option", map[string]interface{}{
		"mount_point": "/sesha_fake_mount",
		"option":      "noexec",
	})
	require.NoError(t, err)
	assert.False(t, pass)
	assert.Contains(t, detail, "not found")
}

func TestMountHasOption_MissingArgs(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	_, _, err := registry.Call("mount_has_option", map[string]interface{}{
		"mount_point": "/tmp",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "option")
}

// ===== file_permissions_max =====

func TestFilePermissionsMax_WithinLimit(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "strict")
	require.NoError(t, os.WriteFile(f, []byte("test"), 0o600))

	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("file_permissions_max", map[string]interface{}{
		"path":            f,
		"max_permissions": "0644",
	})
	require.NoError(t, err)
	assert.True(t, pass, "0600 should be within max 0644: %s", detail)
}

func TestFilePermissionsMax_ExactMatch(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "exact")
	require.NoError(t, os.WriteFile(f, []byte("test"), 0o644))
	require.NoError(t, os.Chmod(f, 0o644))

	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("file_permissions_max", map[string]interface{}{
		"path":            f,
		"max_permissions": "0644",
	})
	require.NoError(t, err)
	assert.True(t, pass, "0644 should equal max 0644: %s", detail)
}

func TestFilePermissionsMax_TooPermissive(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "loose")
	require.NoError(t, os.WriteFile(f, []byte("test"), 0o777))
	require.NoError(t, os.Chmod(f, 0o777))

	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("file_permissions_max", map[string]interface{}{
		"path":            f,
		"max_permissions": "0644",
	})
	require.NoError(t, err)
	assert.False(t, pass)
	assert.Contains(t, detail, "too permissive")
}

func TestFilePermissionsMax_GroupWrite(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "groupwrite")
	require.NoError(t, os.WriteFile(f, []byte("test"), 0o664))
	require.NoError(t, os.Chmod(f, 0o664))

	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("file_permissions_max", map[string]interface{}{
		"path":            f,
		"max_permissions": "0644",
	})
	require.NoError(t, err)
	assert.False(t, pass, "0664 exceeds max 0644 (group write bit): %s", detail)
}

func TestFilePermissionsMax_FileNotFound(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("file_permissions_max", map[string]interface{}{
		"path":            "/nonexistent/file",
		"max_permissions": "0644",
	})
	require.NoError(t, err)
	assert.False(t, pass)
	assert.Contains(t, detail, "cannot stat")
}

func TestFilePermissionsMax_InvalidFormat(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test")
	require.NoError(t, os.WriteFile(f, []byte("test"), 0o644))

	registry := engine.NewFunctionRegistry(nil)
	_, _, err := registry.Call("file_permissions_max", map[string]interface{}{
		"path":            f,
		"max_permissions": "not-octal",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
}

func TestFilePermissionsMax_MissingArgs(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	_, _, err := registry.Call("file_permissions_max", map[string]interface{}{
		"path": "/tmp",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_permissions")
}

// ===== Verify all new functions are registered =====

func TestNewFunctionsRegistered(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	names := registry.FunctionNames()

	expected := []string{
		"file_not_contains",
		"file_owner",
		"sysctl_value",
		"service_enabled",
		"command_output_contains",
		"kernel_module_loaded",
		"mount_has_option",
		"file_permissions_max",
	}

	for _, fn := range expected {
		assert.Contains(t, names, fn, "function %q should be registered", fn)
	}
}
