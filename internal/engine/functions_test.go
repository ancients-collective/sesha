package engine_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ancients-collective/sesha/internal/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileExists_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testfile")
	require.NoError(t, os.WriteFile(path, []byte("content"), 0o644))

	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("file_exists", map[string]interface{}{"path": path})

	require.NoError(t, err)
	assert.True(t, pass)
	assert.Contains(t, detail, "exists")
}

func TestFileExists_NonexistentFile(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("file_exists", map[string]interface{}{"path": "/nonexistent/file"})

	require.NoError(t, err)
	assert.False(t, pass)
	assert.Contains(t, detail, "does not exist")
}

func TestFileExists_MissingPathArg(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	_, _, err := registry.Call("file_exists", map[string]interface{}{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "path")
}

func TestFilePermissions_Correct(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testfile")
	require.NoError(t, os.WriteFile(path, []byte("content"), 0o640))
	require.NoError(t, os.Chmod(path, 0o640))

	registry := engine.NewFunctionRegistry(nil)
	pass, _, err := registry.Call("file_permissions", map[string]interface{}{
		"path":        path,
		"permissions": "0640",
	})

	require.NoError(t, err)
	assert.True(t, pass)
}

func TestFilePermissions_Wrong(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testfile")
	require.NoError(t, os.WriteFile(path, []byte("content"), 0o644))
	require.NoError(t, os.Chmod(path, 0o644))

	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("file_permissions", map[string]interface{}{
		"path":        path,
		"permissions": "0600",
	})

	require.NoError(t, err)
	assert.False(t, pass)
	assert.Contains(t, detail, "expected")
}

func TestFilePermissions_InvalidFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testfile")
	require.NoError(t, os.WriteFile(path, []byte("content"), 0o644))

	registry := engine.NewFunctionRegistry(nil)
	_, _, err := registry.Call("file_permissions", map[string]interface{}{
		"path":        path,
		"permissions": "invalid",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "permissions")
}

func TestFilePermissions_MissingArgs(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)

	_, _, err := registry.Call("file_permissions", map[string]interface{}{
		"permissions": "0640",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path")

	_, _, err = registry.Call("file_permissions", map[string]interface{}{
		"path": "/tmp/test",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permissions")
}

func TestFileContains_PatternFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	require.NoError(t, os.WriteFile(path, []byte("PermitRootLogin no\nPort 22\n"), 0o644))

	registry := engine.NewFunctionRegistry(nil)
	pass, _, err := registry.Call("file_contains", map[string]interface{}{
		"path":    path,
		"pattern": "PermitRootLogin no",
	})

	require.NoError(t, err)
	assert.True(t, pass)
}

func TestFileContains_PatternNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	require.NoError(t, os.WriteFile(path, []byte("PermitRootLogin yes\n"), 0o644))

	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("file_contains", map[string]interface{}{
		"path":    path,
		"pattern": "PermitRootLogin no",
	})

	require.NoError(t, err)
	assert.False(t, pass)
	assert.Contains(t, detail, "pattern not found")
}

func TestFileContains_RegexPattern(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	require.NoError(t, os.WriteFile(path, []byte("PermitRootLogin no\n"), 0o644))

	registry := engine.NewFunctionRegistry(nil)
	pass, _, err := registry.Call("file_contains", map[string]interface{}{
		"path":    path,
		"pattern": `^PermitRootLogin\s+no`,
	})

	require.NoError(t, err)
	assert.True(t, pass)
}

func TestFileContains_InvalidRegex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	require.NoError(t, os.WriteFile(path, []byte("content\n"), 0o644))

	registry := engine.NewFunctionRegistry(nil)
	_, _, err := registry.Call("file_contains", map[string]interface{}{
		"path":    path,
		"pattern": "[invalid regex",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "pattern")
}

func TestFileContains_FileNotFound(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	pass, _, err := registry.Call("file_contains", map[string]interface{}{
		"path":    "/nonexistent/file",
		"pattern": "test",
	})

	require.NoError(t, err)
	assert.False(t, pass)
}

func TestPortListening_InvalidPort(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	_, _, err := registry.Call("port_listening", map[string]interface{}{
		"port": 99999,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "port")
}

func TestPortListening_MissingArg(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	_, _, err := registry.Call("port_listening", map[string]interface{}{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "port")
}

func TestPortListening_NotListening(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	pass, _, err := registry.Call("port_listening", map[string]interface{}{
		"port": 39999,
	})

	require.NoError(t, err)
	assert.False(t, pass)
}

func TestServiceRunning_MissingArg(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	_, _, err := registry.Call("service_running", map[string]interface{}{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "name")
}

func TestFunctionNames(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	names := registry.FunctionNames()

	assert.Contains(t, names, "file_exists")
	assert.Contains(t, names, "file_permissions")
	assert.Contains(t, names, "file_contains")
	assert.Contains(t, names, "file_not_contains")
	assert.Contains(t, names, "file_owner")
	assert.Contains(t, names, "file_permissions_max")
	assert.Contains(t, names, "port_listening")
	assert.Contains(t, names, "service_running")
	assert.Contains(t, names, "service_enabled")
	assert.Contains(t, names, "sysctl_value")
	assert.Contains(t, names, "command_output_contains")
	assert.Contains(t, names, "kernel_module_loaded")
	assert.Contains(t, names, "mount_has_option")
	assert.Len(t, names, 13)
}

func TestFunctionNames_Sorted(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	names := registry.FunctionNames()

	for i := 1; i < len(names); i++ {
		assert.True(t, names[i-1] < names[i], "names should be sorted: %s >= %s", names[i-1], names[i])
	}
}

func TestCall_UnknownFunction(t *testing.T) {
	registry := engine.NewFunctionRegistry(nil)
	_, _, err := registry.Call("nonexistent_function", map[string]interface{}{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown function")
}

func TestFileExists_Symlink(t *testing.T) {
	dir := t.TempDir()
	linkPath := filepath.Join(dir, "symlink")
	require.NoError(t, os.Symlink("/nonexistent/target", linkPath))

	registry := engine.NewFunctionRegistry(nil)
	pass, _, err := registry.Call("file_exists", map[string]interface{}{"path": linkPath})

	require.NoError(t, err)
	assert.True(t, pass)
}

func TestFilePermissions_Symlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("content"), 0o644))
	os.Chmod(target, 0o640)

	linkPath := filepath.Join(dir, "symlink")
	require.NoError(t, os.Symlink(target, linkPath))

	registry := engine.NewFunctionRegistry(nil)
	pass, detail, err := registry.Call("file_permissions", map[string]interface{}{
		"path":        linkPath,
		"permissions": "0640",
	})

	require.NoError(t, err)
	assert.True(t, pass, "should match target permissions: %s", detail)
}
