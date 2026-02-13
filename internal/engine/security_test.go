package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- validatePath ---

func TestValidatePath_RejectsRelativePaths(t *testing.T) {
	cases := []string{
		"../etc/passwd",
		"../../root/.ssh/id_rsa",
		"relative/path",
		"./local/file",
		"noprefix.txt",
	}
	for _, tc := range cases {
		_, err := validatePath(tc)
		assert.Error(t, err, "should reject: %s", tc)
		assert.Contains(t, err.Error(), "absolute", tc)
	}
}

func TestValidatePath_CleansAbsoluteTraversal(t *testing.T) {
	cases := []string{
		"/etc/../shadow",
		"/proc/sys/../../etc/shadow",
		"/tmp/safe/../../etc/passwd",
	}
	for _, tc := range cases {
		result, err := validatePath(tc)
		assert.NoError(t, err, "filepath.Clean resolves %q to a valid path", tc)
		assert.NotContains(t, result, "..")
	}
}

func TestValidatePath_AcceptsAbsolutePaths(t *testing.T) {
	cases := []string{
		"/etc/passwd",
		"/proc/sys/net/ipv4/ip_forward",
		"/var/log/syslog",
	}
	for _, tc := range cases {
		result, err := validatePath(tc)
		assert.NoError(t, err, "should accept absolute path: %s", tc)
		assert.Equal(t, tc, result)
	}
}

func TestValidatePath_RejectsEmpty(t *testing.T) {
	_, err := validatePath("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

// --- validateSysctlKey ---

func TestValidateSysctlKey_RejectsTraversal(t *testing.T) {
	cases := []string{
		"..hidden",
		"a..b",
		"net.ipv4..forward",
	}
	for _, tc := range cases {
		err := validateSysctlKey(tc)
		assert.Error(t, err, "should reject sysctl key with '..': %s", tc)
	}
}

func TestValidateSysctlKey_RejectsInvalidChars(t *testing.T) {
	cases := []string{
		"../../etc/shadow",
		"net/ipv4/ip_forward",
		"net ipv4",
		"key;rm",
	}
	for _, tc := range cases {
		err := validateSysctlKey(tc)
		assert.Error(t, err, "should reject sysctl key: %s", tc)
	}
}

func TestValidateSysctlKey_AcceptsValid(t *testing.T) {
	cases := []string{
		"net.ipv4.ip_forward",
		"kernel.randomize_va_space",
		"fs.suid_dumpable",
		"net.ipv6.conf.all.disable_ipv6",
	}
	for _, tc := range cases {
		err := validateSysctlKey(tc)
		assert.NoError(t, err, "should accept valid sysctl key: %s", tc)
	}
}

func TestValidateSysctlKey_RejectsEmpty(t *testing.T) {
	err := validateSysctlKey("")
	assert.Error(t, err)
}

// --- validateServiceName ---

func TestValidateServiceName_RejectsInjection(t *testing.T) {
	cases := []struct {
		name   string
		reason string
	}{
		{"--force", "starts with hyphen (flag injection)"},
		{"-v", "short flag injection"},
		{"; rm -rf /", "shell metacharacters"},
		{"$(whoami)", "command substitution"},
		{"`id`", "backtick execution"},
		{"sshd --now", "space in name"},
		{"../../../etc", "path traversal characters"},
		{"foo\nbar", "newline injection"},
	}
	for _, tc := range cases {
		err := validateServiceName(tc.name)
		assert.Error(t, err, "should reject %q (%s)", tc.name, tc.reason)
	}
}

func TestValidateServiceName_RejectsTooLong(t *testing.T) {
	long := strings.Repeat("a", MaxServiceNameLength+1)
	err := validateServiceName(long)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too long")
}

func TestValidateServiceName_AcceptsValid(t *testing.T) {
	cases := []string{
		"sshd",
		"ufw.service",
		"fail2ban",
		"systemd-journald",
		"nginx@instance1",
	}
	for _, tc := range cases {
		err := validateServiceName(tc)
		assert.NoError(t, err, "should accept service name: %s", tc)
	}
}

func TestValidateServiceName_RejectsEmpty(t *testing.T) {
	err := validateServiceName("")
	assert.Error(t, err)
}

// --- validateKernelModuleName ---

func TestValidateKernelModuleName_RejectsInjection(t *testing.T) {
	cases := []string{
		"../etc/passwd",
		"; rm -rf /",
		"$(whoami)",
		"module name",
		"foo\nbar",
	}
	for _, tc := range cases {
		err := validateKernelModuleName(tc)
		assert.Error(t, err, "should reject kernel module name: %q", tc)
	}
}

func TestValidateKernelModuleName_AcceptsValid(t *testing.T) {
	cases := []string{
		"cramfs",
		"usb_storage",
		"nf_conntrack",
		"ip6table_filter",
		"nf-conntrack",
	}
	for _, tc := range cases {
		err := validateKernelModuleName(tc)
		assert.NoError(t, err, "should accept kernel module name: %s", tc)
	}
}

// --- validateRegexPattern ---

func TestValidateRegexPattern_RejectsTooLong(t *testing.T) {
	long := strings.Repeat("a", MaxRegexLength+1)
	_, err := validateRegexPattern(long)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too long")
}

func TestValidateRegexPattern_RejectsEmpty(t *testing.T) {
	_, err := validateRegexPattern("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestValidateRegexPattern_RejectsInvalid(t *testing.T) {
	_, err := validateRegexPattern("[invalid")
	assert.Error(t, err)
}

func TestValidateRegexPattern_AcceptsValid(t *testing.T) {
	re, err := validateRegexPattern(`^PermitRootLogin\s+no`)
	assert.NoError(t, err)
	assert.NotNil(t, re)
}

// --- readFileLimited ---

func TestReadFileLimited_RejectsRelativePaths(t *testing.T) {
	cases := []string{
		"../etc/passwd",
		"some/file.txt",
	}
	for _, tc := range cases {
		_, err := readFileLimited(tc)
		assert.Error(t, err, "should reject: %s", tc)
	}
}

func TestReadFileLimited_ReadsNormalFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	err := os.WriteFile(path, []byte("hello world"), 0644)
	require.NoError(t, err)

	data, err := readFileLimited(path)
	assert.NoError(t, err)
	assert.Equal(t, "hello world", string(data))
}

func TestReadFileLimited_FollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.txt")
	link := filepath.Join(dir, "link.txt")
	err := os.WriteFile(real, []byte("secret"), 0644)
	require.NoError(t, err)
	err = os.Symlink(real, link)
	require.NoError(t, err)

	data, err := readFileLimited(link)
	assert.NoError(t, err)
	assert.Equal(t, "secret", string(data))
}

func TestReadFileLimited_RejectsDeviceFiles(t *testing.T) {
	_, err := readFileLimited("/dev/null")
	if err != nil {
		assert.Contains(t, err.Error(), "regular file")
	}
}

// --- VerifyChecksDirectory ---

func TestVerifyChecksDirectory_CleanDir(t *testing.T) {
	dir := t.TempDir()
	err := os.Chmod(dir, 0755)
	require.NoError(t, err)

	yaml := filepath.Join(dir, "test.yaml")
	err = os.WriteFile(yaml, []byte("id: test"), 0644)
	require.NoError(t, err)

	warnings := VerifyChecksDirectory(dir)
	assert.Empty(t, warnings)
}

func TestVerifyChecksDirectory_NonExistent(t *testing.T) {
	warnings := VerifyChecksDirectory("/nonexistent/path/12345")
	assert.NotEmpty(t, warnings)
	assert.Contains(t, warnings[0], "cannot stat")
}

func TestVerifyChecksDirectory_WorldWritableDir(t *testing.T) {
	dir := t.TempDir()
	err := os.Chmod(dir, 0777)
	require.NoError(t, err)

	warnings := VerifyChecksDirectory(dir)
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "world-writable") {
			found = true
			break
		}
	}
	assert.True(t, found, "should warn about world-writable directory, got: %v", warnings)
}

func TestVerifyChecksDirectory_GroupWritableDir(t *testing.T) {
	dir := t.TempDir()
	err := os.Chmod(dir, 0775)
	require.NoError(t, err)

	warnings := VerifyChecksDirectory(dir)
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "group-writable") {
			found = true
			break
		}
	}
	assert.True(t, found, "should warn about group-writable directory, got: %v", warnings)
}

func TestVerifyChecksDirectory_WorldWritableYAML(t *testing.T) {
	dir := t.TempDir()
	err := os.Chmod(dir, 0755)
	require.NoError(t, err)

	yamlPath := filepath.Join(dir, "test.yaml")
	err = os.WriteFile(yamlPath, []byte("id: test"), 0644)
	require.NoError(t, err)
	err = os.Chmod(yamlPath, 0666)
	require.NoError(t, err)

	warnings := VerifyChecksDirectory(dir)
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "world-writable") {
			found = true
			break
		}
	}
	assert.True(t, found, "should warn about world-writable YAML file, got: %v", warnings)
}

func TestVerifyChecksDirectory_SymlinkOutside(t *testing.T) {
	dir := t.TempDir()
	err := os.Chmod(dir, 0755)
	require.NoError(t, err)
	outside := t.TempDir()
	target := filepath.Join(outside, "evil.yaml")
	err = os.WriteFile(target, []byte("id: evil"), 0644)
	require.NoError(t, err)

	link := filepath.Join(dir, "link.yaml")
	err = os.Symlink(target, link)
	require.NoError(t, err)

	warnings := VerifyChecksDirectory(dir)
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "symlink") {
			found = true
			break
		}
	}
	assert.True(t, found, "should warn about symlink outside directory, got: %v", warnings)
}

// --- Integration: function registry rejects bad inputs ---

func TestIntegration_FileExistsRejectsRelativePath(t *testing.T) {
	r := NewFunctionRegistry(nil)
	_, _, err := r.Call("file_exists", map[string]interface{}{
		"path": "../../../etc/shadow",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "absolute")
}

func TestIntegration_FileContainsRejectsRelativePath(t *testing.T) {
	r := NewFunctionRegistry(nil)
	pass, msg, err := r.Call("file_contains", map[string]interface{}{
		"path":    "../../../etc/shadow",
		"pattern": "root",
	})
	assert.False(t, pass, "should not pass with relative path")
	assert.Contains(t, msg, "cannot read")
	_ = err
}

func TestIntegration_FilePermissionsRejectsRelativePath(t *testing.T) {
	r := NewFunctionRegistry(nil)
	_, _, err := r.Call("file_permissions", map[string]interface{}{
		"path":        "../../../etc/shadow",
		"permissions": "0600",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "absolute")
}

func TestIntegration_SysctlValueRejectsTraversal(t *testing.T) {
	r := NewFunctionRegistry(nil)
	_, _, err := r.Call("sysctl_value", map[string]interface{}{
		"key":      "../../etc/shadow",
		"expected": "0",
	})
	assert.Error(t, err)
}

func TestIntegration_ServiceRunningRejectsInjection(t *testing.T) {
	r := NewFunctionRegistry(nil)
	_, _, err := r.Call("service_running", map[string]interface{}{
		"name": "; rm -rf /",
	})
	assert.Error(t, err)
}

// --- Constants are exported correctly ---

func TestSecurityConstants(t *testing.T) {
	assert.Greater(t, MaxFileReadBytes, int64(0))
	assert.Greater(t, MaxRegexLength, 0)
	assert.Greater(t, MaxServiceNameLength, 0)
}
