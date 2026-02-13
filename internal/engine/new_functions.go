package engine

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

// fileNotContains checks that a file does NOT contain content matching a regex pattern.
// Inverse of fileContains — used to verify bad configurations are absent.
func (r *FunctionRegistry) fileNotContains(args map[string]interface{}) (bool, string, error) {
	path, err := getStringArg(args, "path")
	if err != nil {
		return false, "", err
	}

	pattern, err := getStringArg(args, "pattern")
	if err != nil {
		return false, "", err
	}

	re, err := validateRegexPattern(pattern)
	if err != nil {
		return false, "", err
	}

	data, err := readFileLimited(path)
	if err != nil {
		return false, fmt.Sprintf("cannot read file: %s (%v)", path, err), nil
	}

	if re.Match(data) {
		return false, fmt.Sprintf("unwanted pattern found: %q in %s", pattern, path), nil
	}

	return true, fmt.Sprintf("pattern %q not found in %s (good)", pattern, path), nil
}

// fileOwner checks if a file has the expected owner (uid:gid).
// Accepts numeric "0:0" or named "root:root" format.
func (r *FunctionRegistry) fileOwner(args map[string]interface{}) (bool, string, error) {
	path, err := getStringArg(args, "path")
	if err != nil {
		return false, "", err
	}

	ownerStr, err := getStringArg(args, "owner")
	if err != nil {
		return false, "", err
	}

	cleaned, err := validatePath(path)
	if err != nil {
		return false, "", err
	}

	parts := strings.SplitN(ownerStr, ":", 2)
	if len(parts) != 2 {
		return false, "", fmt.Errorf("owner format must be \"uid:gid\" or \"user:group\", got %q", ownerStr)
	}

	expectedUID, errU := resolveUID(parts[0])
	expectedGID, errG := resolveGID(parts[1])
	if errU != nil {
		return false, "", fmt.Errorf("cannot resolve owner %q: %w", parts[0], errU)
	}
	if errG != nil {
		return false, "", fmt.Errorf("cannot resolve group %q: %w", parts[1], errG)
	}

	info, err := os.Stat(cleaned)
	if err != nil {
		return false, fmt.Sprintf("cannot stat file: %s", cleaned), nil
	}

	actualUID, actualGID := GetFileOwnerIDs(info)

	if actualUID == expectedUID && actualGID == expectedGID {
		return true, fmt.Sprintf("owner matches: %s is %d:%d", cleaned, actualUID, actualGID), nil
	}

	return false, fmt.Sprintf("owner mismatch: %s is %d:%d, expected %d:%d",
		cleaned, actualUID, actualGID, expectedUID, expectedGID), nil
}

// GetFileOwnerIDs extracts the UID and GID from a FileInfo.
// Exported for use in tests.
func GetFileOwnerIDs(info os.FileInfo) (uid, gid uint32) {
	stat := info.Sys().(*syscall.Stat_t)
	return stat.Uid, stat.Gid
}

// resolveUID converts a username or numeric string to a UID.
func resolveUID(s string) (uint32, error) {
	if uid, err := strconv.ParseUint(s, 10, 32); err == nil {
		return uint32(uid), nil
	}
	u, err := user.Lookup(s)
	if err != nil {
		return 0, fmt.Errorf("unknown user %q", s)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(uid), nil
}

// resolveGID converts a group name or numeric string to a GID.
func resolveGID(s string) (uint32, error) {
	if gid, err := strconv.ParseUint(s, 10, 32); err == nil {
		return uint32(gid), nil
	}
	g, err := user.LookupGroup(s)
	if err != nil {
		return 0, fmt.Errorf("unknown group %q", s)
	}
	gid, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(gid), nil
}

// sysctlValue reads a sysctl value from /proc/sys and compares it to expected.
// Validates the key against a strict pattern to prevent path traversal.
func (r *FunctionRegistry) sysctlValue(args map[string]interface{}) (bool, string, error) {
	key, err := getStringArg(args, "key")
	if err != nil {
		return false, "", err
	}

	expected, err := getStringArg(args, "expected")
	if err != nil {
		return false, "", err
	}

	if err := validateSysctlKey(key); err != nil {
		return false, "", err
	}

	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")

	data, err := readFileLimited(path)
	if err != nil {
		return false, fmt.Sprintf("cannot read sysctl %q (path: %s)", key, path), nil
	}

	actual := strings.TrimSpace(string(data))

	if actual == expected {
		return true, fmt.Sprintf("sysctl %s = %s", key, actual), nil
	}

	return false, fmt.Sprintf("sysctl %s = %s, expected %s", key, actual, expected), nil
}

// serviceEnabled checks if a systemd service is enabled (starts at boot).
// Validates service name before passing to systemctl.
func (r *FunctionRegistry) serviceEnabled(args map[string]interface{}) (bool, string, error) {
	name, err := getStringArg(args, "name")
	if err != nil {
		return false, "", err
	}

	if err := validateServiceName(name); err != nil {
		return false, "", err
	}

	expectEnabled := true
	if raw, ok := args["expect_enabled"]; ok {
		if b, ok := raw.(bool); ok {
			expectEnabled = b
		}
	}

	output, err := r.executor.Execute("systemctl", []string{"is-enabled", name})
	if err != nil {
		var exitErr *exec.ExitError
		if !isExitError(err, &exitErr) {
			return false, "", fmt.Errorf("failed to execute systemctl: %w", err)
		}
	}

	status := strings.TrimSpace(string(output))
	enabled := status == "enabled" || status == "static"

	if expectEnabled {
		if enabled {
			return true, fmt.Sprintf("service %q is enabled (%s)", name, status), nil
		}
		return false, fmt.Sprintf("service %q is not enabled (status: %s)", name, status), nil
	}

	if !enabled {
		return true, fmt.Sprintf("service %q is not enabled (as expected, status: %s)", name, status), nil
	}
	return false, fmt.Sprintf("service %q is enabled (should be disabled, status: %s)", name, status), nil
}

// commandOutputContains runs an allowlisted command and checks output against a regex.
func (r *FunctionRegistry) commandOutputContains(args map[string]interface{}) (bool, string, error) {
	cmd, err := getStringArg(args, "command")
	if err != nil {
		return false, "", err
	}

	pattern, err := getStringArg(args, "pattern")
	if err != nil {
		return false, "", err
	}

	re, err := validateRegexPattern(pattern)
	if err != nil {
		return false, "", err
	}

	var cmdArgs []string
	if rawArgs, ok := args["args"]; ok {
		if argList, ok := rawArgs.([]interface{}); ok {
			for _, a := range argList {
				if s, ok := a.(string); ok {
					cmdArgs = append(cmdArgs, s)
				}
			}
		}
	}

	if !r.executor.IsAllowed(cmd) {
		return false, "", fmt.Errorf("command %q not in allowlist", cmd)
	}

	output, err := r.executor.Execute(cmd, cmdArgs)
	outStr := string(output)

	// For commands like grep that use non-zero exit codes for "no match",
	// we check the regex before the error — but only if the error is a normal
	// exit-code error (ExitError). Timeouts, crashes, and permission errors
	// are always propagated regardless of any partial output match.
	if err != nil {
		var exitErr *exec.ExitError
		if !isExitError(err, &exitErr) {
			// Not a normal exit-code error — propagate as a real error.
			return false, "", fmt.Errorf("command %q failed: %w", cmd, err)
		}
	}

	if re.MatchString(outStr) {
		return true, fmt.Sprintf("command %q output matches pattern %q", cmd, pattern), nil
	}

	if err != nil {
		return false, fmt.Sprintf("command %q exited with error: %v", cmd, err), nil
	}

	return false, fmt.Sprintf("command %q output does not match pattern %q", cmd, pattern), nil
}

// kernelModuleLoaded checks if a kernel module is currently loaded (or not loaded).
func (r *FunctionRegistry) kernelModuleLoaded(args map[string]interface{}) (bool, string, error) {
	name, err := getStringArg(args, "name")
	if err != nil {
		return false, "", err
	}

	if err := validateKernelModuleName(name); err != nil {
		return false, "", err
	}

	expectLoaded := true
	if raw, ok := args["expect_loaded"]; ok {
		if b, ok := raw.(bool); ok {
			expectLoaded = b
		}
	}

	data, err := readProcFileLimited("/proc/modules")
	if err != nil {
		return false, fmt.Sprintf("cannot read /proc/modules: %v", err), nil
	}

	loaded := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == name {
			loaded = true
			break
		}
	}

	if expectLoaded {
		if loaded {
			return true, fmt.Sprintf("kernel module %q is loaded", name), nil
		}
		return false, fmt.Sprintf("kernel module %q is not loaded", name), nil
	}

	if !loaded {
		return true, fmt.Sprintf("kernel module %q is not loaded (as expected)", name), nil
	}
	return false, fmt.Sprintf("kernel module %q is loaded (should be disabled)", name), nil
}

// mountHasOption checks if a mount point has a specific mount option.
// Reads /proc/mounts via readFileLimited — no command execution needed.
func (r *FunctionRegistry) mountHasOption(args map[string]interface{}) (bool, string, error) {
	mountPoint, err := getStringArg(args, "mount_point")
	if err != nil {
		return false, "", err
	}

	option, err := getStringArg(args, "option")
	if err != nil {
		return false, "", err
	}

	data, err := readProcFileLimited("/proc/mounts")
	if err != nil {
		return false, fmt.Sprintf("cannot read /proc/mounts: %v", err), nil
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[1] == mountPoint {
			options := strings.Split(fields[3], ",")
			for _, opt := range options {
				if opt == option {
					return true, fmt.Sprintf("%s is mounted with %s", mountPoint, option), nil
				}
			}
			return false, fmt.Sprintf("%s is mounted but lacks option %q (has: %s)",
				mountPoint, option, fields[3]), nil
		}
	}

	return false, fmt.Sprintf("mount point %s not found in /proc/mounts", mountPoint), nil
}

// filePermissionsMax checks that file permissions do not exceed a maximum.
// Unlike filePermissions (exact match), this passes if actual perms are
// equal or stricter than the maximum. E.g., max 0750, actual 0700 → pass.
func (r *FunctionRegistry) filePermissionsMax(args map[string]interface{}) (bool, string, error) {
	path, err := getStringArg(args, "path")
	if err != nil {
		return false, "", err
	}

	maxStr, err := getStringArg(args, "max_permissions")
	if err != nil {
		return false, "", err
	}

	cleaned, err := validatePath(path)
	if err != nil {
		return false, "", err
	}

	maxPerm, err := strconv.ParseUint(maxStr, 8, 32)
	if err != nil {
		return false, "", fmt.Errorf("invalid permissions format %q: must be octal (e.g., \"0640\")", maxStr)
	}

	info, err := os.Stat(cleaned)
	if err != nil {
		return false, fmt.Sprintf("cannot stat file: %s", cleaned), nil
	}

	actual := uint32(info.Mode().Perm())
	max := uint32(maxPerm)

	if actual & ^max != 0 {
		return false, fmt.Sprintf("too permissive: %s has %04o, maximum allowed is %04o",
			cleaned, actual, max), nil
	}

	return true, fmt.Sprintf("permissions OK: %s has %04o (max allowed: %04o)", cleaned, actual, max), nil
}
