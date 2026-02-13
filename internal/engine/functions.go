// Package engine contains the security check execution engine including
// built-in functions, allowlisted command execution, and check orchestration.
package engine

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// BuiltinFunction is a function that performs a security check.
// Returns: pass (true/false), detail message, and error (for unexpected failures).
type BuiltinFunction func(args map[string]interface{}) (pass bool, detail string, err error)

// FunctionRegistry holds the set of built-in functions available to check steps.
type FunctionRegistry struct {
	functions map[string]BuiltinFunction
	executor  *AllowlistExecutor
}

// NewFunctionRegistry creates a registry with all built-in functions registered.
// If executor is nil, functions requiring command execution (service_running) will
// attempt to create a default executor.
func NewFunctionRegistry(executor *AllowlistExecutor) *FunctionRegistry {
	if executor == nil {
		executor = NewAllowlistExecutor()
	}

	r := &FunctionRegistry{
		functions: make(map[string]BuiltinFunction),
		executor:  executor,
	}

	r.functions["file_exists"] = r.fileExists
	r.functions["file_permissions"] = r.filePermissions
	r.functions["file_contains"] = r.fileContains
	r.functions["file_not_contains"] = r.fileNotContains
	r.functions["file_owner"] = r.fileOwner
	r.functions["file_permissions_max"] = r.filePermissionsMax
	r.functions["port_listening"] = r.portListening
	r.functions["service_running"] = r.serviceRunning
	r.functions["service_enabled"] = r.serviceEnabled
	r.functions["sysctl_value"] = r.sysctlValue
	r.functions["command_output_contains"] = r.commandOutputContains
	r.functions["kernel_module_loaded"] = r.kernelModuleLoaded
	r.functions["mount_has_option"] = r.mountHasOption

	return r
}

// FunctionNames returns a sorted list of all registered function names.
func (r *FunctionRegistry) FunctionNames() []string {
	names := make([]string, 0, len(r.functions))
	for name := range r.functions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Call invokes a registered function by name with the given arguments.
func (r *FunctionRegistry) Call(name string, args map[string]interface{}) (bool, string, error) {
	fn, ok := r.functions[name]
	if !ok {
		return false, "", fmt.Errorf("unknown function %q", name)
	}
	return fn(args)
}

// fileExists checks if a file exists at the given path.
// Uses validatePath + os.Lstat to prevent path traversal.
// Note: uses Lstat (does not follow symlinks) — a dangling symlink reports as "exists".
// This differs from filePermissions which uses Stat (follows symlinks). This is intentional:
// existence should detect the link itself, while permissions should check the target.
func (r *FunctionRegistry) fileExists(args map[string]interface{}) (bool, string, error) {
	path, err := getStringArg(args, "path")
	if err != nil {
		return false, "", err
	}

	cleaned, err := validatePath(path)
	if err != nil {
		return false, "", err
	}

	// Default: expect the file to exist
	expectExists := true
	if raw, ok := args["expect_exists"]; ok {
		if b, ok := raw.(bool); ok {
			expectExists = b
		}
	}

	_, err = os.Lstat(cleaned)
	exists := !os.IsNotExist(err)
	if err != nil && !os.IsNotExist(err) {
		return false, "", fmt.Errorf("error checking file %q: %w", cleaned, err)
	}

	if expectExists {
		if exists {
			return true, fmt.Sprintf("file exists: %s", cleaned), nil
		}
		return false, fmt.Sprintf("file does not exist: %s", cleaned), nil
	}

	// expect_exists == false: pass when file does NOT exist
	if !exists {
		return true, fmt.Sprintf("file does not exist (as expected): %s", cleaned), nil
	}
	return false, fmt.Sprintf("file exists (should not): %s", cleaned), nil
}

// filePermissions checks if a file has the expected permissions.
// Uses validatePath + os.Stat (follows symlinks) to check target file permissions.
func (r *FunctionRegistry) filePermissions(args map[string]interface{}) (bool, string, error) {
	path, err := getStringArg(args, "path")
	if err != nil {
		return false, "", err
	}

	expectedStr, err := getStringArg(args, "permissions")
	if err != nil {
		return false, "", err
	}

	cleaned, err := validatePath(path)
	if err != nil {
		return false, "", err
	}

	expected, err := strconv.ParseUint(expectedStr, 8, 32)
	if err != nil {
		return false, "", fmt.Errorf("invalid permissions format %q: must be octal (e.g., \"0640\")", expectedStr)
	}

	info, err := os.Stat(cleaned)
	if err != nil {
		return false, fmt.Sprintf("cannot stat file: %s", cleaned), nil
	}

	actual := info.Mode().Perm()
	expectedPerm := os.FileMode(expected)

	if actual == expectedPerm {
		return true, fmt.Sprintf("permissions match: %s has %04o", cleaned, actual), nil
	}

	return false, fmt.Sprintf("permissions mismatch: %s has %04o, expected %04o", cleaned, actual, expectedPerm), nil
}

// fileContains checks if a file contains content matching a regex pattern.
// Uses readFileLimited (bounded, symlink-safe) and validateRegexPattern (length-capped).
func (r *FunctionRegistry) fileContains(args map[string]interface{}) (bool, string, error) {
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
		return true, fmt.Sprintf("pattern %q found in %s", pattern, path), nil
	}

	return false, fmt.Sprintf("pattern not found: %q in %s", pattern, path), nil
}

// portListening checks if a TCP port is listening on localhost.
func (r *FunctionRegistry) portListening(args map[string]interface{}) (bool, string, error) {
	port, err := getIntArg(args, "port")
	if err != nil {
		return false, "", err
	}

	if port < 1 || port > 65535 {
		return false, "", fmt.Errorf("invalid port number %d: must be 1-65535", port)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false, fmt.Sprintf("port %d is not listening", port), nil
	}
	defer conn.Close()

	return true, fmt.Sprintf("port %d is listening", port), nil
}

// serviceRunning checks if a systemd service is active using the allowlist executor.
// Validates service name before passing to systemctl.
func (r *FunctionRegistry) serviceRunning(args map[string]interface{}) (bool, string, error) {
	name, err := getStringArg(args, "name")
	if err != nil {
		return false, "", err
	}

	if err := validateServiceName(name); err != nil {
		return false, "", err
	}

	// Default: expect the service to be running
	expectRunning := true
	if raw, ok := args["expect_running"]; ok {
		if b, ok := raw.(bool); ok {
			expectRunning = b
		}
	}

	output, err := r.executor.Execute("systemctl", []string{"is-active", name})
	if err != nil {
		var exitErr *exec.ExitError
		if !isExitError(err, &exitErr) {
			return false, "", fmt.Errorf("failed to execute systemctl: %w", err)
		}
	}

	status := strings.TrimSpace(string(output))
	running := status == "active"

	if expectRunning {
		if running {
			return true, fmt.Sprintf("service %q is running", name), nil
		}
		return false, fmt.Sprintf("service %q is not running", name), nil
	}

	if !running {
		return true, fmt.Sprintf("service %q is not running (as expected)", name), nil
	}
	return false, fmt.Sprintf("service %q is running (should be stopped)", name), nil
}

// isExitError returns true if err (or any wrapped error) is an *exec.ExitError.
func isExitError(err error, target **exec.ExitError) bool {
	return errors.As(err, target)
}

// getStringArg extracts a string argument from the args map.
func getStringArg(args map[string]interface{}, key string) (string, error) {
	val, ok := args[key]
	if !ok {
		return "", fmt.Errorf("missing required argument %q", key)
	}

	str, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("argument %q must be a string, got %T", key, val)
	}

	return str, nil
}

// getIntArg extracts an integer argument from the args map.
// Handles both int and float64 (common from YAML/JSON unmarshaling).
func getIntArg(args map[string]interface{}, key string) (int, error) {
	val, ok := args[key]
	if !ok {
		return 0, fmt.Errorf("missing required argument %q", key)
	}

	switch v := val.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		return int(v), nil
	default:
		return 0, fmt.Errorf("argument %q must be a number, got %T", key, val)
	}
}
