package engine

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// CommandSpec defines the constraints for an allowlisted command.
type CommandSpec struct {
	// Path is the resolved absolute path to the command binary.
	// Resolved at construction time via exec.LookPath, with a hardcoded fallback.
	Path string

	// FallbackPath is the hardcoded path used when LookPath fails.
	FallbackPath string

	// AllowedFlags are the flags/subcommands that can be passed.
	AllowedFlags []string

	// MaxArgs is the maximum number of positional (non-flag) arguments allowed.
	MaxArgs int

	// Timeout is the maximum execution time for this command.
	Timeout time.Duration
}

// AllowlistExecutor executes only pre-approved commands with validated arguments.
// This is the security boundary that prevents arbitrary command execution.
type AllowlistExecutor struct {
	allowlist map[string]CommandSpec
}

// resolveCommandPath attempts to find the command using exec.LookPath.
// Falls back to the provided default path if LookPath fails.
func resolveCommandPath(name, fallbackPath string) string {
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	return fallbackPath
}

// NewAllowlistExecutor creates an executor with the default security-focused allowlist.
// Command paths are resolved via exec.LookPath at construction time, with hardcoded
// fallback paths for systems where the binary isn't in PATH.
func NewAllowlistExecutor() *AllowlistExecutor {
	type entry struct {
		name         string
		fallbackPath string
		allowedFlags []string
		maxArgs      int
		timeout      time.Duration
	}

	entries := []entry{
		{"systemctl", "/usr/bin/systemctl", []string{"status", "is-active", "is-enabled", "is-failed"}, 2, 5 * time.Second},
		{"stat", "/usr/bin/stat", []string{"-c", "--format"}, 1, 2 * time.Second},
		{"ss", "/usr/bin/ss", []string{"-tlnp", "-t", "-l", "-n", "-p"}, 0, 2 * time.Second},
		{"ufw", "/usr/sbin/ufw", []string{"status"}, 0, 2 * time.Second},
		{"iptables", "/usr/sbin/iptables", []string{"-L", "-n", "--list"}, 1, 5 * time.Second},
		{"auditctl", "/usr/sbin/auditctl", []string{"-l"}, 0, 2 * time.Second},
		{"timedatectl", "/usr/bin/timedatectl", []string{"status", "show"}, 1, 2 * time.Second},
		{"loginctl", "/usr/bin/loginctl", []string{"show-session"}, 1, 2 * time.Second},
	}

	allowlist := make(map[string]CommandSpec, len(entries))
	for _, e := range entries {
		allowlist[e.name] = CommandSpec{
			Path:         resolveCommandPath(e.name, e.fallbackPath),
			FallbackPath: e.fallbackPath,
			AllowedFlags: e.allowedFlags,
			MaxArgs:      e.maxArgs,
			Timeout:      e.timeout,
		}
	}

	return &AllowlistExecutor{allowlist: allowlist}
}

// IsAllowed checks whether a command is in the allowlist.
func (e *AllowlistExecutor) IsAllowed(cmd string) bool {
	_, ok := e.allowlist[cmd]
	return ok
}

// Execute runs an allowlisted command with validated arguments.
// Returns stdout output or an error. Never uses shell invocation.
func (e *AllowlistExecutor) Execute(cmd string, args []string) ([]byte, error) {
	spec, ok := e.allowlist[cmd]
	if !ok {
		return nil, fmt.Errorf("command %q not in allowlist", cmd)
	}

	if err := validateArgs(spec, args); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), spec.Timeout)
	defer cancel()

	execCmd := exec.CommandContext(ctx, spec.Path, args...)
	output, err := execCmd.Output()

	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("command %q timed out after %v", cmd, spec.Timeout)
	}

	return output, err
}

// validateArgs checks that all arguments comply with the CommandSpec constraints.
func validateArgs(spec CommandSpec, args []string) error {
	positionalCount := 0

	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			if !isAllowedFlag(spec.AllowedFlags, arg) {
				return fmt.Errorf("flag %q not allowed for this command (allowed: %s)",
					arg, strings.Join(spec.AllowedFlags, ", "))
			}
		} else {
			positionalCount++
		}
	}

	if positionalCount > spec.MaxArgs {
		return fmt.Errorf("too many positional arguments: got %d, max %d",
			positionalCount, spec.MaxArgs)
	}

	return nil
}

// isAllowedFlag checks if a flag is in the allowed list.
func isAllowedFlag(allowed []string, flag string) bool {
	for _, f := range allowed {
		if f == flag {
			return true
		}
	}
	return false
}
