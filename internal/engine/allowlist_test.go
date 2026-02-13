package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllowlistExecutor_AllowedCommand(t *testing.T) {
	executor := NewAllowlistExecutor()

	_, err := executor.Execute("stat", []string{"-c", "%a", "/tmp"})
	if err != nil {
		assert.NotContains(t, err.Error(), "not in allowlist")
	}
}

func TestAllowlistExecutor_RejectedCommand(t *testing.T) {
	executor := NewAllowlistExecutor()

	_, err := executor.Execute("rm", []string{"-rf", "/"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not in allowlist")
}

func TestAllowlistExecutor_DisallowedFlag(t *testing.T) {
	executor := NewAllowlistExecutor()

	_, err := executor.Execute("systemctl", []string{"--force", "stop", "sshd"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed")
}

func TestAllowlistExecutor_TooManyArgs(t *testing.T) {
	executor := NewAllowlistExecutor()

	_, err := executor.Execute("stat", []string{"-c", "%a", "file1", "file2", "file3"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many")
}

func TestAllowlistExecutor_EmptyCommand(t *testing.T) {
	executor := NewAllowlistExecutor()

	_, err := executor.Execute("", nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not in allowlist")
}

func TestAllowlistExecutor_ShellInjectionPrevention(t *testing.T) {
	executor := NewAllowlistExecutor()

	dangerous := []struct {
		cmd  string
		args []string
	}{
		{"sh", []string{"-c", "echo pwned"}},
		{"bash", []string{"-c", "echo pwned"}},
		{"/bin/sh", []string{"-c", "echo pwned"}},
	}

	for _, d := range dangerous {
		t.Run(d.cmd, func(t *testing.T) {
			_, err := executor.Execute(d.cmd, d.args)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not in allowlist")
		})
	}
}

func TestAllowlistExecutor_DefaultAllowlistContents(t *testing.T) {
	executor := NewAllowlistExecutor()

	expected := []string{"systemctl", "stat", "ss", "ufw", "iptables", "timedatectl", "loginctl", "auditctl"}
	for _, cmd := range expected {
		t.Run(cmd, func(t *testing.T) {
			assert.True(t, executor.IsAllowed(cmd), "command %q should be in allowlist", cmd)
		})
	}

	rejected := []string{"rm", "sh", "bash", "curl", "wget", "dd", "mkfs"}
	for _, cmd := range rejected {
		t.Run("rejected_"+cmd, func(t *testing.T) {
			assert.False(t, executor.IsAllowed(cmd), "command %q should NOT be in allowlist", cmd)
		})
	}
}

func TestAllowlistExecutor_ValidFlagCombinations(t *testing.T) {
	executor := NewAllowlistExecutor()

	tests := []struct {
		cmd  string
		args []string
	}{
		{"systemctl", []string{"is-active", "sshd"}},
		{"systemctl", []string{"is-enabled", "sshd"}},
		{"systemctl", []string{"status", "sshd"}},
		{"ss", []string{"-tlnp"}},
		{"timedatectl", []string{"status"}},
		{"timedatectl", []string{"show"}},
		{"loginctl", []string{"show-session"}},
	}

	for _, tt := range tests {
		t.Run(tt.cmd+"_"+tt.args[0], func(t *testing.T) {
			_, err := executor.Execute(tt.cmd, tt.args)
			if err != nil {
				assert.NotContains(t, err.Error(), "not in allowlist")
				assert.NotContains(t, err.Error(), "not allowed")
				assert.NotContains(t, err.Error(), "too many")
			}
		})
	}
}

func TestAllowlistExecutor_TimedatectlTooManyArgs(t *testing.T) {
	executor := NewAllowlistExecutor()

	_, err := executor.Execute("timedatectl", []string{"status", "extra"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many")
}
