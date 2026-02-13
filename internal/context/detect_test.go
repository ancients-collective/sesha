package context

import (
	"errors"
	"testing"

	"github.com/ancients-collective/sesha/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockDetector is a configurable OSDetector for testing the coordinator logic.
type mockDetector struct {
	osInfo    types.OSInfo
	osErr     error
	distro    types.DistroInfo
	distroErr error
	env       types.EnvInfo
	envErr    error
}

func (m *mockDetector) DetectOS() (types.OSInfo, error)           { return m.osInfo, m.osErr }
func (m *mockDetector) DetectDistro() (types.DistroInfo, error)   { return m.distro, m.distroErr }
func (m *mockDetector) DetectEnvironment() (types.EnvInfo, error) { return m.env, m.envErr }

func TestDetectSystemContext_AllSuccess(t *testing.T) {
	detector := &mockDetector{
		osInfo: types.OSInfo{Name: "linux", Version: "6.1.0", Arch: "amd64"},
		distro: types.DistroInfo{ID: "ubuntu", Version: "22.04", Family: "debian"},
		env:    types.EnvInfo{Type: "container", Runtime: "docker"},
	}

	ctx, warnings, err := DetectSystemContext(detector)

	require.NoError(t, err)
	assert.Empty(t, warnings)
	assert.Equal(t, "linux", ctx.OS.Name)
	assert.Equal(t, "6.1.0", ctx.OS.Version)
	assert.Equal(t, "amd64", ctx.OS.Arch)
	assert.Equal(t, "ubuntu", ctx.Distro.ID)
	assert.Equal(t, "22.04", ctx.Distro.Version)
	assert.Equal(t, "debian", ctx.Distro.Family)
	assert.Equal(t, "container", ctx.Environment.Type)
	assert.Equal(t, "docker", ctx.Environment.Runtime)
}

func TestDetectSystemContext_OSFailure(t *testing.T) {
	detector := &mockDetector{
		osErr: errors.New("OS detection failed"),
	}

	_, _, err := DetectSystemContext(detector)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "OS detection failed")
}

func TestDetectSystemContext_DistroFailureNonFatal(t *testing.T) {
	detector := &mockDetector{
		osInfo:    types.OSInfo{Name: "linux", Version: "6.1.0", Arch: "amd64"},
		distroErr: errors.New("distro detection failed"),
		env:       types.EnvInfo{Type: "bare-metal"},
	}

	ctx, warnings, err := DetectSystemContext(detector)

	require.NoError(t, err) // Distro failure should not cause overall failure
	assert.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "distro detection failed")
	assert.Equal(t, "linux", ctx.OS.Name)
	assert.Empty(t, ctx.Distro.ID) // Distro should be empty
	assert.Equal(t, "bare-metal", ctx.Environment.Type)
}

func TestDetectSystemContext_EnvironmentFailureNonFatal(t *testing.T) {
	detector := &mockDetector{
		osInfo: types.OSInfo{Name: "linux", Version: "6.1.0", Arch: "amd64"},
		distro: types.DistroInfo{ID: "ubuntu", Version: "22.04", Family: "debian"},
		envErr: errors.New("env detection failed"),
	}

	ctx, warnings, err := DetectSystemContext(detector)

	require.NoError(t, err) // Env failure should not cause overall failure
	assert.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "environment detection failed")
	assert.Equal(t, "linux", ctx.OS.Name)
	assert.Equal(t, "ubuntu", ctx.Distro.ID)
	assert.Empty(t, ctx.Environment.Type) // Env should be empty
}

func TestDetectSystemContext_IntentProfileSetByCaller(t *testing.T) {
	detector := &mockDetector{
		osInfo: types.OSInfo{Name: "linux", Version: "6.1.0", Arch: "amd64"},
	}

	ctx, _, err := DetectSystemContext(detector)

	require.NoError(t, err)
	assert.Empty(t, ctx.IntentProfile) // Not set by detection

	// Caller sets it
	ctx.IntentProfile = "server"
	assert.Equal(t, "server", ctx.IntentProfile)
}

func TestDetectSystemContext_BareMetal(t *testing.T) {
	detector := &mockDetector{
		osInfo: types.OSInfo{Name: "linux", Version: "6.1.0", Arch: "amd64"},
		distro: types.DistroInfo{ID: "rhel", Version: "9", Family: "rhel"},
		env:    types.EnvInfo{Type: "bare-metal"},
	}

	ctx, _, err := DetectSystemContext(detector)

	require.NoError(t, err)
	assert.Equal(t, "bare-metal", ctx.Environment.Type)
	assert.Empty(t, ctx.Environment.Runtime)
}

func TestDetectSystemContext_VM(t *testing.T) {
	detector := &mockDetector{
		osInfo: types.OSInfo{Name: "linux", Version: "6.1.0", Arch: "amd64"},
		distro: types.DistroInfo{ID: "ubuntu", Version: "22.04", Family: "debian"},
		env:    types.EnvInfo{Type: "vm", Runtime: "kvm"},
	}

	ctx, _, err := DetectSystemContext(detector)

	require.NoError(t, err)
	assert.Equal(t, "vm", ctx.Environment.Type)
	assert.Equal(t, "kvm", ctx.Environment.Runtime)
}

func TestDetectSystemContext_Container(t *testing.T) {
	detector := &mockDetector{
		osInfo: types.OSInfo{Name: "linux", Version: "6.1.0", Arch: "amd64"},
		distro: types.DistroInfo{ID: "alpine", Version: "3.18", Family: "alpine"},
		env: types.EnvInfo{
			Type:        "container",
			Runtime:     "docker",
			ContainerID: "abc123def456abc123def456abc123def456abc123def456abc123def456abc12345",
		},
	}

	ctx, _, err := DetectSystemContext(detector)

	require.NoError(t, err)
	assert.Equal(t, "container", ctx.Environment.Type)
	assert.Equal(t, "docker", ctx.Environment.Runtime)
	assert.NotEmpty(t, ctx.Environment.ContainerID)
}

func TestDetectSystemContext_AllFailures(t *testing.T) {
	detector := &mockDetector{
		osErr: errors.New("critical failure"),
	}

	_, _, err := DetectSystemContext(detector)

	require.Error(t, err)
	// Only OS failure is fatal, others are non-fatal
}

func TestDetectSystemContext_IdentityFields(t *testing.T) {
	detector := &mockDetector{
		osInfo: types.OSInfo{Name: "linux", Version: "6.1.0", Arch: "amd64"},
		distro: types.DistroInfo{ID: "ubuntu", Version: "22.04", Family: "debian"},
		env: types.EnvInfo{
			Type:      "vm",
			Runtime:   "kvm",
			Hostname:  "test-host",
			MachineID: "abc123",
		},
	}

	ctx, _, err := DetectSystemContext(detector)

	require.NoError(t, err)
	assert.Equal(t, "test-host", ctx.Environment.Hostname)
	assert.Equal(t, "abc123", ctx.Environment.MachineID)
}
