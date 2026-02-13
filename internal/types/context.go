package types

// Valid environment types.
const (
	EnvContainer = "container"
	EnvVM        = "vm"
	EnvBareMetal = "bare-metal"
)

// Valid intent profiles.
const (
	ProfileServer      = "server"
	ProfileWorkstation = "workstation"
)

// ValidWhenTokens is the set of tokens accepted in acceptable.when blocks.
// Derived from the environment types and profile constants above.
var ValidWhenTokens = map[string]bool{
	EnvContainer:       true,
	EnvVM:              true,
	EnvBareMetal:       true,
	ProfileServer:      true,
	ProfileWorkstation: true,
}

// SystemContext holds information about the system where checks are running.
// It is populated by the context detection package and used to filter checks.
type SystemContext struct {
	// OS contains operating system information.
	OS OSInfo

	// Distro contains Linux distribution information.
	Distro DistroInfo

	// Environment contains execution environment information.
	Environment EnvInfo

	// IntentProfile is the intended use of the system (server, workstation, container).
	// Set externally via CLI flag or config, not auto-detected.
	IntentProfile string
}

// OSInfo holds operating system details.
type OSInfo struct {
	// Name is the OS identifier (e.g., "linux", "darwin").
	Name string

	// Version is the kernel version string.
	Version string

	// Arch is the CPU architecture (e.g., "amd64", "arm64").
	Arch string
}

// DistroInfo holds Linux distribution details.
// Empty on non-Linux systems.
type DistroInfo struct {
	// ID is the distribution identifier (e.g., "ubuntu", "rhel", "alpine").
	ID string

	// Version is the distribution version (e.g., "22.04", "9", "3.18").
	Version string

	// Family is the distribution family (e.g., "debian", "rhel", "alpine").
	Family string
}

// EnvInfo holds execution environment details.
type EnvInfo struct {
	// Type is the environment category: "container", "vm", or "bare-metal".
	Type string

	// Runtime is the specific runtime (e.g., "docker", "podman", "kvm", "vmware").
	Runtime string

	// Hostname is the system hostname (os.Hostname).
	Hostname string

	// MachineID is the stable machine identifier (from /etc/machine-id on Linux).
	MachineID string

	// ContainerID is the container ID when running inside a container.
	ContainerID string
}
