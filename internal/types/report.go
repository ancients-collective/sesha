package types

import "time"

// ScanReport is the top-level structure for a complete scan report.
// It is serialized directly to JSON for the --format=json output.
type ScanReport struct {
	// Version is the sesha version that produced this report.
	Version string `json:"version"`

	// Timestamp is when the scan started.
	Timestamp time.Time `json:"timestamp"`

	// System describes the scanned system.
	System ScanSystem `json:"system"`

	// Filters describes which filters were applied during the scan.
	Filters ScanFilters `json:"filters,omitempty"`

	// Summary provides aggregate statistics.
	Summary ScanSummary `json:"summary"`

	// Results is the list of individual check outcomes.
	Results []TestResult `json:"results"`
}

// ScanSystem describes the system that was scanned.
type ScanSystem struct {
	// Hostname is the system hostname.
	Hostname string `json:"hostname"`

	// OS is the operating system name.
	OS string `json:"os"`

	// OSVersion is the kernel version.
	OSVersion string `json:"os_version"`

	// Arch is the CPU architecture.
	Arch string `json:"arch"`

	// DistroID is the Linux distribution ID.
	DistroID string `json:"distro_id,omitempty"`

	// DistroVersion is the Linux distribution version.
	DistroVersion string `json:"distro_version,omitempty"`

	// DistroFamily is the Linux distribution family.
	DistroFamily string `json:"distro_family,omitempty"`

	// EnvType is the environment category (container, vm, bare-metal).
	EnvType string `json:"env_type"`

	// EnvRuntime is the specific runtime (docker, kvm, etc.).
	EnvRuntime string `json:"env_runtime,omitempty"`

	// ContainerID is the container ID when running inside a container.
	ContainerID string `json:"container_id,omitempty"`

	// Profile is the intent profile used for this scan.
	Profile string `json:"profile,omitempty"`

	// MachineID is the stable machine identifier.
	MachineID string `json:"machine_id,omitempty"`

	// IsRoot indicates whether the scan was run as root/sudo.
	IsRoot bool `json:"is_root"`
}

// ScanFilters records the filters that were active during a scan.
type ScanFilters struct {
	// Show is the display mode (findings, all, fail, pass).
	Show string `json:"show"`

	// Severity lists the severity filters applied.
	Severity []string `json:"severity,omitempty"`

	// Profile is the intent profile filter.
	Profile string `json:"profile,omitempty"`

	// Explain indicates whether explain mode was active.
	Explain bool `json:"explain"`

	// CheckID is set when a single check was targeted by --id.
	CheckID string `json:"check_id,omitempty"`

	// Tags lists the tag filters applied.
	Tags []string `json:"tags,omitempty"`
}

// ScanSummary provides aggregate statistics for a scan.
type ScanSummary struct {
	// TotalChecks is the total number of checks loaded.
	TotalChecks int `json:"total_checks"`

	// Passed is the number of checks that passed.
	Passed int `json:"passed"`

	// Failed is the number of checks that failed.
	Failed int `json:"failed"`

	// Skipped is the number of checks that were skipped.
	Skipped int `json:"skipped"`

	// Errors is the number of checks that errored.
	Errors int `json:"errors"`

	// Accepted is the number of checks that were accepted.
	Accepted int `json:"accepted"`

	// DurationMS is the total scan duration in milliseconds.
	DurationMS int64 `json:"duration_ms"`
}
