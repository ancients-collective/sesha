// Package context detects system information for check filtering.
package context

import (
	"fmt"

	"github.com/ancients-collective/sesha/internal/types"
)

// OSDetector abstracts platform-specific system detection.
// Each supported OS provides an implementation via build tags.
type OSDetector interface {
	// DetectOS returns operating system information.
	DetectOS() (types.OSInfo, error)

	// DetectDistro returns Linux distribution information.
	// Returns empty DistroInfo on non-Linux systems.
	DetectDistro() (types.DistroInfo, error)

	// DetectEnvironment returns execution environment information
	// (container, VM, or bare-metal).
	DetectEnvironment() (types.EnvInfo, error)
}

// DebugMode enables diagnostic messages to stderr.
// Set via --debug for troubleshooting detection issues.
var DebugMode bool

// DetectSystemContext coordinates layered system detection using the provided detector.
// Detection follows a layered approach:
//   - Layer 1: OS detection (must succeed)
//   - Layer 2: Distro detection (warning on failure, continues)
//   - Layer 3: Environment detection (warning on failure, continues)
//
// Returns the system context, a list of non-fatal warnings, and an error (only for
// Layer 1 OS detection failure, which is fatal).
// IntentProfile should be set by the caller after detection (from CLI flag or config).
func DetectSystemContext(detector OSDetector) (types.SystemContext, []string, error) {
	var ctx types.SystemContext
	var warnings []string

	// Layer 1: OS detection — must succeed
	osInfo, err := detector.DetectOS()
	if err != nil {
		return ctx, nil, fmt.Errorf("OS detection failed: %w", err)
	}
	ctx.OS = osInfo

	// Layer 2: Distro detection — non-fatal failure
	distro, err := detector.DetectDistro()
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("distro detection failed: %v", err))
	} else {
		ctx.Distro = distro
	}

	// Layer 3: Environment detection — non-fatal failure
	env, err := detector.DetectEnvironment()
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("environment detection failed: %v", err))
	} else {
		ctx.Environment = env
	}

	return ctx, warnings, nil
}
