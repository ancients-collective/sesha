//go:build darwin

package context

import (
	"os"
	"runtime"

	"github.com/ancients-collective/sesha/internal/types"
	"github.com/shirou/gopsutil/v4/host"
)

// DarwinDetector implements OSDetector for macOS systems.
type DarwinDetector struct{}

// NewOSDetector returns a DarwinDetector for macOS systems.
func NewOSDetector() OSDetector {
	return &DarwinDetector{}
}

// DetectOS returns macOS OS information.
func (d *DarwinDetector) DetectOS() (types.OSInfo, error) {
	info, err := host.Info()
	if err != nil {
		return types.OSInfo{
			Name: runtime.GOOS,
			Arch: runtime.GOARCH,
		}, nil
	}

	return types.OSInfo{
		Name:    runtime.GOOS,
		Version: info.KernelVersion,
		Arch:    runtime.GOARCH,
	}, nil
}

// DetectDistro returns empty DistroInfo — macOS has no distribution concept.
func (d *DarwinDetector) DetectDistro() (types.DistroInfo, error) {
	return types.DistroInfo{}, nil
}

// DetectEnvironment returns bare-metal for macOS with hostname populated.
func (d *DarwinDetector) DetectEnvironment() (types.EnvInfo, error) {
	env := types.EnvInfo{Type: "bare-metal"}
	if h, err := os.Hostname(); err == nil {
		env.Hostname = h
	}
	return env, nil
}
