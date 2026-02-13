//go:build linux

package context

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"

	"github.com/ancients-collective/sesha/internal/types"
	"github.com/shirou/gopsutil/v4/host"
)

// containerIDPattern matches a 64-character hexadecimal container ID in cgroup paths.
var containerIDPattern = regexp.MustCompile(`[a-f0-9]{64}`)

// LinuxDetector implements OSDetector for Linux systems using gopsutil.
type LinuxDetector struct{}

// NewOSDetector returns a LinuxDetector for Linux systems.
func NewOSDetector() OSDetector {
	return &LinuxDetector{}
}

// DetectOS returns Linux OS information.
func (d *LinuxDetector) DetectOS() (types.OSInfo, error) {
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

// DetectDistro returns Linux distribution information via gopsutil.
func (d *LinuxDetector) DetectDistro() (types.DistroInfo, error) {
	info, err := host.Info()
	if err != nil {
		return types.DistroInfo{}, err
	}

	return types.DistroInfo{
		ID:      info.Platform,
		Version: info.PlatformVersion,
		Family:  info.PlatformFamily,
	}, nil
}

// DetectEnvironment detects whether running in a container, VM, or bare-metal.
// Also collects system identity: hostname, machine-id, and container-id.
func (d *LinuxDetector) DetectEnvironment() (types.EnvInfo, error) {
	env := types.EnvInfo{Type: "bare-metal"}

	// Collect hostname (best-effort)
	if h, err := os.Hostname(); err == nil {
		env.Hostname = h
	}

	// Collect machine-id (best-effort)
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		env.MachineID = strings.TrimSpace(string(data))
	}

	// Check container first (container > VM > bare-metal priority)
	if isContainer, cRuntime := detectContainer(); isContainer {
		env.Type = "container"
		env.Runtime = cRuntime
		env.ContainerID = detectContainerID()
	} else if isVM, hypervisor := detectVM(); isVM {
		env.Type = "vm"
		env.Runtime = hypervisor
	}

	return env, nil
}

// detectContainer checks for container indicators using multiple signals.
func detectContainer() (bool, string) {
	return detectContainerWith(
		"/.dockerenv",
		"/run/.containerenv",
		"/proc/self/cgroup",
	)
}

// detectContainerWith is the injectable core of container detection.
// It tries gopsutil first, then checks marker files and cgroup contents.
func detectContainerWith(dockerenvPath, containerenvPath, cgroupPath string) (bool, string) {
	role, virt, err := host.Virtualization()
	if err == nil && role == "guest" {
		switch virt {
		case "docker", "lxc", "podman", "systemd-nspawn":
			return true, virt
		}
	}

	if _, err := os.Lstat(dockerenvPath); err == nil {
		return true, "docker"
	}

	if _, err := os.Lstat(containerenvPath); err == nil {
		return true, "podman"
	}

	if data, err := os.ReadFile(cgroupPath); err == nil {
		if bytes.Contains(data, []byte("docker")) {
			return true, "docker"
		}
		if bytes.Contains(data, []byte("kubepods")) {
			return true, "kubernetes"
		}
		if bytes.Contains(data, []byte("lxc")) {
			return true, "lxc"
		}
	}

	return false, ""
}

// detectContainerID extracts the container ID from cgroup or cpuset information.
func detectContainerID() string {
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		if id := containerIDPattern.FindString(string(data)); id != "" {
			return id
		}
	}

	if data, err := os.ReadFile("/proc/1/cpuset"); err == nil {
		if id := containerIDPattern.FindString(string(data)); id != "" {
			return id
		}
	}

	return ""
}

// detectVM checks for virtual machine hypervisors using gopsutil with
// filesystem-based fallbacks for environments where gopsutil returns empty.
func detectVM() (bool, string) {
	return detectVMWith(
		"/sys/class/dmi/id/sys_vendor",
		"/sys/class/dmi/id/product_name",
		"/proc/cpuinfo",
		"/proc/device-tree/hypervisor/compatible",
	)
}

// detectVMWith is the injectable core of VM detection. It tries gopsutil
// first, then falls through DMI, cpuinfo, and device-tree paths.
func detectVMWith(
	sysVendorPath, productNamePath, cpuinfoPath, deviceTreePath string,
) (bool, string) {
	// Primary: gopsutil host.Virtualization
	role, virt, err := host.Virtualization()
	if err == nil && role == "guest" && virt != "" {
		switch virt {
		case "docker", "lxc", "podman", "systemd-nspawn":
			// not a VM — let container detection handle it
		default:
			return true, virt
		}
	}

	// Fallback 1: DMI sys_vendor
	vendorMap := map[string]string{
		"qemu":                  "kvm",
		"bochs":                 "kvm",
		"innotek gmbh":          "virtualbox",
		"vmware, inc.":          "vmware",
		"microsoft corporation": "hyper-v",
		"xen":                   "xen",
		"amazon ec2":            "aws-nitro",
		"google":                "gce",
		"digitalocean":          "digitalocean",
		"hetzner":               "hetzner",
	}
	if data, err := os.ReadFile(sysVendorPath); err == nil {
		v := strings.TrimSpace(strings.ToLower(string(data)))
		for substr, hv := range vendorMap {
			if strings.Contains(v, substr) {
				return true, hv
			}
		}
	}

	// Fallback 2: DMI product_name
	type productMatch struct {
		substr, hv string
	}
	productMatches := []productMatch{
		{"kvm", "kvm"},
		{"virtualbox", "virtualbox"},
		{"vmware", "vmware"},
		{"standard pc", "kvm"},
		{"bhyve", "bhyve"},
		{"virtual machine", "hyper-v"},
	}
	if data, err := os.ReadFile(productNamePath); err == nil {
		p := strings.TrimSpace(strings.ToLower(string(data)))
		for _, m := range productMatches {
			if strings.Contains(p, m.substr) {
				return true, m.hv
			}
		}
	}

	// Fallback 3: /proc/cpuinfo hypervisor flag (x86)
	if data, err := os.ReadFile(cpuinfoPath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "flags") && strings.Contains(line, " hypervisor") {
				return true, "unknown"
			}
		}
	}

	// Fallback 4: device-tree (arm64 / non-DMI)
	if data, err := os.ReadFile(deviceTreePath); err == nil {
		d := strings.TrimSpace(strings.ToLower(string(data)))
		d = strings.ReplaceAll(d, "\x00", "")
		if strings.Contains(d, "kvm") {
			return true, "kvm"
		}
		if strings.Contains(d, "xen") {
			return true, "xen"
		}
		return true, d
	}

	if DebugMode {
		fmt.Fprintf(os.Stderr, "debug: VM detection: no hypervisor indicators found\n")
	}
	return false, ""
}
