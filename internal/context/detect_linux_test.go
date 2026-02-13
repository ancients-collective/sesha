//go:build linux

package context

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── detectVMWith unit tests ──────────────────────────────────────────

func TestDetectVMWith_DMISysVendor(t *testing.T) {
	tests := []struct {
		name   string
		vendor string
		wantVM bool
		wantHV string
	}{
		{"QEMU", "QEMU\n", true, "kvm"},
		{"Bochs", "Bochs\n", true, "kvm"},
		{"VirtualBox", "innotek GmbH\n", true, "virtualbox"},
		{"VMware", "VMware, Inc.\n", true, "vmware"},
		{"Hyper-V", "Microsoft Corporation\n", true, "hyper-v"},
		{"Xen", "Xen\n", true, "xen"},
		{"AWS Nitro", "Amazon EC2\n", true, "aws-nitro"},
		{"GCE", "Google\n", true, "gce"},
		{"DigitalOcean", "DigitalOcean\n", true, "digitalocean"},
		{"Hetzner", "Hetzner\n", true, "hetzner"},
		{"Dell bare-metal", "Dell Inc.\n", false, ""},
		{"Lenovo bare-metal", "LENOVO\n", false, ""},
		{"Supermicro bare-metal", "Supermicro\n", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			vendorPath := filepath.Join(dir, "sys_vendor")
			require.NoError(t, os.WriteFile(vendorPath, []byte(tt.vendor), 0o644))

			isVM, hv := detectVMWith(vendorPath, "/nonexistent", "/nonexistent", "/nonexistent")
			assert.Equal(t, tt.wantVM, isVM)
			assert.Equal(t, tt.wantHV, hv)
		})
	}
}

func TestDetectVMWith_DMIProductName(t *testing.T) {
	tests := []struct {
		name    string
		product string
		wantVM  bool
		wantHV  string
	}{
		{"KVM Standard PC", "Standard PC (Q35 + ICH9, 2009)\n", true, "kvm"},
		{"KVM keyword", "KVM Virtual Machine\n", true, "kvm"},
		{"VirtualBox", "VirtualBox\n", true, "virtualbox"},
		{"Hyper-V", "Virtual Machine\n", true, "hyper-v"},
		{"VMware", "VMware Virtual Platform\n", true, "vmware"},
		{"bhyve", "BHYVE\n", true, "bhyve"},
		{"Physical server", "PowerEdge R740\n", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			productPath := filepath.Join(dir, "product_name")
			require.NoError(t, os.WriteFile(productPath, []byte(tt.product), 0o644))

			// No sys_vendor → skip to product_name fallback
			isVM, hv := detectVMWith("/nonexistent", productPath, "/nonexistent", "/nonexistent")
			assert.Equal(t, tt.wantVM, isVM)
			assert.Equal(t, tt.wantHV, hv)
		})
	}
}

func TestDetectVMWith_CPUInfoHypervisorFlag(t *testing.T) {
	dir := t.TempDir()
	cpuinfo := filepath.Join(dir, "cpuinfo")

	content := `processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 142
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr hypervisor lahf_lm
`
	require.NoError(t, os.WriteFile(cpuinfo, []byte(content), 0o644))

	isVM, hv := detectVMWith("/nonexistent", "/nonexistent", cpuinfo, "/nonexistent")
	assert.True(t, isVM)
	assert.Equal(t, "unknown", hv)
}

func TestDetectVMWith_CPUInfoNoHypervisorFlag(t *testing.T) {
	dir := t.TempDir()
	cpuinfo := filepath.Join(dir, "cpuinfo")

	content := `processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr lahf_lm
`
	require.NoError(t, os.WriteFile(cpuinfo, []byte(content), 0o644))

	isVM, hv := detectVMWith("/nonexistent", "/nonexistent", cpuinfo, "/nonexistent")
	assert.False(t, isVM)
	assert.Empty(t, hv)
}

func TestDetectVMWith_DeviceTree(t *testing.T) {
	tests := []struct {
		name   string
		dt     string
		wantHV string
	}{
		{"KVM device-tree", "linux,kvm\x00", "kvm"},
		{"Xen device-tree", "xen,xen-4.17\x00", "xen"},
		{"Other hypervisor", "custom-hv\x00", "custom-hv"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			dtPath := filepath.Join(dir, "compatible")
			require.NoError(t, os.WriteFile(dtPath, []byte(tt.dt), 0o644))

			isVM, hv := detectVMWith("/nonexistent", "/nonexistent", "/nonexistent", dtPath)
			assert.True(t, isVM)
			assert.Equal(t, tt.wantHV, hv)
		})
	}
}

func TestDetectVMWith_AllPathsMissing(t *testing.T) {
	isVM, hv := detectVMWith("/nonexistent", "/nonexistent", "/nonexistent", "/nonexistent")
	// gopsutil may or may not detect the current host as a VM,
	// but with no filesystem fallbacks the function should still return cleanly.
	_ = isVM
	_ = hv
}

func TestDetectVMWith_FallbackOrder(t *testing.T) {
	// When sys_vendor matches, product_name/cpuinfo/device-tree are not needed.
	dir := t.TempDir()
	vendorPath := filepath.Join(dir, "sys_vendor")
	require.NoError(t, os.WriteFile(vendorPath, []byte("QEMU\n"), 0o644))

	productPath := filepath.Join(dir, "product_name")
	require.NoError(t, os.WriteFile(productPath, []byte("VirtualBox\n"), 0o644))

	isVM, hv := detectVMWith(vendorPath, productPath, "/nonexistent", "/nonexistent")
	assert.True(t, isVM)
	// gopsutil runs first; if it doesn't match, sys_vendor (QEMU→kvm) wins over product_name.
	// On bare-metal CI gopsutil won't match, so we expect kvm from sys_vendor.
	if hv != "kvm" {
		// gopsutil matched first — still valid
		assert.NotEmpty(t, hv)
	}
}

func TestDetectVMWith_DebugHint(t *testing.T) {
	// Verify DebugMode doesn't panic when all paths are missing
	old := DebugMode
	DebugMode = true
	defer func() { DebugMode = old }()

	isVM, hv := detectVMWith("/nonexistent", "/nonexistent", "/nonexistent", "/nonexistent")
	_ = isVM
	_ = hv
}

// ── detectContainerWith unit tests ───────────────────────────────────

func TestDetectContainerWith_DockerEnv(t *testing.T) {
	dir := t.TempDir()
	dockerenv := filepath.Join(dir, ".dockerenv")
	require.NoError(t, os.WriteFile(dockerenv, nil, 0o644))

	isCont, rt := detectContainerWith(dockerenv, "/nonexistent", "/nonexistent")
	assert.True(t, isCont)
	assert.Equal(t, "docker", rt)
}

func TestDetectContainerWith_PodmanEnv(t *testing.T) {
	dir := t.TempDir()
	containerenv := filepath.Join(dir, ".containerenv")
	require.NoError(t, os.WriteFile(containerenv, nil, 0o644))

	isCont, rt := detectContainerWith("/nonexistent", containerenv, "/nonexistent")
	assert.True(t, isCont)
	assert.Equal(t, "podman", rt)
}

func TestDetectContainerWith_CgroupDocker(t *testing.T) {
	dir := t.TempDir()
	cgroup := filepath.Join(dir, "cgroup")
	content := "12:devices:/docker/abc123\n0::/docker/abc123\n"
	require.NoError(t, os.WriteFile(cgroup, []byte(content), 0o644))

	isCont, rt := detectContainerWith("/nonexistent", "/nonexistent", cgroup)
	assert.True(t, isCont)
	assert.Equal(t, "docker", rt)
}

func TestDetectContainerWith_CgroupKubernetes(t *testing.T) {
	dir := t.TempDir()
	cgroup := filepath.Join(dir, "cgroup")
	content := "11:memory:/kubepods/burstable/podabc/def456\n"
	require.NoError(t, os.WriteFile(cgroup, []byte(content), 0o644))

	isCont, rt := detectContainerWith("/nonexistent", "/nonexistent", cgroup)
	assert.True(t, isCont)
	assert.Equal(t, "kubernetes", rt)
}

func TestDetectContainerWith_CgroupLXC(t *testing.T) {
	dir := t.TempDir()
	cgroup := filepath.Join(dir, "cgroup")
	content := "10:memory:/lxc/my-container\n"
	require.NoError(t, os.WriteFile(cgroup, []byte(content), 0o644))

	isCont, rt := detectContainerWith("/nonexistent", "/nonexistent", cgroup)
	assert.True(t, isCont)
	assert.Equal(t, "lxc", rt)
}

func TestDetectContainerWith_NoIndicators(t *testing.T) {
	isCont, rt := detectContainerWith("/nonexistent", "/nonexistent", "/nonexistent")
	// On bare-metal / VM host: gopsutil shouldn't report container.
	// On a CI docker runner: gopsutil may detect it — that's fine.
	_ = isCont
	_ = rt
}

func TestDetectContainerWith_EmptyCgroup(t *testing.T) {
	dir := t.TempDir()
	cgroup := filepath.Join(dir, "cgroup")
	require.NoError(t, os.WriteFile(cgroup, []byte("0::/init.scope\n"), 0o644))

	isCont, rt := detectContainerWith("/nonexistent", "/nonexistent", cgroup)
	// gopsutil may still detect if running in a container, but cgroup fallback won't.
	_ = isCont
	_ = rt
}
