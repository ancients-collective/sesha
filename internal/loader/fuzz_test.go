package loader

import (
	"testing"

	"github.com/ancients-collective/sesha/internal/types"
	"gopkg.in/yaml.v3"
)

// FuzzLoadYAML exercises the YAML check parser with random bytes to ensure
// it never panics — always returns a valid result or an error.
func FuzzLoadYAML(f *testing.F) {
	// Seed with a valid minimal check
	f.Add([]byte(`id: test_check
name: Test Check
category: test
function: file_exists
args:
  path: /tmp/test
severity: low
`))
	// Seed with empty input
	f.Add([]byte{})
	// Seed with invalid YAML
	f.Add([]byte(`{{{invalid yaml---`))
	// Seed with valid YAML but invalid check
	f.Add([]byte(`id: ""
name: ""
`))

	knownFunctions := []string{
		"file_exists", "file_not_exists", "file_contains",
		"file_not_contains", "file_permissions", "file_owner",
		"service_running", "service_enabled", "port_listening",
		"command_output_contains", "sysctl_value",
		"kernel_module_loaded", "mount_option",
	}
	l := New(knownFunctions)

	f.Fuzz(func(t *testing.T, data []byte) {
		var test types.TestDefinition
		if err := yaml.Unmarshal(data, &test); err != nil {
			return // Invalid YAML is fine
		}
		// Validate must not panic
		_ = l.validateTest(test)
	})
}
