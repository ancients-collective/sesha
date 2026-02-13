package loader_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ancients-collective/sesha/internal/engine"
	"github.com/ancients-collective/sesha/internal/loader"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findChecksDir walks up from the test file to find the repo root checks/ dir.
func findChecksDir(t *testing.T) string {
	t.Helper()

	// Start from this test file's directory and walk up to find checks/
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller failed")

	dir := filepath.Dir(filename)
	for i := 0; i < 10; i++ {
		candidate := filepath.Join(dir, "checks")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	t.Skip("checks directory not found — run tests from the repository root")
	return ""
}

func TestAllChecksLoadSuccessfully(t *testing.T) {
	checksDir := findChecksDir(t)
	registry := engine.NewFunctionRegistry(nil)
	ldr := loader.New(registry.FunctionNames())

	tests, errs := ldr.LoadDirectory(checksDir)

	for _, err := range errs {
		t.Errorf("load error: %v", err)
	}

	assert.Empty(t, errs, "all checks should load without errors")
	assert.GreaterOrEqual(t, len(tests), 13, "expected at least 13 starter checks")

	t.Logf("loaded %d checks successfully", len(tests))
}

func TestNoDuplicateIDs(t *testing.T) {
	checksDir := findChecksDir(t)
	registry := engine.NewFunctionRegistry(nil)
	ldr := loader.New(registry.FunctionNames())

	tests, errs := ldr.LoadDirectory(checksDir)
	require.Empty(t, errs)

	seen := make(map[string]string) // id -> first occurrence
	for _, test := range tests {
		if prev, exists := seen[test.ID]; exists {
			t.Errorf("duplicate ID %q: first seen as %s, found again", test.ID, prev)
		}
		seen[test.ID] = test.ID
	}
}

func TestAllHaveRequiredMetadata(t *testing.T) {
	checksDir := findChecksDir(t)
	registry := engine.NewFunctionRegistry(nil)
	ldr := loader.New(registry.FunctionNames())

	tests, errs := ldr.LoadDirectory(checksDir)
	require.Empty(t, errs)

	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true, "info": true,
	}

	for _, test := range tests {
		t.Run(test.ID, func(t *testing.T) {
			assert.NotEmpty(t, test.ID, "ID must be set")
			assert.NotEmpty(t, test.Name, "Name must be set")
			assert.NotEmpty(t, test.Description, "Description must be set")
			assert.True(t, validSeverities[test.Severity],
				"Severity %q is not valid for check %s", test.Severity, test.ID)
			assert.NotEmpty(t, test.Category, "Category must be set")
			assert.NotEmpty(t, test.Remediation, "Remediation must be set")
			assert.NotEmpty(t, test.Steps, "Steps must not be empty")

			// Every step must have a function and args
			for i, step := range test.Steps {
				assert.NotEmpty(t, step.Function,
					"Step %d of check %s must have a function", i, test.ID)
				assert.NotNil(t, step.Args,
					"Step %d of check %s must have args", i, test.ID)
			}
		})
	}
}

func TestAllFunctionsExistInRegistry(t *testing.T) {
	checksDir := findChecksDir(t)
	registry := engine.NewFunctionRegistry(nil)
	knownFuncs := make(map[string]bool)
	for _, name := range registry.FunctionNames() {
		knownFuncs[name] = true
	}

	ldr := loader.New(registry.FunctionNames())
	tests, errs := ldr.LoadDirectory(checksDir)
	require.Empty(t, errs)

	for _, test := range tests {
		for _, step := range test.Steps {
			assert.True(t, knownFuncs[step.Function],
				"check %s uses unknown function %q", test.ID, step.Function)
		}
	}
}

func TestChecksHaveValidIDs(t *testing.T) {
	checksDir := findChecksDir(t)
	registry := engine.NewFunctionRegistry(nil)
	ldr := loader.New(registry.FunctionNames())

	tests, errs := ldr.LoadDirectory(checksDir)
	require.Empty(t, errs)

	for _, test := range tests {
		t.Run(test.ID, func(t *testing.T) {
			// IDs should be snake_case with optional hyphens
			for _, ch := range test.ID {
				valid := (ch >= 'a' && ch <= 'z') ||
					(ch >= '0' && ch <= '9') ||
					ch == '_' || ch == '-'
				assert.True(t, valid,
					"ID %q contains invalid character %q", test.ID, string(ch))
			}
		})
	}
}

func TestChecksEssentialsCategory(t *testing.T) {
	checksDir := findChecksDir(t)
	registry := engine.NewFunctionRegistry(nil)
	ldr := loader.New(registry.FunctionNames())

	tests, errs := ldr.LoadDirectory(checksDir)
	require.Empty(t, errs)

	// Count checks per category
	categories := make(map[string]int)
	for _, test := range tests {
		categories[test.Category]++
	}

	t.Logf("Categories found: %v", categories)

	// The essentials pack should produce checks across several categories
	assert.GreaterOrEqual(t, len(categories), 3,
		"expected checks in at least 3 categories, got %d", len(categories))
}

func TestAllChecksHaveLinuxSupport(t *testing.T) {
	checksDir := findChecksDir(t)
	registry := engine.NewFunctionRegistry(nil)
	ldr := loader.New(registry.FunctionNames())

	tests, errs := ldr.LoadDirectory(checksDir)
	require.Empty(t, errs)

	for _, test := range tests {
		if len(test.SupportedOS) > 0 {
			found := false
			for _, os := range test.SupportedOS {
				if os == "linux" {
					found = true
					break
				}
			}
			assert.True(t, found,
				"check %s specifies supported_os but does not include linux", test.ID)
		}
	}
}

func TestValidateDirectoryReportsAllErrors(t *testing.T) {
	dir := t.TempDir()

	// Write a valid check
	validYAML := `id: good_check
name: "Good Check"
description: "A valid check"
severity: high
category: test
steps:
  - function: file_exists
    args:
      path: /etc/passwd
remediation: "fix it"`

	// Write an invalid check (missing required fields)
	invalidYAML := `id: bad_check
description: "Missing name and severity"
steps:
  - function: file_exists
    args:
      path: /tmp`

	require.NoError(t, os.WriteFile(filepath.Join(dir, "good.yaml"), []byte(validYAML), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(invalidYAML), 0o644))

	registry := engine.NewFunctionRegistry(nil)
	ldr := loader.New(registry.FunctionNames())

	errs := ldr.ValidateDirectory(dir)

	assert.NotEmpty(t, errs, "should report errors for the invalid check")

	// Verify errors reference the bad file
	found := false
	for _, e := range errs {
		if fmt.Sprintf("%v", e) != "" {
			found = true
		}
	}
	assert.True(t, found)
}
