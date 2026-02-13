// Package loader reads and validates YAML check definitions from files and directories.
package loader

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"

	"github.com/ancients-collective/sesha/internal/types"
)

// idPattern matches valid check IDs: alphanumeric, underscores, and hyphens.
var idPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Loader reads YAML check definitions and validates them against the schema
// and a set of known built-in function names.
type Loader struct {
	validate       *validator.Validate
	knownFunctions map[string]struct{}
}

// New creates a new Loader with the given known function names.
// Function names are used to validate that check steps reference real functions.
func New(knownFunctions []string) *Loader {
	v := validator.New()

	// Register custom validator for check IDs
	_ = v.RegisterValidation("sesha_id", func(fl validator.FieldLevel) bool {
		return idPattern.MatchString(fl.Field().String())
	})

	funcs := make(map[string]struct{}, len(knownFunctions))
	for _, f := range knownFunctions {
		funcs[f] = struct{}{}
	}

	return &Loader{
		validate:       v,
		knownFunctions: funcs,
	}
}

// LoadTest reads a YAML file and returns a validated TestDefinition.
func (l *Loader) LoadTest(path string) (types.TestDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return types.TestDefinition{}, fmt.Errorf("failed to read %q: %w", path, err)
	}

	var test types.TestDefinition
	if err := yaml.Unmarshal(data, &test); err != nil {
		return types.TestDefinition{}, fmt.Errorf("failed to parse YAML in %q: %w", path, err)
	}

	if err := l.validateTest(test); err != nil {
		return types.TestDefinition{}, err
	}

	return test, nil
}

// LoadDirectory recursively loads all .yaml and .yml files from a directory.
// It returns all successfully loaded checks and a slice of errors for files that failed.
// Loading continues past individual file failures.
// Uses filepath.WalkDir and skips symlinks to prevent symlink-based attacks.
func (l *Loader) LoadDirectory(dir string) ([]types.TestDefinition, []error) {
	var tests []types.TestDefinition
	var errs []error
	seen := make(map[string]string) // check ID → file path

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, fmt.Errorf("error accessing %q: %w", path, err))
			return nil
		}

		if d.Type()&fs.ModeSymlink != 0 {
			errs = append(errs, fmt.Errorf("skipping symlink: %s", path))
			return nil
		}

		if d.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		test, err := l.LoadTest(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			return nil
		}

		if prevPath, exists := seen[test.ID]; exists {
			errs = append(errs, fmt.Errorf("duplicate check ID %q: first defined in %s, duplicated in %s", test.ID, prevPath, path))
			return nil
		}
		seen[test.ID] = path

		tests = append(tests, test)
		return nil
	})
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to walk directory %q: %w", dir, err))
	}

	return tests, errs
}

// ValidateOnly loads a YAML file and validates it without executing any checks.
// Returns nil if the check definition is valid.
func (l *Loader) ValidateOnly(path string) error {
	_, err := l.LoadTest(path)
	return err
}

// ValidateDirectory validates all YAML files in a directory without execution.
// Returns a list of errors for invalid files.
func (l *Loader) ValidateDirectory(dir string) []error {
	var errs []error
	seen := make(map[string]string) // check ID → file path

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, fmt.Errorf("error accessing %q: %w", path, err))
			return nil
		}

		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}

		if d.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		test, err := l.LoadTest(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			return nil
		}

		if prevPath, exists := seen[test.ID]; exists {
			errs = append(errs, fmt.Errorf("duplicate check ID %q: first defined in %s, duplicated in %s", test.ID, prevPath, path))
			return nil
		}
		seen[test.ID] = path

		return nil
	})
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to walk directory %q: %w", dir, err))
	}

	return errs
}

// validateTest runs both schema validation (struct tags) and business logic validation.
func (l *Loader) validateTest(test types.TestDefinition) error {
	if err := l.validate.Struct(test); err != nil {
		return formatValidationErrors(err)
	}

	// Validate function names against known functions
	for i, step := range test.Steps {
		if _, ok := l.knownFunctions[step.Function]; !ok {
			return fmt.Errorf("step %d: unknown function %q (known functions: %s)",
				i+1, step.Function, l.knownFunctionList())
		}
	}

	// Validate severity_overrides values
	validSeverities := map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
	for key, val := range test.SeverityOverrides {
		if !validSeverities[val] {
			return fmt.Errorf("severity_overrides[%q]: invalid severity %q (must be info, low, medium, high, or critical)", key, val)
		}
	}

	// Validate acceptable.when tokens
	validWhenTokens := map[string]bool{
		"container": true, "vm": true, "bare-metal": true,
		"server": true, "workstation": true,
	}
	if test.Acceptable != nil {
		for _, when := range test.Acceptable.When {
			if !validWhenTokens[when] {
				return fmt.Errorf("acceptable.when: invalid token %q (must be an environment type or profile name)", when)
			}
		}
	}

	return nil
}

// formatValidationErrors converts validator errors into user-friendly messages.
func formatValidationErrors(err error) error {
	validationErrors, ok := err.(validator.ValidationErrors)
	if !ok {
		return err
	}

	var messages []string
	for _, fe := range validationErrors {
		msg := formatFieldError(fe)
		messages = append(messages, msg)
	}

	return fmt.Errorf("validation failed: %s", strings.Join(messages, "; "))
}

// formatFieldError converts a single field validation error to a human-readable message.
func formatFieldError(fe validator.FieldError) string {
	field := fe.Field()

	switch fe.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", field)
	case "min":
		if fe.Type().Kind().String() == "string" {
			return fmt.Sprintf("%s must be at least %s characters", field, fe.Param())
		}
		return fmt.Sprintf("%s must have at least %s entries", field, fe.Param())
	case "max":
		return fmt.Sprintf("%s must be at most %s characters", field, fe.Param())
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", field, fe.Param())
	case "url":
		return fmt.Sprintf("%s must be a valid URL", field)
	case "sesha_id":
		return fmt.Sprintf("%s must be alphanumeric with underscores and hyphens only", field)
	default:
		return fmt.Sprintf("%s failed validation: %s", field, fe.Tag())
	}
}

// knownFunctionList returns a comma-separated list of known function names.
func (l *Loader) knownFunctionList() string {
	names := make([]string, 0, len(l.knownFunctions))
	for name := range l.knownFunctions {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
