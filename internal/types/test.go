// Package types defines shared type definitions used across all sesha packages.
package types

// TestDefinition represents a single security check loaded from a YAML file.
// Each check is atomic and self-contained with metadata, steps, and filtering criteria.
type TestDefinition struct {
	// ID is a unique identifier for the check (alphanumeric, underscores, hyphens).
	ID string `yaml:"id" validate:"required,sesha_id"`

	// Name is a human-readable name for the check.
	Name string `yaml:"name" validate:"required,min=3,max=100"`

	// Author identifies who created or maintains the check.
	Author string `yaml:"author,omitempty"`

	// Version is the version of the check definition (e.g., "1.0").
	Version string `yaml:"version,omitempty"`

	// Description explains what the check verifies and why it matters.
	Description string `yaml:"description" validate:"required"`

	// Severity indicates the importance of a finding (info, low, medium, high, critical).
	Severity string `yaml:"severity" validate:"required,oneof=info low medium high critical"`

	// Category groups related checks (e.g., "file-permissions", "ssh", "firewall").
	Category string `yaml:"category" validate:"required"`

	// SupportedOS limits which operating systems this check applies to.
	SupportedOS []string `yaml:"supported_os,omitempty" validate:"omitempty,dive,oneof=linux darwin"`

	// RequiredDistro limits which Linux distributions this check applies to.
	RequiredDistro []string `yaml:"required_distro,omitempty"`

	// Environment limits which execution environments this check applies to.
	Environment string `yaml:"environment,omitempty" validate:"omitempty,oneof=container vm bare-metal"`

	// Profiles lists the intent profiles this check applies to.
	// Valid values: "server", "workstation", "container".
	// If empty, the check applies to all profiles (universal).
	Profiles []string `yaml:"profiles,omitempty" validate:"omitempty,dive,oneof=server workstation container"`

	// Steps are the ordered actions the check performs.
	Steps []TestStep `yaml:"steps" validate:"required,min=1,dive"`

	// Requirements describes privilege and environmental prerequisites for this check.
	Requirements *Requirements `yaml:"requirements,omitempty"`

	// Impact describes what an attacker gains if this check fails.
	Impact string `yaml:"impact,omitempty"`

	// Explain describes *why* this matters in plain language (shown with --explain).
	Explain string `yaml:"explain,omitempty"`

	// BreakRisk describes what might break if the recommended fix is applied.
	BreakRisk string `yaml:"break_risk,omitempty"`

	// Likelihood estimates how likely this misconfiguration is to be exploited.
	// Values: "certain", "likely", "possible", "unlikely".
	Likelihood string `yaml:"likelihood,omitempty" validate:"omitempty,oneof=certain likely possible unlikely"`

	// ContextNotes provides environment-specific explanations keyed by environment type.
	// Example: {"container": "Less relevant in ephemeral containers"}.
	ContextNotes map[string]string `yaml:"context_notes,omitempty"`

	// SeverityOverrides allows changing effective severity per environment or profile.
	// Keys are environment types or profile names, values are severity levels.
	// Example: {"container": "low", "workstation": "medium"}.
	SeverityOverrides map[string]string `yaml:"severity_overrides,omitempty"`

	// Acceptable defines conditions under which a failing check is considered acceptable.
	Acceptable *AcceptableBlock `yaml:"acceptable,omitempty"`

	// Tags are optional labels for filtering and organization.
	Tags []string `yaml:"tags,omitempty"`

	// References are URLs to documentation or standards related to this check.
	References []string `yaml:"references,omitempty" validate:"omitempty,dive,url"`

	// Remediation describes how to fix a finding from this check.
	Remediation string `yaml:"remediation" validate:"required"`
}

// AcceptableBlock defines conditions under which a failing check is considered acceptable risk.
type AcceptableBlock struct {
	// When lists the contexts where this fail is acceptable.
	// Values can be environment types ("container", "vm") or profiles ("workstation").
	When []string `yaml:"when" validate:"required,min=1"`

	// Reason explains why this is considered acceptable in those contexts.
	Reason string `yaml:"reason" validate:"required"`
}

// Requirements describes privilege and environmental prerequisites for a check.
type Requirements struct {
	// Privilege indicates the privilege level needed for full functionality.
	// Values: "standard" (works as any user), "elevated" (some steps need root),
	// "root" (requires root or specific capabilities).
	Privilege string `yaml:"privilege" validate:"required,oneof=standard elevated root"`

	// Note is a concise explanation of what specifically requires elevated privileges.
	Note string `yaml:"note,omitempty"`
}

// TestStep represents a single action within a check.
// Each step calls a built-in function with arguments and optional conditions.
type TestStep struct {
	// Function is the name of the built-in function to call (e.g., "file_exists").
	Function string `yaml:"function" validate:"required"`

	// Args are the arguments passed to the function.
	Args map[string]interface{} `yaml:"args" validate:"required"`

	// When specifies conditions under which this step should execute.
	// If the condition does not match the current system context, the step is skipped.
	When *ConditionBlock `yaml:"when,omitempty"`
}

// ConditionBlock defines platform/context conditions for conditional step execution.
// All specified fields must match (AND logic). Empty fields are ignored.
type ConditionBlock struct {
	// OS matches the operating system name (e.g., "linux", "darwin").
	OS string `yaml:"os,omitempty"`

	// Distro matches the Linux distribution ID (e.g., "ubuntu", "rhel").
	Distro string `yaml:"distro,omitempty"`

	// Environment matches the execution environment type (e.g., "container", "vm").
	Environment string `yaml:"environment,omitempty"`
}
