package types

import "time"

// ResultStatus represents the outcome of a check execution.
type ResultStatus string

const (
	// StatusPass means the check's expected condition was met.
	StatusPass ResultStatus = "pass"
	// StatusFail means the check's expected condition was not met.
	StatusFail ResultStatus = "fail"
	// StatusSkip means the check was not applicable and was skipped.
	StatusSkip ResultStatus = "skip"
	// StatusError means the check encountered an error during execution.
	StatusError ResultStatus = "error"
	// StatusAccepted means the check failed but the failure is acceptable in context.
	StatusAccepted ResultStatus = "accepted"
)

// TestResult holds the outcome of running a single check.
type TestResult struct {
	// ID is the unique check identifier.
	ID string `json:"id"`

	// Name is the human-readable check name.
	Name string `json:"name"`

	// Category is the check's category.
	Category string `json:"category"`

	// Severity is the effective severity after any context overrides.
	Severity string `json:"severity"`

	// OriginalSeverity is the severity before any context overrides.
	OriginalSeverity string `json:"original_severity,omitempty"`

	// Status is the check result.
	Status ResultStatus `json:"status"`

	// Message provides detail about the result.
	Message string `json:"message,omitempty"`

	// AcceptedReason explains why a fail was accepted, when Status is StatusAccepted.
	AcceptedReason string `json:"accepted_reason,omitempty"`

	// ContextNote is an environment-specific note included when relevant.
	ContextNote string `json:"context_note,omitempty"`

	// FilePath is the file path related to the check, if applicable.
	FilePath string `json:"file_path,omitempty"`

	// Duration is how long the check took to execute (not serialized to JSON).
	Duration time.Duration `json:"-"`

	// DurationMS is the duration in milliseconds for JSON serialization.
	DurationMS int64 `json:"duration_ms"`

	// Description is the check's description.
	Description string `json:"description,omitempty"`

	// Impact describes attacker advantage if the check fails.
	Impact string `json:"impact,omitempty"`

	// Explain is the plain-language explanation.
	Explain string `json:"explain,omitempty"`

	// BreakRisk describes what might break when applying the fix.
	BreakRisk string `json:"break_risk,omitempty"`

	// Likelihood estimates exploitation probability.
	Likelihood string `json:"likelihood,omitempty"`

	// References lists related URLs.
	References []string `json:"references,omitempty"`

	// Remediation describes how to fix the finding.
	Remediation string `json:"remediation,omitempty"`

	// Author identifies who created or maintains the check.
	Author string `json:"author,omitempty"`

	// Version is the version of the check definition.
	Version string `json:"version,omitempty"`

	// Tags are freeform labels for filtering and organization.
	Tags []string `json:"tags,omitempty"`
}
