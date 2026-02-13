package engine

import (
	"time"

	"github.com/ancients-collective/sesha/internal/types"
)

// Executor runs TestDefinitions against a SystemContext using a FunctionRegistry.
type Executor struct {
	registry *FunctionRegistry
	ctx      types.SystemContext

	// ForceRun bypasses ShouldSkip filtering (used by --id).
	// When true, checks that would normally be skipped still execute.
	ForceRun bool
}

// NewExecutor creates an Executor with the given function registry and system context.
func NewExecutor(registry *FunctionRegistry, ctx types.SystemContext) *Executor {
	return &Executor{
		registry: registry,
		ctx:      ctx,
	}
}

// RunTest executes a single TestDefinition and returns the result.
// It checks if the test should be skipped based on context, iterates steps
// with conditional logic, applies context-aware evaluation, and produces a TestResult.
func (e *Executor) RunTest(test types.TestDefinition) types.TestResult {
	start := time.Now()

	result := types.TestResult{
		ID:          test.ID,
		Name:        test.Name,
		Severity:    test.Severity,
		Category:    test.Category,
		Remediation: test.Remediation,
		Impact:      test.Impact,
		Explain:     test.Explain,
		BreakRisk:   test.BreakRisk,
		Likelihood:  test.Likelihood,
		References:  test.References,
		Description: test.Description,
		FilePath:    extractFilePath(test),
		Author:      test.Author,
		Version:     test.Version,
		Tags:        test.Tags,
	}

	// Check if the test should be skipped based on context
	if skip, reason := ShouldSkip(test, e.ctx); skip {
		if !e.ForceRun {
			result.Status = types.StatusSkip
			result.Message = reason
			result.Duration = time.Since(start)
			return result
		}
	}

	// Execute steps
	stepsExecuted := 0

	for _, step := range test.Steps {
		if !EvaluateCondition(step.When, e.ctx) {
			continue
		}

		pass, detail, err := e.registry.Call(step.Function, step.Args)
		stepsExecuted++

		if err != nil {
			result.Status = types.StatusError
			result.Message = err.Error()
			result.Duration = time.Since(start)
			return result
		}

		if !pass {
			result.Status = types.StatusFail
			result.Message = detail
			e.applyContextAwareness(&result, test)
			result.Duration = time.Since(start)
			return result
		}
	}

	if stepsExecuted == 0 {
		result.Status = types.StatusSkip
		result.Message = "no steps executed: all steps were skipped by conditions"
		result.Duration = time.Since(start)
		return result
	}

	// All executed steps passed
	result.Status = types.StatusPass
	e.applyContextOverrides(&result, test)
	result.Duration = time.Since(start)
	return result
}

// applyContextAwareness applies context-aware evaluation to a failing result.
// Handles severity overrides, context notes, and acceptable blocks.
func (e *Executor) applyContextAwareness(result *types.TestResult, test types.TestDefinition) {
	// 1. Apply severity overrides and context notes
	e.applyContextOverrides(result, test)

	// 2. Check if the failure is acceptable in this context
	if test.Acceptable != nil && e.matchesAcceptable(test.Acceptable) {
		result.Status = types.StatusAccepted
		result.AcceptedReason = test.Acceptable.Reason
	}
}

// applyContextOverrides applies severity overrides and context notes based on the current context.
func (e *Executor) applyContextOverrides(result *types.TestResult, test types.TestDefinition) {
	if len(test.SeverityOverrides) > 0 {
		if sev, ok := test.SeverityOverrides[e.ctx.Environment.Type]; ok {
			result.OriginalSeverity = result.Severity
			result.Severity = sev
		} else if sev, ok := test.SeverityOverrides[e.ctx.IntentProfile]; ok {
			result.OriginalSeverity = result.Severity
			result.Severity = sev
		}
	}

	if len(test.ContextNotes) > 0 {
		if note, ok := test.ContextNotes[e.ctx.Environment.Type]; ok {
			result.ContextNote = note
		} else if note, ok := test.ContextNotes[e.ctx.IntentProfile]; ok {
			result.ContextNote = note
		}
	}
}

// matchesAcceptable checks if the current context matches any of the acceptable conditions.
func (e *Executor) matchesAcceptable(acceptable *types.AcceptableBlock) bool {
	for _, when := range acceptable.When {
		if when == e.ctx.Environment.Type || when == e.ctx.IntentProfile {
			return true
		}
	}
	return false
}

// extractFilePath extracts the primary file path from a test definition's steps.
func extractFilePath(test types.TestDefinition) string {
	for _, step := range test.Steps {
		if p, ok := step.Args["path"]; ok {
			if s, ok := p.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}
