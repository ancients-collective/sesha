package engine

import (
	"fmt"
	"strings"

	"github.com/ancients-collective/sesha/internal/types"
)

// ShouldSkip determines if a check should be skipped based on system context.
// All specified filters must match (AND logic). Empty filters are ignored.
// Returns skip=true with a reason if the check is not applicable.
func ShouldSkip(test types.TestDefinition, ctx types.SystemContext) (skip bool, reason string) {
	// Check OS filter
	if len(test.SupportedOS) > 0 && !contains(test.SupportedOS, ctx.OS.Name) {
		return true, fmt.Sprintf("OS %q not in supported list [%s]",
			ctx.OS.Name, strings.Join(test.SupportedOS, ", "))
	}

	// Check distro filter
	if len(test.RequiredDistro) > 0 && !contains(test.RequiredDistro, ctx.Distro.ID) {
		return true, fmt.Sprintf("distro %q not in required list [%s]",
			ctx.Distro.ID, strings.Join(test.RequiredDistro, ", "))
	}

	// Check environment filter
	if test.Environment != "" && test.Environment != ctx.Environment.Type {
		return true, fmt.Sprintf("environment %q does not match required %q",
			ctx.Environment.Type, test.Environment)
	}

	// Check intent profile filter
	// Empty profiles = universal (runs for all profiles).
	// Non-empty profiles = check only runs when the active profile is in the list.
	if len(test.Profiles) > 0 && ctx.IntentProfile != "" && !contains(test.Profiles, ctx.IntentProfile) {
		return true, fmt.Sprintf("profile %q not in check's profiles [%s]",
			ctx.IntentProfile, strings.Join(test.Profiles, ", "))
	}

	return false, ""
}

// EvaluateCondition checks if a step's condition matches the system context.
// All specified fields must match (AND logic). Nil or empty condition = always true.
func EvaluateCondition(cond *types.ConditionBlock, ctx types.SystemContext) bool {
	if cond == nil {
		return true
	}

	if cond.OS != "" && cond.OS != ctx.OS.Name {
		return false
	}

	if cond.Distro != "" && cond.Distro != ctx.Distro.ID {
		return false
	}

	if cond.Environment != "" && cond.Environment != ctx.Environment.Type {
		return false
	}

	return true
}

// contains checks if a string is in a slice.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
