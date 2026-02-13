package engine

import (
	"testing"

	"github.com/ancients-collective/sesha/internal/types"
	"github.com/stretchr/testify/assert"
)

func TestShouldSkip_MatchingOS(t *testing.T) {
	test := types.TestDefinition{SupportedOS: []string{"linux"}}
	ctx := types.SystemContext{OS: types.OSInfo{Name: "linux"}}

	skip, reason := ShouldSkip(test, ctx)

	assert.False(t, skip)
	assert.Empty(t, reason)
}

func TestShouldSkip_WrongOS(t *testing.T) {
	test := types.TestDefinition{SupportedOS: []string{"linux"}}
	ctx := types.SystemContext{OS: types.OSInfo{Name: "darwin"}}

	skip, reason := ShouldSkip(test, ctx)

	assert.True(t, skip)
	assert.Contains(t, reason, "darwin")
	assert.Contains(t, reason, "linux")
}

func TestShouldSkip_MultipleOS(t *testing.T) {
	test := types.TestDefinition{SupportedOS: []string{"linux", "darwin"}}
	ctx := types.SystemContext{OS: types.OSInfo{Name: "darwin"}}

	skip, _ := ShouldSkip(test, ctx)
	assert.False(t, skip)
}

func TestShouldSkip_NoOSFilter(t *testing.T) {
	test := types.TestDefinition{}
	ctx := types.SystemContext{OS: types.OSInfo{Name: "linux"}}

	skip, _ := ShouldSkip(test, ctx)
	assert.False(t, skip)
}

func TestShouldSkip_MatchingDistro(t *testing.T) {
	test := types.TestDefinition{RequiredDistro: []string{"ubuntu", "debian"}}
	ctx := types.SystemContext{Distro: types.DistroInfo{ID: "ubuntu"}}

	skip, _ := ShouldSkip(test, ctx)
	assert.False(t, skip)
}

func TestShouldSkip_WrongDistro(t *testing.T) {
	test := types.TestDefinition{RequiredDistro: []string{"ubuntu", "debian"}}
	ctx := types.SystemContext{Distro: types.DistroInfo{ID: "rhel"}}

	skip, reason := ShouldSkip(test, ctx)

	assert.True(t, skip)
	assert.Contains(t, reason, "rhel")
}

func TestShouldSkip_MatchingEnvironment(t *testing.T) {
	test := types.TestDefinition{Environment: "container"}
	ctx := types.SystemContext{Environment: types.EnvInfo{Type: "container"}}

	skip, _ := ShouldSkip(test, ctx)
	assert.False(t, skip)
}

func TestShouldSkip_WrongEnvironment(t *testing.T) {
	test := types.TestDefinition{Environment: "container"}
	ctx := types.SystemContext{Environment: types.EnvInfo{Type: "bare-metal"}}

	skip, reason := ShouldSkip(test, ctx)

	assert.True(t, skip)
	assert.Contains(t, reason, "bare-metal")
}

func TestShouldSkip_MatchingProfile(t *testing.T) {
	test := types.TestDefinition{Profiles: []string{"server"}}
	ctx := types.SystemContext{IntentProfile: "server"}

	skip, _ := ShouldSkip(test, ctx)
	assert.False(t, skip)
}

func TestShouldSkip_WrongProfile(t *testing.T) {
	test := types.TestDefinition{Profiles: []string{"server"}}
	ctx := types.SystemContext{IntentProfile: "workstation"}

	skip, reason := ShouldSkip(test, ctx)

	assert.True(t, skip)
	assert.Contains(t, reason, "workstation")
	assert.Contains(t, reason, "server")
}

func TestShouldSkip_MultipleProfiles(t *testing.T) {
	test := types.TestDefinition{Profiles: []string{"server", "workstation"}}
	ctx := types.SystemContext{IntentProfile: "workstation"}

	skip, _ := ShouldSkip(test, ctx)
	assert.False(t, skip)
}

func TestShouldSkip_MultipleProfiles_NoMatch(t *testing.T) {
	test := types.TestDefinition{Profiles: []string{"server", "workstation"}}
	ctx := types.SystemContext{IntentProfile: "container"}

	skip, reason := ShouldSkip(test, ctx)
	assert.True(t, skip)
	assert.Contains(t, reason, "container")
}

func TestShouldSkip_EmptyProfiles_Universal(t *testing.T) {
	test := types.TestDefinition{}
	ctx := types.SystemContext{IntentProfile: "container"}

	skip, _ := ShouldSkip(test, ctx)
	assert.False(t, skip)
}

func TestShouldSkip_ProfileAll_BypassesFilter(t *testing.T) {
	test := types.TestDefinition{Profiles: []string{"server"}}
	ctx := types.SystemContext{IntentProfile: ""}

	skip, _ := ShouldSkip(test, ctx)
	assert.False(t, skip)
}

func TestShouldSkip_NoFilters(t *testing.T) {
	test := types.TestDefinition{}
	ctx := types.SystemContext{
		OS:            types.OSInfo{Name: "linux"},
		Distro:        types.DistroInfo{ID: "ubuntu"},
		Environment:   types.EnvInfo{Type: "container"},
		IntentProfile: "server",
	}

	skip, _ := ShouldSkip(test, ctx)
	assert.False(t, skip)
}

func TestShouldSkip_MultipleFiltersAND(t *testing.T) {
	test := types.TestDefinition{
		SupportedOS:    []string{"linux"},
		RequiredDistro: []string{"ubuntu"},
	}

	ctx := types.SystemContext{
		OS:     types.OSInfo{Name: "linux"},
		Distro: types.DistroInfo{ID: "rhel"},
	}

	skip, _ := ShouldSkip(test, ctx)
	assert.True(t, skip)
}

func TestEvaluateCondition_EmptyCondition(t *testing.T) {
	cond := &types.ConditionBlock{}
	ctx := types.SystemContext{OS: types.OSInfo{Name: "linux"}}

	assert.True(t, EvaluateCondition(cond, ctx))
}

func TestEvaluateCondition_NilCondition(t *testing.T) {
	ctx := types.SystemContext{OS: types.OSInfo{Name: "linux"}}
	assert.True(t, EvaluateCondition(nil, ctx))
}

func TestEvaluateCondition_MatchingOS(t *testing.T) {
	cond := &types.ConditionBlock{OS: "linux"}
	ctx := types.SystemContext{OS: types.OSInfo{Name: "linux"}}

	assert.True(t, EvaluateCondition(cond, ctx))
}

func TestEvaluateCondition_NonMatchingOS(t *testing.T) {
	cond := &types.ConditionBlock{OS: "linux"}
	ctx := types.SystemContext{OS: types.OSInfo{Name: "darwin"}}

	assert.False(t, EvaluateCondition(cond, ctx))
}

func TestEvaluateCondition_MatchingDistro(t *testing.T) {
	cond := &types.ConditionBlock{Distro: "ubuntu"}
	ctx := types.SystemContext{Distro: types.DistroInfo{ID: "ubuntu"}}

	assert.True(t, EvaluateCondition(cond, ctx))
}

func TestEvaluateCondition_NonMatchingDistro(t *testing.T) {
	cond := &types.ConditionBlock{Distro: "ubuntu"}
	ctx := types.SystemContext{Distro: types.DistroInfo{ID: "rhel"}}

	assert.False(t, EvaluateCondition(cond, ctx))
}

func TestEvaluateCondition_MatchingEnvironment(t *testing.T) {
	cond := &types.ConditionBlock{Environment: "container"}
	ctx := types.SystemContext{Environment: types.EnvInfo{Type: "container"}}

	assert.True(t, EvaluateCondition(cond, ctx))
}

func TestEvaluateCondition_NonMatchingEnvironment(t *testing.T) {
	cond := &types.ConditionBlock{Environment: "container"}
	ctx := types.SystemContext{Environment: types.EnvInfo{Type: "bare-metal"}}

	assert.False(t, EvaluateCondition(cond, ctx))
}

func TestEvaluateCondition_MultipleFieldsAND(t *testing.T) {
	cond := &types.ConditionBlock{OS: "linux", Distro: "ubuntu"}

	ctx1 := types.SystemContext{
		OS:     types.OSInfo{Name: "linux"},
		Distro: types.DistroInfo{ID: "ubuntu"},
	}
	assert.True(t, EvaluateCondition(cond, ctx1))

	ctx2 := types.SystemContext{
		OS:     types.OSInfo{Name: "linux"},
		Distro: types.DistroInfo{ID: "rhel"},
	}
	assert.False(t, EvaluateCondition(cond, ctx2))
}
