package main

import (
	"testing"

	"github.com/ancients-collective/sesha/internal/types"
	"github.com/stretchr/testify/assert"
)

// ── levenshtein tests ────────────────────────────────────────────────

func TestLevenshtein_IdenticalStrings(t *testing.T) {
	assert.Equal(t, 0, levenshtein("abc", "abc"))
}

func TestLevenshtein_EmptyStrings(t *testing.T) {
	assert.Equal(t, 0, levenshtein("", ""))
	assert.Equal(t, 3, levenshtein("abc", ""))
	assert.Equal(t, 3, levenshtein("", "abc"))
}

func TestLevenshtein_SingleEdit(t *testing.T) {
	assert.Equal(t, 1, levenshtein("cat", "car"))  // substitution
	assert.Equal(t, 1, levenshtein("cat", "cats")) // insertion
	assert.Equal(t, 1, levenshtein("cats", "cat")) // deletion
}

func TestLevenshtein_MultipleEdits(t *testing.T) {
	assert.Equal(t, 3, levenshtein("kitten", "sitting"))
}

func TestLevenshtein_CompletelyDifferent(t *testing.T) {
	assert.Equal(t, 3, levenshtein("abc", "xyz"))
}

func TestLevenshtein_Symmetric(t *testing.T) {
	assert.Equal(t, levenshtein("abc", "def"), levenshtein("def", "abc"))
}

// ── suggestIDs tests ─────────────────────────────────────────────────

func TestSuggestIDs_CloseMatch(t *testing.T) {
	tests := []types.TestDefinition{
		{ID: "ssh_root_login"},
		{ID: "ssh_protocol"},
		{ID: "firewall_active"},
		{ID: "passwd_exists"},
	}

	suggestions := suggestIDs("ssh_root_logn", tests) // one char off
	assert.NotEmpty(t, suggestions)
	assert.Contains(t, suggestions, "ssh_root_login")
}

func TestSuggestIDs_NoMatch(t *testing.T) {
	tests := []types.TestDefinition{
		{ID: "ssh_root_login"},
		{ID: "ssh_protocol"},
	}

	// Completely different string
	suggestions := suggestIDs("zzzzzzzzzzzzzzzzzzz", tests)
	assert.Empty(t, suggestions)
}

func TestSuggestIDs_MaxThree(t *testing.T) {
	tests := []types.TestDefinition{
		{ID: "aaa"},
		{ID: "aab"},
		{ID: "aac"},
		{ID: "aad"},
		{ID: "aae"},
	}

	suggestions := suggestIDs("aax", tests)
	assert.LessOrEqual(t, len(suggestions), 3)
}

func TestSuggestIDs_ExactMatchExcluded(t *testing.T) {
	tests := []types.TestDefinition{
		{ID: "ssh_root_login"},
	}

	// Exact match has distance 0 and should be excluded (d > 0 check)
	suggestions := suggestIDs("ssh_root_login", tests)
	assert.Empty(t, suggestions)
}

func TestSuggestIDs_SortedByDistance(t *testing.T) {
	tests := []types.TestDefinition{
		{ID: "ssh_protocol"},   // distance 9 from input
		{ID: "ssh_root_login"}, // distance 1 from input
		{ID: "ssh_root_logon"}, // distance 2 from input
	}

	suggestions := suggestIDs("ssh_root_logn", tests)
	if len(suggestions) >= 2 {
		// Closest should come first
		d1 := levenshtein("ssh_root_logn", suggestions[0])
		d2 := levenshtein("ssh_root_logn", suggestions[1])
		assert.LessOrEqual(t, d1, d2)
	}
}

func TestSuggestIDs_EmptyInput(t *testing.T) {
	tests := []types.TestDefinition{
		{ID: "ab"},
		{ID: "abc"},
	}

	// maxDist = max(len("")/2, 3) = 3
	suggestions := suggestIDs("", tests)
	// "ab" has distance 2, "abc" has distance 3 → both within maxDist
	assert.NotEmpty(t, suggestions)
}

func TestSuggestIDs_EmptyTests(t *testing.T) {
	suggestions := suggestIDs("ssh_root_login", nil)
	assert.Empty(t, suggestions)
}
