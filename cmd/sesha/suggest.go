package main

import (
	"sort"

	"github.com/ancients-collective/sesha/internal/types"
)

// levenshtein computes the edit distance between two strings.
func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	if la < lb {
		a, b = b, a
		la, lb = lb, la
	}

	prev := make([]int, lb+1)
	for j := range prev {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr := make([]int, lb+1)
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			ins := curr[j-1] + 1
			del := prev[j] + 1
			sub := prev[j-1] + cost
			curr[j] = min(ins, del, sub)
		}
		prev = curr
	}
	return prev[lb]
}

// suggestIDs returns up to 3 check IDs closest to the input by edit distance.
func suggestIDs(input string, tests []types.TestDefinition) []string {
	type candidate struct {
		id   string
		dist int
	}

	maxDist := len(input) / 2
	if maxDist < 3 {
		maxDist = 3
	}

	var candidates []candidate
	for _, t := range tests {
		d := levenshtein(input, t.ID)
		if d <= maxDist && d > 0 {
			candidates = append(candidates, candidate{id: t.ID, dist: d})
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].dist != candidates[j].dist {
			return candidates[i].dist < candidates[j].dist
		}
		return candidates[i].id < candidates[j].id
	})

	limit := 3
	if len(candidates) < limit {
		limit = len(candidates)
	}

	result := make([]string, limit)
	for i := 0; i < limit; i++ {
		result[i] = candidates[i].id
	}
	return result
}
