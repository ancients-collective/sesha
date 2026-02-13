package main

import (
	"testing"
)

// FuzzLevenshtein exercises the edit distance function with random string pairs
// to ensure it never panics and always returns a non-negative value.
func FuzzLevenshtein(f *testing.F) {
	f.Add("ssh_port", "ssh_prot")
	f.Add("", "")
	f.Add("abc", "")
	f.Add("", "xyz")
	f.Add("passwd_exists", "password_exists")
	f.Add("a", "a")
	f.Add("kitten", "sitting")

	f.Fuzz(func(t *testing.T, a, b string) {
		d := levenshtein(a, b)
		if d < 0 {
			t.Errorf("levenshtein(%q, %q) = %d, want >= 0", a, b, d)
		}
		// Symmetry property: distance(a,b) == distance(b,a)
		d2 := levenshtein(b, a)
		if d != d2 {
			t.Errorf("levenshtein(%q, %q) = %d but levenshtein(%q, %q) = %d", a, b, d, b, a, d2)
		}
	})
}
