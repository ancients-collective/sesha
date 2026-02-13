package engine_test

import (
	"testing"

	"github.com/ancients-collective/sesha/internal/engine"
)

// FuzzValidateArgs exercises the allowlist argument validator with random inputs
// to ensure it never panics and always returns a valid error or nil.
func FuzzValidateArgs(f *testing.F) {
	// Seed corpus with interesting edge cases
	f.Add("--flag", 3)
	f.Add("", 1)
	f.Add("\x00", 1)
	f.Add("normal-arg", 5)
	f.Add("-v", 2)
	f.Add("--verbose", 0)
	f.Add("arg with spaces", 10)
	f.Add("/etc/passwd", 1)
	f.Add("../../etc/shadow", 1)
	f.Add("\x00hidden\x00", 3)

	spec := engine.CommandSpec{
		AllowedFlags: []string{"-v", "--verbose", "-n", "--no-heading"},
		MaxArgs:      3,
	}

	f.Fuzz(func(t *testing.T, arg string, maxArgs int) {
		if maxArgs < 0 {
			maxArgs = 0
		}
		if maxArgs > 100 {
			maxArgs = 100
		}
		s := spec
		s.MaxArgs = maxArgs

		// Must not panic; error or nil are both acceptable
		_ = engine.ValidateArgs(s, []string{arg})
	})
}
