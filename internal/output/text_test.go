package output

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/ancients-collective/sesha/internal/types"
	"github.com/fatih/color"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Disable color for deterministic test output.
	color.NoColor = true
}

func renderText(t *testing.T, report *types.ScanReport, opts ...func(*TextFormatter)) string {
	t.Helper()
	f := &TextFormatter{Show: report.Filters.Show}
	for _, opt := range opts {
		opt(f)
	}
	var buf bytes.Buffer
	require.NoError(t, f.Write(&buf, report))
	return buf.String()
}

// ─── Full Write tests ────────────────────────────────────────────────

func TestTextFormatter_Write_CleanScan(t *testing.T) {
	out := renderText(t, newCleanReport())

	assert.Contains(t, out, "Clean")
	assert.Contains(t, out, "2 passed")
	assert.Contains(t, out, "0 failed")
	assert.NotContains(t, out, "Findings")
}

func TestTextFormatter_Write_WithFindings(t *testing.T) {
	out := renderText(t, newTestReport())

	assert.Contains(t, out, "[CRIT]")
	assert.Contains(t, out, "SSH Root Login Disabled")
	assert.Contains(t, out, "Findings")
	assert.Contains(t, out, "Check:")
	assert.Contains(t, out, "Result:")
	assert.Contains(t, out, "Set PermitRootLogin to no")
	assert.Contains(t, out, "2 failed")
}

func TestTextFormatter_Write_FindingsSortedBySeverity(t *testing.T) {
	out := renderText(t, newTestReport())

	// critical finding (SSH Root Login) should appear before low finding (Shadow perms)
	critIdx := strings.Index(out, "SSH Root Login Disabled")
	lowIdx := strings.Index(out, "Shadow file permissions")

	if critIdx == -1 || lowIdx == -1 {
		t.Fatal("expected both findings to appear in output")
	}
	assert.Less(t, critIdx, lowIdx, "critical finding should appear before low-severity finding")
}

func TestTextFormatter_Write_ExplainMode(t *testing.T) {
	out := renderText(t, newTestReport(), func(f *TextFormatter) {
		f.Explain = true
	})

	assert.Contains(t, out, "Impact:")
	assert.Contains(t, out, "Attacker can brute-force root password")
	assert.Contains(t, out, "Why:")
	assert.Contains(t, out, "Root login via SSH is dangerous")
	assert.Contains(t, out, "Risk:")
	assert.Contains(t, out, "May lock out users")
}

func TestTextFormatter_Write_NoExplainByDefault(t *testing.T) {
	out := renderText(t, newTestReport())

	assert.NotContains(t, out, "Impact:")
	assert.NotContains(t, out, "Why:")
	assert.NotContains(t, out, "Risk:")
}

func TestTextFormatter_Write_SeverityOverrideBadge(t *testing.T) {
	out := renderText(t, newTestReport())

	// Shadow file permissions has OriginalSeverity=high, Severity=low -> arrow badge
	assert.Contains(t, out, ">")
	assert.Contains(t, out, "HIGH")
	assert.Contains(t, out, "LOW")
}

func TestTextFormatter_Write_AcceptedResult(t *testing.T) {
	report := newAcceptedReport()
	out := renderText(t, report)

	assert.Contains(t, out, "Containers use exec/attach instead of SSH")
	assert.Contains(t, out, "SSH is typically not needed inside containers")
}

func TestTextFormatter_Write_DumbTerminal(t *testing.T) {
	report := newTestReport()
	report.Filters.Show = "all"
	out := renderText(t, report, func(f *TextFormatter) {
		f.Dumb = true
		f.Show = "all"
	})

	// Dumb mode uses ASCII icons
	assert.Contains(t, out, "+")  // pass
	assert.Contains(t, out, "x")  // fail
}

func TestTextFormatter_Write_ShowAll(t *testing.T) {
	report := newTestReport()
	report.Filters.Show = "all"
	out := renderText(t, report, func(f *TextFormatter) {
		f.Show = "all"
	})

	assert.Contains(t, out, "Results")
	assert.Contains(t, out, "Password file exists") // pass result
	assert.Contains(t, out, "SSH Root Login Disabled") // fail result

	// Without --explain, no extended detail in --show all
	assert.NotContains(t, out, "Impact:")

	// Result: and Fix: labels should always appear
	assert.Contains(t, out, "Result:")
	assert.Contains(t, out, "Fix:")
}

func TestTextFormatter_Write_ShowAllExplain(t *testing.T) {
	report := newTestReport()
	report.Filters.Show = "all"
	out := renderText(t, report, func(f *TextFormatter) {
		f.Show = "all"
		f.Explain = true
	})

	// Passing check should show explain fields
	assert.Contains(t, out, "Without /etc/passwd, user authentication breaks entirely")
	assert.Contains(t, out, "The passwd file maps usernames to UIDs")
	assert.Contains(t, out, "No risk")

	// Failing check should show Result: label and Fix:
	assert.Contains(t, out, "Result:")
	assert.Contains(t, out, "Fix:")

	// Impact/Why/Risk should appear for all non-skip checks
	assert.Contains(t, out, "Impact:")
	assert.Contains(t, out, "Why:")
	assert.Contains(t, out, "Risk:")
}

func TestTextFormatter_Write_NonRootWarning(t *testing.T) {
	report := newCleanReport()
	report.System.IsRoot = false
	out := renderText(t, report)

	assert.Contains(t, out, "non-root")
}

func TestTextFormatter_Write_Wrapping(t *testing.T) {
	report := newTestReport()
	report.Filters.Show = "all"
	out := renderText(t, report, func(f *TextFormatter) {
		f.Width = 60
		f.Show = "all"
	})

	// Output should not crash and should produce reasonable output
	assert.NotEmpty(t, out)
	assert.Contains(t, out, "Catch drift, not feelings")
}

func TestTextFormatter_Write_Hints(t *testing.T) {
	out := renderText(t, newTestReport())

	assert.Contains(t, out, "--explain")
	assert.Contains(t, out, "--show all")
}

// ─── Unit tests for individual helpers ───────────────────────────────

func TestSortResults(t *testing.T) {
	f := &TextFormatter{}
	results := []types.TestResult{
		{Name: "C", Severity: "low", Category: "bb"},
		{Name: "A", Severity: "critical", Category: "aa"},
		{Name: "B", Severity: "high", Category: "aa"},
		{Name: "D", Severity: "critical", Category: "bb"},
	}

	sorted := f.sortResults(results)

	assert.Equal(t, "A", sorted[0].Name, "critical/aa first")
	assert.Equal(t, "D", sorted[1].Name, "critical/bb second")
	assert.Equal(t, "B", sorted[2].Name, "high/aa third")
	assert.Equal(t, "C", sorted[3].Name, "low/bb last")
}

func TestIcon_DumbVsUnicode(t *testing.T) {
	f := &TextFormatter{Dumb: false}
	assert.Equal(t, "✓", f.icon("pass"))
	assert.Equal(t, "✗", f.icon("fail"))
	assert.Equal(t, "○", f.icon("skip"))
	assert.Equal(t, "⚠", f.icon("warn"))
	assert.Equal(t, "≋", f.icon("accepted"))

	fd := &TextFormatter{Dumb: true}
	assert.Equal(t, "+", fd.icon("pass"))
	assert.Equal(t, "x", fd.icon("fail"))
	assert.Equal(t, "-", fd.icon("skip"))
	assert.Equal(t, "!", fd.icon("warn"))
	assert.Equal(t, "~", fd.icon("accepted"))
}

func TestSeverityBadgeRaw(t *testing.T) {
	assert.Equal(t, "[CRIT]", severityBadgeRaw("critical"))
	assert.Equal(t, "[HIGH]", severityBadgeRaw("high"))
	assert.Equal(t, "[MED]", severityBadgeRaw("medium"))
	assert.Equal(t, "[LOW]", severityBadgeRaw("low"))
	assert.Equal(t, "[INFO]", severityBadgeRaw("info"))
	assert.Equal(t, "[----]", severityBadgeRaw("unknown"))
}

func TestSeverityAbbrev(t *testing.T) {
	assert.Equal(t, "CRIT", severityAbbrev("critical"))
	assert.Equal(t, "HIGH", severityAbbrev("high"))
	assert.Equal(t, "MED", severityAbbrev("medium"))
	assert.Equal(t, "LOW", severityAbbrev("low"))
	assert.Equal(t, "INFO", severityAbbrev("info"))
	assert.Equal(t, "CUSTOM", severityAbbrev("custom"))
}

func TestDurationRaw(t *testing.T) {
	f := &TextFormatter{}

	r0 := types.TestResult{DurationMS: 0}
	assert.Equal(t, "(<1ms)", f.durationRaw(r0))

	r5 := types.TestResult{DurationMS: 5}
	assert.Equal(t, "(5ms)", f.durationRaw(r5))

	r100 := types.TestResult{DurationMS: 100}
	assert.Equal(t, "(100ms)", f.durationRaw(r100))
}

func TestColPad(t *testing.T) {
	assert.Equal(t, "", colPad(0))
	assert.Equal(t, "    ", colPad(4))
	assert.Equal(t, "          ", colPad(10))
}

func TestWrapWidth(t *testing.T) {
	f := &TextFormatter{Width: 0}
	assert.Equal(t, maxLine, f.wrapWidth())

	f.Width = 80
	assert.Equal(t, 80, f.wrapWidth())

	f.Width = 200
	assert.Equal(t, maxLine, f.wrapWidth())
}

func TestWrap_ShortText(t *testing.T) {
	f := &TextFormatter{Width: 80}
	result := f.wrap("short text", 10, 10)
	assert.Equal(t, "short text", result)
}

func TestWrap_LongText(t *testing.T) {
	f := &TextFormatter{Width: 40}
	longText := "this is a very long text that should be wrapped at the terminal width boundary"
	result := f.wrap(longText, 10, 10)
	assert.Contains(t, result, "\n")
}

func TestIsDumbTerm(t *testing.T) {
	orig := os.Getenv("TERM")
	defer func() { os.Setenv("TERM", orig) }()

	os.Setenv("TERM", "dumb")
	assert.True(t, IsDumbTerm())

	os.Setenv("TERM", "xterm-256color")
	assert.False(t, IsDumbTerm())

	os.Setenv("TERM", "")
	assert.False(t, IsDumbTerm())
}

func TestExtractFindings(t *testing.T) {
	f := &TextFormatter{}
	report := newTestReport()
	findings := f.extractFindings(report.Results)

	// Should only include fail and error results
	for _, fi := range findings {
		assert.True(t, fi.Status == types.StatusFail || fi.Status == types.StatusError,
			"expected fail or error, got %s for %s", fi.Status, fi.ID)
	}

	assert.Equal(t, 2, len(findings), "test report has 2 fail results")
}
