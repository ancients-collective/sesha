package output

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/ancients-collective/sesha/internal/types"
	"github.com/fatih/color"
)

// ─── Layout constants ────────────────────────────────────────────────
//
// Every result line follows a strict column grid:
//
//     col 0    4   6       14      16                          maxLine
//     │margin│ I │ BADGE   │2sp│ CHECK NAME ...           DURATION │
//              ↑   ↑              ↑                              ↑
//           colIcon colBadge    colName                    right-aligned
//
// Detail blocks start at colDetail and use labelWidth-padded labels
// so every value begins at colValue.
//
const (
	colMargin  = 4   // left margin (spaces) for result/detail lines
	colIcon    = 4   // column of the 1-char status icon
	colBadge   = 6   // column where the severity badge starts
	badgeWidth = 8   // visible width of a padded badge, e.g. "[CRIT]  "
	colName    = 16  // column where the check name starts
	colDetail  = 16  // column where detail-block lines start (= colName)
	labelWidth = 9   // fixed label field: "Context: " / "Impact:  " / etc.
	colValue   = 25  // column where label values start (colDetail + labelWidth)
	maxLine    = 110 // hard wrap cap — even on ultra-wide terminals
	ruleWidth  = 64  // width of horizontal divider rules
)

// TextFormatter writes a colored, human-readable scan report.
type TextFormatter struct {
	Explain bool   // show impact/explain/break_risk detail
	Show    string // "findings" (default), "all", "fail", "pass"
	Width   int    // terminal width for text wrapping; 0 = unknown
	Dumb    bool   // TERM=dumb — use single-char ASCII fallback icons
}

// Color helpers — each returns a sprint function.
var (
	cBold   = color.New(color.Bold).SprintFunc()
	cGreen  = color.New(color.FgGreen).SprintFunc()
	cRed    = color.New(color.FgRed).SprintFunc()
	cYellow = color.New(color.FgYellow).SprintFunc()
	cCyan   = color.New(color.FgCyan).SprintFunc()
	cDim    = color.New(color.Faint).SprintFunc()

	cRedBold    = color.New(color.FgRed, color.Bold).SprintFunc()
	cYellowBold = color.New(color.FgYellow, color.Bold).SprintFunc()
	cGreenBold  = color.New(color.FgGreen, color.Bold).SprintFunc()
	cCyanBold   = color.New(color.FgCyan, color.Bold).SprintFunc()
)

// IsDumbTerm returns true when the terminal doesn't support Unicode.
func IsDumbTerm() bool {
	t := os.Getenv("TERM")
	return t == "dumb" || t == ""
}

// wrapWidth returns the effective line width: min(terminal, maxLine).
func (f *TextFormatter) wrapWidth() int {
	if f.Width > 0 && f.Width < maxLine {
		return f.Width
	}
	return maxLine
}

// ─── Public entry point ──────────────────────────────────────────────

// Write renders the full text report.
func (f *TextFormatter) Write(w io.Writer, report *types.ScanReport) error {
	show := f.Show
	if show == "" {
		show = "findings"
	}

	f.writeHeader(w, report)
	f.writeSystem(w, report)
	f.writeLoading(w, report)
	if show != "findings" {
		f.writeResults(w, report)
	}
	f.writeSummary(w, report)
	if show == "findings" {
		f.writeFindings(w, report)
	}
	f.writeHints(w, report)
	fmt.Fprintln(w)
	return nil
}

// ─── Header ──────────────────────────────────────────────────────────

func (f *TextFormatter) writeHeader(w io.Writer, r *types.ScanReport) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "   ___  ___ ___| |__   __ _\n")
	fmt.Fprintf(w, "  / __|/ _ / __| '_ \\ / _` |\n")
	fmt.Fprintf(w, "  \\__ |  __\\__ | | | | (_| |\n")
	fmt.Fprintf(w, "  |___/\\___|___|_| |_|\\__,_|  v%s\n", r.Version)
	fmt.Fprintf(w, "  %s\n", cDim("Catch drift, not feelings"))
	fmt.Fprintf(w, "  %s %s\n", cDim("Scan started:"), r.Timestamp.Format("2006-01-02T15:04:05Z07:00"))
	fmt.Fprintln(w)
}

// ─── System context ──────────────────────────────────────────────────

func (f *TextFormatter) writeSystem(w io.Writer, r *types.ScanReport) {
	sys := r.System
	fmt.Fprintf(w, "  %s\n", cBold("▸ System"))
	fmt.Fprintf(w, "    OS:      %s %s (%s)\n", sys.OS, sys.OSVersion, sys.Arch)
	if sys.DistroID != "" {
		fmt.Fprintf(w, "    Distro:  %s %s (%s)\n", sys.DistroID, sys.DistroVersion, sys.DistroFamily)
	}
	envStr := sys.EnvType
	if sys.EnvRuntime != "" {
		envStr += fmt.Sprintf(" (%s)", sys.EnvRuntime)
	}
	fmt.Fprintf(w, "    Env:     %s\n", envStr)
	fmt.Fprintf(w, "    Profile: %s\n", sys.Profile)
	fmt.Fprintln(w)
	if !sys.IsRoot {
		fmt.Fprintf(w, "  %s %s\n", cYellow(f.icon("warn")),
			f.wrap("Running as non-root — some checks may produce incomplete results", 4, 4))
		fmt.Fprintln(w)
	}
}

// ─── Loading ─────────────────────────────────────────────────────────

func (f *TextFormatter) writeLoading(w io.Writer, r *types.ScanReport) {
	fmt.Fprintf(w, "  %s Loaded %d check(s)\n", cBold("▸"), r.Summary.TotalChecks)

	var filters []string
	if r.Filters.CheckID != "" {
		filters = append(filters, fmt.Sprintf("check=%s", r.Filters.CheckID))
	}
	show := f.Show
	if show == "" {
		show = "findings"
	}
	if show != "findings" {
		filters = append(filters, fmt.Sprintf("show=%s", show))
	}
	if len(filters) > 0 {
		fmt.Fprintf(w, "    Filters: %s\n", strings.Join(filters, " · "))
	}
	fmt.Fprintln(w)
}

// ─── Results (--show all/fail/pass) ──────────────────────────────────

func (f *TextFormatter) writeResults(w io.Writer, r *types.ScanReport) {
	fmt.Fprintf(w, "  %s\n", cBold("▸ Results"))

	if len(r.Results) == 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s(no results match the current filters)\n", colPad(colMargin))
		return
	}

	sorted := f.sortResults(r.Results)

	currentCategory := ""
	for _, res := range sorted {
		if res.Category != currentCategory {
			currentCategory = res.Category
			f.writeCategoryHeader(w, currentCategory)
		}

		f.writeResultLine(w, res, false)
		f.writeDetailBlock(w, res, r.System.IsRoot, false)
		fmt.Fprintln(w)
	}
}

// ─── Findings (default view) ─────────────────────────────────────────

func (f *TextFormatter) writeFindings(w io.Writer, r *types.ScanReport) {
	findings := f.extractFindings(r.Results)
	if len(findings) == 0 {
		return
	}

	// Sort findings by severity (critical first) before grouping by category.
	findings = f.sortResults(findings)

	type catGroup struct {
		category string
		findings []types.TestResult
	}
	order := make(map[string]int)
	var groups []catGroup
	for _, fi := range findings {
		idx, ok := order[fi.Category]
		if !ok {
			idx = len(groups)
			order[fi.Category] = idx
			groups = append(groups, catGroup{category: fi.Category})
		}
		groups[idx].findings = append(groups[idx].findings, fi)
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", cRedBold("▸ Findings"))

	for _, g := range groups {
		f.writeCategoryHeader(w, g.category)

		for _, fi := range g.findings {
			f.writeResultLine(w, fi, true)
			f.writeDetailBlock(w, fi, r.System.IsRoot, true)
			fmt.Fprintln(w)
		}
	}
}

// extractFindings returns only fail and error results.
func (f *TextFormatter) extractFindings(results []types.TestResult) []types.TestResult {
	var findings []types.TestResult
	for _, r := range results {
		if r.Status == types.StatusFail || r.Status == types.StatusError {
			findings = append(findings, r)
		}
	}
	return findings
}

// ─── Summary ─────────────────────────────────────────────────────────

func (f *TextFormatter) writeSummary(w io.Writer, r *types.ScanReport) {
	rule := cDim(strings.Repeat("─", ruleWidth))
	fmt.Fprintf(w, "  %s\n", rule)

	f.writeVerdict(w, r)

	s := r.Summary
	passed := cGreenBold(fmt.Sprintf("%d passed", s.Passed))
	failed := cRedBold(fmt.Sprintf("%d failed", s.Failed))
	skipped := cDim(fmt.Sprintf("%d skipped", s.Skipped))
	extra := ""
	if s.Errors > 0 {
		extra += " · " + cRedBold(fmt.Sprintf("%d errors", s.Errors))
	}
	if s.Accepted > 0 {
		extra += " · " + cCyan(fmt.Sprintf("%d accepted", s.Accepted))
	}

	fmt.Fprintf(w, "  %s  %s · %s · %s%s\n",
		cBold("Summary:"), passed, failed, skipped, extra)

	dur := fmt.Sprintf("%.1fs", float64(s.DurationMS)/1000.0)
	fmt.Fprintf(w, "  %s  %s\n", cDim("Completed in"), cBold(dur))
	fmt.Fprintf(w, "  %s\n", rule)
}

func (f *TextFormatter) writeVerdict(w io.Writer, r *types.ScanReport) {
	s := r.Summary
	if s.Failed == 0 && s.Errors == 0 {
		fmt.Fprintf(w, "  %s %s\n", cGreenBold(f.icon("pass")),
			cGreenBold("Clean — no findings"))
		return
	}

	findings := f.extractFindings(r.Results)
	counts := map[string]int{}
	for _, fi := range findings {
		counts[fi.Severity]++
	}

	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if c, ok := counts[sev]; ok && c > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c, sev))
		}
	}

	total := s.Failed + s.Errors
	detail := ""
	if len(parts) > 0 {
		detail = fmt.Sprintf(" (%s)", strings.Join(parts, ", "))
	}

	fmt.Fprintf(w, "  %s %s\n", cRedBold(f.icon("shield")),
		cRedBold(fmt.Sprintf("%d finding(s) require attention%s", total, detail)))
}

// ─── Hints ───────────────────────────────────────────────────────────

func (f *TextFormatter) writeHints(w io.Writer, r *types.ScanReport) {
	var hints []string
	s := r.Summary
	hasFindings := s.Failed > 0 || s.Errors > 0
	show := f.Show
	if show == "" {
		show = "findings"
	}

	if hasFindings && !f.Explain {
		hints = append(hints, "Run with --explain for impact details")
	}
	if show == "findings" && hasFindings {
		hints = append(hints, "Use --show all to see every check result")
	}

	if len(hints) == 0 {
		return
	}

	fmt.Fprintln(w)
	for _, h := range hints {
		fmt.Fprintf(w, "  %s %s\n", cDim("›"), cDim(h))
	}
}

// ─── Category header ─────────────────────────────────────────────────

func (f *TextFormatter) writeCategoryHeader(w io.Writer, category string) {
	label := strings.ToUpper(category)
	fill := ruleWidth - 4 - len(label)
	if fill < 1 {
		fill = 1
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s%s %s %s\n", colPad(colMargin), cDim("──"), cBold(label), cDim(strings.Repeat("─", fill)))
	fmt.Fprintln(w)
}

// ─── Result line (single shared renderer) ────────────────────────────

func (f *TextFormatter) writeResultLine(w io.Writer, res types.TestResult, isFinding bool) {
	icon := f.statusIcon(res.Status)
	badge := f.severityBadge(res)
	dur := f.durationTag(res)
	durRaw := f.durationRaw(res)
	ww := f.wrapWidth()

	// Always show "Check:" label with the name, duration right-aligned.
	// Layout: margin icon badge  Check:   name ... duration
	checkLabel := cBold(fmt.Sprintf("%-*s", labelWidth, "Check:"))
	name := res.Name
	nameAvail := ww - colValue - 2 - len(durRaw)
	namePad := nameAvail - len(name)
	if namePad < 2 {
		namePad = 2
	}
	fmt.Fprintf(w, "%s%s %s  %s%s%s%s\n",
		colPad(colMargin),
		icon,
		badge,
		checkLabel,
		name,
		strings.Repeat(" ", namePad),
		dur,
	)
}

// ─── Detail block (single shared renderer) ───────────────────────────

func (f *TextFormatter) writeDetailBlock(w io.Writer, res types.TestResult, isRoot bool, isFinding bool) {
	p := colPad(colDetail)

	// 1. Accepted note
	if res.Status == types.StatusAccepted && res.AcceptedReason != "" {
		f.writeLabel(w, p, "Note:", cCyan, res.AcceptedReason)
	}

	// 2. Context note
	if res.ContextNote != "" {
		f.writeLabel(w, p, "Context:", cCyan, res.ContextNote)
	}

	// 3. Status-specific message
	switch res.Status {
	case types.StatusFail:
		if res.Message != "" {
			f.writeLabel(w, p, "Result:", cRed, res.Message)
		}
	case types.StatusSkip:
		f.writeLabel(w, p, "Skipped:", cDim, res.Message)
	case types.StatusError:
		f.writeLabel(w, p, "Error:", cRed, res.Message)
	}

	// 4. Remediation
	if res.Remediation != "" && res.Status != types.StatusSkip {
		f.writeLabel(w, p, "Fix:", cGreen, res.Remediation)
	}

	// 5. Explain fields (all statuses except skip — skipped checks didn't execute)
	if f.Explain && res.Status != types.StatusSkip {
		if res.Impact != "" {
			f.writeLabel(w, p, "Impact:", cYellowBold, res.Impact)
		}
		if res.Explain != "" {
			f.writeLabel(w, p, "Why:", cYellowBold, res.Explain)
		}
		if res.BreakRisk != "" {
			f.writeLabel(w, p, "Risk:", cYellowBold, res.BreakRisk)
		}
	}
}

// writeLabel emits one detail line: prefix + colored label (padded to labelWidth) + wrapped value.
func (f *TextFormatter) writeLabel(w io.Writer, prefix, label string, colorFn func(a ...interface{}) string, value string) {
	colored := colorFn(fmt.Sprintf("%-*s", labelWidth, label))
	wrapped := f.wrap(value, colValue, colValue)
	fmt.Fprintf(w, "%s%s%s\n", prefix, colored, wrapped)
}

// ─── Sorting ─────────────────────────────────────────────────────────

func (f *TextFormatter) sortResults(results []types.TestResult) []types.TestResult {
	sorted := make([]types.TestResult, len(results))
	copy(sorted, results)
	sevOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.SliceStable(sorted, func(i, j int) bool {
		si := sorted[i].Severity
		sj := sorted[j].Severity
		if sevOrder[si] != sevOrder[sj] {
			return sevOrder[si] < sevOrder[sj]
		}
		if sorted[i].Category != sorted[j].Category {
			return sorted[i].Category < sorted[j].Category
		}
		return sorted[i].Name < sorted[j].Name
	})
	return sorted
}

// ─── Text wrapping ───────────────────────────────────────────────────

func (f *TextFormatter) wrap(text string, startCol, wrapCol int) string {
	w := f.wrapWidth()
	if startCol+len(text) <= w {
		return text
	}

	avail := w - startCol
	if avail < 20 {
		return text
	}

	wrapPad := strings.Repeat(" ", wrapCol)
	words := strings.Fields(text)
	if len(words) == 0 {
		return text
	}

	var b strings.Builder
	lineLen := 0

	for i, word := range words {
		if i == 0 {
			b.WriteString(word)
			lineLen = len(word)
			continue
		}
		if lineLen+1+len(word) > avail {
			b.WriteByte('\n')
			b.WriteString(wrapPad)
			b.WriteString(word)
			lineLen = len(word)
			avail = w - wrapCol
		} else {
			b.WriteByte(' ')
			b.WriteString(word)
			lineLen += 1 + len(word)
		}
	}

	return b.String()
}

// ─── Icons ───────────────────────────────────────────────────────────

func (f *TextFormatter) icon(name string) string {
	if f.Dumb {
		switch name {
		case "pass":
			return "+"
		case "fail":
			return "x"
		case "skip":
			return "-"
		case "warn":
			return "!"
		case "error":
			return "!"
		case "accepted":
			return "~"
		case "info":
			return "i"
		case "shield":
			return "!"
		case "section":
			return ">"
		default:
			return "?"
		}
	}
	switch name {
	case "pass":
		return "✓"
	case "fail":
		return "✗"
	case "skip":
		return "○"
	case "warn":
		return "⚠"
	case "error":
		return "⚠"
	case "accepted":
		return "≋"
	case "info":
		return "ℹ"
	case "shield":
		return "🛡"
	case "section":
		return "▸"
	default:
		return "?"
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────

func (f *TextFormatter) statusIcon(s types.ResultStatus) string {
	switch s {
	case types.StatusPass:
		return cGreen(f.icon("pass"))
	case types.StatusFail:
		return cRed(f.icon("fail"))
	case types.StatusSkip:
		return cDim(f.icon("skip"))
	case types.StatusError:
		return cRed(f.icon("error"))
	case types.StatusAccepted:
		return cCyan(f.icon("accepted"))
	default:
		return "?"
	}
}

func (f *TextFormatter) severityBadge(r types.TestResult) string {
	if r.OriginalSeverity != "" && r.OriginalSeverity != r.Severity {
		from := severityAbbrev(r.OriginalSeverity)
		to := severityAbbrev(r.Severity)
		arrow := fmt.Sprintf("[%s>%s]", from, to)
		return cCyan(fmt.Sprintf("%-*s", badgeWidth, arrow))
	}
	return f.coloredBadge(r.Severity)
}

func (f *TextFormatter) coloredBadge(sev string) string {
	raw := severityBadgeRaw(sev)
	padded := fmt.Sprintf("%-*s", badgeWidth, raw)
	switch sev {
	case "critical":
		return cRedBold(padded)
	case "high":
		return cRed(padded)
	case "medium":
		return cYellow(padded)
	case "low":
		return cGreen(padded)
	case "info":
		return cDim(padded)
	default:
		return padded
	}
}

func (f *TextFormatter) durationTag(r types.TestResult) string {
	return cDim(f.durationRaw(r))
}

func (f *TextFormatter) durationRaw(r types.TestResult) string {
	ms := r.DurationMS
	if ms <= 0 {
		ms = r.Duration.Milliseconds()
	}
	if ms < 1 {
		return "(<1ms)"
	}
	return fmt.Sprintf("(%dms)", ms)
}

func colPad(n int) string {
	return strings.Repeat(" ", n)
}

func severityBadgeRaw(sev string) string {
	switch sev {
	case "critical":
		return "[CRIT]"
	case "high":
		return "[HIGH]"
	case "medium":
		return "[MED]"
	case "low":
		return "[LOW]"
	case "info":
		return "[INFO]"
	default:
		return "[----]"
	}
}

func severityAbbrev(sev string) string {
	switch sev {
	case "critical":
		return "CRIT"
	case "high":
		return "HIGH"
	case "medium":
		return "MED"
	case "low":
		return "LOW"
	case "info":
		return "INFO"
	default:
		return strings.ToUpper(sev)
	}
}
