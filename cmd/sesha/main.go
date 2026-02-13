// Package main is the entry point for sesha — Catch drift, not feelings.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"golang.org/x/term"

	sysdetect "github.com/ancients-collective/sesha/internal/context"
	"github.com/ancients-collective/sesha/internal/engine"
	"github.com/ancients-collective/sesha/internal/loader"
	"github.com/ancients-collective/sesha/internal/output"
	"github.com/ancients-collective/sesha/internal/types"
)

// version is set at build time via -ldflags. The default is a dev fallback
// for plain `go install` or `go run` usage.
var version = "1.0.6"

// Config holds all parsed CLI flag values.
type Config struct {
	ChecksDir  string
	Show       string
	Severity   string
	Verify     bool
	Profile    string
	Explain    bool
	Format     string
	NoColor    bool
	OutputFile string
	Quiet      bool
	CheckID    string
	ListChecks bool
	Debug      bool
	Validate   string
	Tags       string
}

// parseFlags parses command-line arguments into a Config using a dedicated FlagSet,
// keeping the global flag.CommandLine clean for testability.
func parseFlags(args []string) (*Config, error) {
	cfg := &Config{}
	fs := flag.NewFlagSet("sesha", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	fs.StringVar(&cfg.ChecksDir, "checks", "./checks", "Path to the checks directory")
	fs.StringVar(&cfg.ChecksDir, "c", "./checks", "Path to the checks directory (shorthand)")
	fs.StringVar(&cfg.Show, "show", "findings", "Which results to display: findings, all, fail, pass")
	fs.StringVar(&cfg.Show, "s", "findings", "Which results to display (shorthand)")
	fs.StringVar(&cfg.Severity, "severity", "", "Filter by severity (comma-separated): critical,high,medium,low,info")
	fs.StringVar(&cfg.Severity, "sev", "", "Filter by severity (shorthand)")
	fs.BoolVar(&cfg.Verify, "verify", false, "Verify checks directory integrity before running")
	fs.StringVar(&cfg.Profile, "profile", "auto", "Intent profile: auto, all, server, workstation, container")
	fs.StringVar(&cfg.Profile, "p", "auto", "Intent profile (shorthand)")
	fs.BoolVar(&cfg.Explain, "explain", false, "Show impact, explain, and break_risk details")
	fs.StringVar(&cfg.Format, "format", "text", "Output format: text, json, jsonl")
	fs.StringVar(&cfg.Format, "f", "text", "Output format (shorthand)")
	fs.BoolVar(&cfg.NoColor, "no-color", false, "Disable colored output")
	fs.StringVar(&cfg.OutputFile, "output", "", "Write output to file (default: stdout)")
	fs.StringVar(&cfg.OutputFile, "o", "", "Write output to file (shorthand)")
	fs.BoolVar(&cfg.Quiet, "quiet", false, "Suppress output, exit code only (0 = clean, 1 = findings, 2 = errors)")
	fs.BoolVar(&cfg.Quiet, "q", false, "Suppress output (shorthand)")
	fs.StringVar(&cfg.CheckID, "id", "", "Run a single check by its ID")
	fs.BoolVar(&cfg.ListChecks, "list-checks", false, "List all available check IDs and exit")
	fs.BoolVar(&cfg.Debug, "debug", false, "Enable debug diagnostic output")
	fs.StringVar(&cfg.Validate, "validate", "", "Validate YAML check file(s) without execution (file or directory)")
	fs.StringVar(&cfg.Tags, "tags", "", "Filter checks by tags (comma-separated)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "   ___  ___ ___| |__   __ _\n")
		fmt.Fprintf(os.Stderr, "  / __|/ _ / __| '_ \\ / _` |\n")
		fmt.Fprintf(os.Stderr, "  \\__ |  __\\__ | | | | (_| |\n")
		fmt.Fprintf(os.Stderr, "  |___/\\___|___|_| |_|\\__,_|\n")
		fmt.Fprintf(os.Stderr, "  Catch drift, not feelings\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "  Usage: sesha [options]\n\n")
		fmt.Fprintf(os.Stderr, "  Options:\n")
		fmt.Fprintf(os.Stderr, "    -c,  --checks <dir>       Path to checks directory (default: ./checks)\n")
		fmt.Fprintf(os.Stderr, "    -s,  --show <mode>        Output filter: findings, all, fail, pass (default: findings)\n")
		fmt.Fprintf(os.Stderr, "         --severity <list>    Filter by severity: critical, high, medium, low, info\n")
		fmt.Fprintf(os.Stderr, "         --sev <list>         (shorthand for --severity)\n")
		fmt.Fprintf(os.Stderr, "    -p,  --profile <type>     Intent profile: auto, all, server, workstation, container\n")
		fmt.Fprintf(os.Stderr, "         --explain            Show impact, explain, and break_risk details\n")
		fmt.Fprintf(os.Stderr, "    -f,  --format <type>      Output format: text, json, jsonl (default: text)\n")
		fmt.Fprintf(os.Stderr, "         --no-color           Disable colored output\n")
		fmt.Fprintf(os.Stderr, "    -o,  --output <file>      Write output to file (default: stdout)\n")
		fmt.Fprintf(os.Stderr, "    -q,  --quiet              Suppress output, exit code only (0/1/2)\n")
		fmt.Fprintf(os.Stderr, "         --verify             Verify checks directory integrity before running\n")
		fmt.Fprintf(os.Stderr, "         --id <check_id>      Run a single check by its ID\n")
		fmt.Fprintf(os.Stderr, "         --list-checks        List all available check IDs and exit\n")
		fmt.Fprintf(os.Stderr, "         --debug              Enable debug diagnostic output\n")
		fmt.Fprintf(os.Stderr, "         --validate <path>    Validate YAML check file(s) without execution\n")
		fmt.Fprintf(os.Stderr, "         --tags <list>        Filter checks by tag (comma-separated)\n")
		fmt.Fprintf(os.Stderr, "\n  Examples:\n")
		fmt.Fprintf(os.Stderr, "    sesha                                 Show findings (default)\n")
		fmt.Fprintf(os.Stderr, "    sesha --show all                      Show all check results\n")
		fmt.Fprintf(os.Stderr, "    sesha --show pass                     Show only passing checks\n")
		fmt.Fprintf(os.Stderr, "    sesha --sev critical,high             Critical and high findings only\n")
		fmt.Fprintf(os.Stderr, "    sesha --profile container             Run with container profile\n")
		fmt.Fprintf(os.Stderr, "    sesha --profile all                   Run all checks (ignore profiles)\n")
		fmt.Fprintf(os.Stderr, "    sesha --id ssh_permit_root            Run a single check by ID\n")
		fmt.Fprintf(os.Stderr, "    sesha --list-checks                   List all available check IDs\n")
		fmt.Fprintf(os.Stderr, "    sesha --list-checks -p container      List checks for container profile\n")
		fmt.Fprintf(os.Stderr, "    sesha --explain                       Include impact details\n")
		fmt.Fprintf(os.Stderr, "    sesha --format json                   JSON for SIEM ingestion\n")
		fmt.Fprintf(os.Stderr, "    sesha --format jsonl -o scan.jsonl    JSONL for log pipelines\n")
		fmt.Fprintf(os.Stderr, "    sesha --format json -o scan.json      Write JSON to file\n")
		fmt.Fprintf(os.Stderr, "    sesha --validate ./checks             Validate YAML without running\n")
		fmt.Fprintf(os.Stderr, "    sesha -q && echo clean                Scripting with exit code\n")
		fmt.Fprintf(os.Stderr, "    sesha -c /etc/sesha/checks            Custom checks directory\n")
		fmt.Fprintf(os.Stderr, "    sesha --tags cis-benchmark            Run only CIS-tagged checks\n")
		fmt.Fprintf(os.Stderr, "    sesha --tags web-server,ssh-server    Run checks matching any tag\n")
		fmt.Fprintf(os.Stderr, "\n")
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return cfg, nil
}

func main() {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		os.Exit(1)
	}
	os.Exit(run(cfg))
}

// run executes the scan with the given configuration and returns an exit code.
func run(cfg *Config) int {
	scanStart := time.Now()

	// Handle --validate early
	if cfg.Validate != "" {
		return handleValidate(cfg.Validate)
	}

	// Validate flags
	if code := validateFlags(cfg); code >= 0 {
		return code
	}

	// Setup output options
	isDumb, sevFilter, tagsFilter, err := setupOutputOptions(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ✗ %v\n", err)
		return 1
	}

	// Detect system context and apply profile
	ctx, isRoot, code := detectSystem(cfg)
	if code >= 0 {
		return code
	}

	showProgress := cfg.Format == "text" && !cfg.Quiet && cfg.OutputFile == ""
	if showProgress {
		fmt.Fprintf(os.Stderr, "\n")
	}

	// Verify checks directory (optional)
	if code := verifyChecksDir(cfg); code >= 0 {
		return code
	}

	// Load, filter, and optionally list checks
	tests, code := loadAndFilterChecks(cfg, tagsFilter)
	if code >= 0 {
		return code
	}

	// Execute checks
	allResults := executeChecks(cfg, tests, ctx, showProgress)

	// Tally results
	displayResults, pass, fail, skip, errCount, accepted := tallyResults(allResults, cfg.Show, sevFilter)

	scanDuration := time.Since(scanStart)

	// Quiet mode: exit code only
	if cfg.Quiet {
		return exitCode(fail, errCount)
	}

	// Build report
	report := buildScanReport(cfg, ctx, isRoot, tests, displayResults,
		pass, fail, skip, errCount, accepted, scanStart, scanDuration, sevFilter, tagsFilter)

	// Write output
	return writeReport(cfg, report, isDumb, pass, fail, skip)
}

// validateFlags checks --show, --profile, and --format values.
// Returns -1 if valid, or an exit code (1) if invalid.
func validateFlags(cfg *Config) int {
	switch cfg.Show {
	case "findings", "all", "fail", "pass":
	default:
		fmt.Fprintf(os.Stderr, "  ✗ Invalid --show value %q (must be findings, all, fail, or pass)\n", cfg.Show)
		return 1
	}
	switch cfg.Profile {
	case "auto", "all", "server", "workstation", "container":
	default:
		fmt.Fprintf(os.Stderr, "  ✗ Invalid --profile value %q (must be auto, all, server, workstation, or container)\n", cfg.Profile)
		return 1
	}
	switch cfg.Format {
	case "text", "json", "jsonl":
	default:
		fmt.Fprintf(os.Stderr, "  ✗ Invalid --format value %q (must be text, json, or jsonl)\n", cfg.Format)
		return 1
	}
	return -1
}

// setupOutputOptions configures color, severity filter, and tag filter.
func setupOutputOptions(cfg *Config) (isDumb bool, sevFilter map[string]bool, tagsFilter map[string]bool, err error) {
	isDumb = output.IsDumbTerm()
	if cfg.NoColor || cfg.Format != "text" || cfg.OutputFile != "" || isDumb {
		color.NoColor = true
	}

	sevFilter, err = parseSeverityFilter(cfg.Severity)
	if err != nil {
		return false, nil, nil, fmt.Errorf("Invalid --severity flag: %v", err)
	}

	tagsFilter = parseTagsFilter(cfg.Tags)
	return isDumb, sevFilter, tagsFilter, nil
}

// detectSystem detects the system context, applies the profile, and checks privilege.
// Returns -1 as code if successful, or an exit code on failure.
func detectSystem(cfg *Config) (ctx types.SystemContext, isRoot bool, code int) {
	sysdetect.DebugMode = cfg.Debug
	detector := sysdetect.NewOSDetector()
	ctx, detectWarnings, err := sysdetect.DetectSystemContext(detector)
	if err != nil {
		if !cfg.Quiet {
			fmt.Fprintf(os.Stderr, "  ✗ Failed to detect system context: %v\n", err)
		}
		return ctx, false, 1
	}
	if !cfg.Quiet {
		for _, w := range detectWarnings {
			fmt.Fprintf(os.Stderr, "  ⚠ %s\n", w)
		}
	}

	// Apply profile
	switch cfg.Profile {
	case "all":
		ctx.IntentProfile = ""
	case "auto":
		if ctx.Environment.Type == "container" {
			cfg.Profile = "container"
		} else {
			cfg.Profile = "server"
		}
		ctx.IntentProfile = cfg.Profile
	default:
		ctx.IntentProfile = cfg.Profile
	}

	// Detect privilege level
	if u, err := user.Current(); err == nil && u.Uid == "0" {
		isRoot = true
	}

	return ctx, isRoot, -1
}

// verifyChecksDir runs the optional --verify integrity check.
// Returns -1 if skipped or passed, or an exit code on failure.
func verifyChecksDir(cfg *Config) int {
	if !cfg.Verify {
		return -1
	}
	if !cfg.Quiet {
		fmt.Fprintf(os.Stderr, "  ▸ Verifying checks directory: %s ...\n", cfg.ChecksDir)
	}
	warnings := engine.VerifyChecksDirectory(cfg.ChecksDir)
	if len(warnings) > 0 {
		if !cfg.Quiet {
			for _, w := range warnings {
				fmt.Fprintf(os.Stderr, "    ✗ %s\n", w)
			}
			fmt.Fprintf(os.Stderr, "\n  Aborting: checks directory failed integrity verification.\n")
			fmt.Fprintf(os.Stderr, "  Fix the above issues or run without --verify to skip this check.\n\n")
		}
		return 1
	}
	return -1
}

// loadAndFilterChecks loads checks, applies tag/ID filters, and handles --list-checks.
// Returns -1 as code if successful, or an exit code on early exit.
func loadAndFilterChecks(cfg *Config, tagsFilter map[string]bool) ([]types.TestDefinition, int) {
	registry := engine.NewFunctionRegistry(nil)
	ldr := loader.New(registry.FunctionNames())
	tests, errs := ldr.LoadDirectory(cfg.ChecksDir)
	if !cfg.Quiet && len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "    ⚠ Load error: %v\n", e)
		}
	}
	if len(tests) == 0 {
		if !cfg.Quiet {
			fmt.Fprintf(os.Stderr, "  ✗ No checks found in %s\n", cfg.ChecksDir)
		}
		return nil, 1
	}

	// --tags filter
	if tagsFilter != nil {
		tests = filterByTags(tests, tagsFilter)
		if len(tests) == 0 {
			if !cfg.Quiet {
				fmt.Fprintf(os.Stderr, "  ✗ No checks match --tags %q\n", cfg.Tags)
			}
			return nil, 1
		}
	}

	// --list-checks
	if cfg.ListChecks {
		sysdetect.DebugMode = cfg.Debug
		detector := sysdetect.NewOSDetector()
		ctx, _, _ := sysdetect.DetectSystemContext(detector)
		printCheckList(tests, ctx, cfg.Profile)
		return nil, 0
	}

	// --id filter
	if cfg.CheckID != "" {
		return filterByID(cfg, tests)
	}

	return tests, -1
}

// filterByTags returns tests that match any of the given tags.
func filterByTags(tests []types.TestDefinition, tagsFilter map[string]bool) []types.TestDefinition {
	var matched []types.TestDefinition
	for _, t := range tests {
		if matchesTags(t, tagsFilter) {
			matched = append(matched, t)
		}
	}
	return matched
}

// filterByID returns the single test matching cfg.CheckID, or exits with an error.
func filterByID(cfg *Config, tests []types.TestDefinition) ([]types.TestDefinition, int) {
	for _, t := range tests {
		if t.ID == cfg.CheckID {
			cfg.Show = "all"
			return []types.TestDefinition{t}, -1
		}
	}
	fmt.Fprintf(os.Stderr, "  ✗ No check found with ID %q\n", cfg.CheckID)
	if suggestions := suggestIDs(cfg.CheckID, tests); len(suggestions) > 0 {
		fmt.Fprintf(os.Stderr, "\n  Did you mean:\n")
		for _, s := range suggestions {
			fmt.Fprintf(os.Stderr, "    • %s\n", s)
		}
	}
	fmt.Fprintf(os.Stderr, "\n  Use --list-checks to see all available check IDs.\n")
	return nil, 1
}

// executeChecks runs all checks with optional progress output.
func executeChecks(cfg *Config, tests []types.TestDefinition, ctx types.SystemContext, showProgress bool) []types.TestResult {
	registry := engine.NewFunctionRegistry(nil)
	executor := engine.NewExecutor(registry, ctx)
	if cfg.CheckID != "" {
		executor.ForceRun = true
	}

	var allResults []types.TestResult
	totalChecks := len(tests)
	for i, test := range tests {
		if showProgress {
			fmt.Fprintf(os.Stderr, "\r  Scanning... %d/%d", i+1, totalChecks)
		}
		result := executor.RunTest(test)
		result.DurationMS = result.Duration.Milliseconds()
		allResults = append(allResults, result)
	}
	if showProgress {
		fmt.Fprintf(os.Stderr, "\r  Scanning... done    \n")
	}
	return allResults
}

// tallyResults counts results by status and filters for display.
func tallyResults(allResults []types.TestResult, show string, sevFilter map[string]bool) (
	displayResults []types.TestResult, pass, fail, skip, errCount, accepted int,
) {
	for _, r := range allResults {
		switch r.Status {
		case types.StatusPass:
			pass++
		case types.StatusFail:
			fail++
		case types.StatusSkip:
			skip++
		case types.StatusError:
			errCount++
		case types.StatusAccepted:
			accepted++
		}
		if shouldDisplay(r, show, sevFilter) {
			displayResults = append(displayResults, r)
		}
	}
	return
}

// buildScanReport assembles the scan report struct.
func buildScanReport(cfg *Config, ctx types.SystemContext, isRoot bool,
	tests []types.TestDefinition, displayResults []types.TestResult,
	pass, fail, skip, errCount, accepted int,
	scanStart time.Time, scanDuration time.Duration,
	sevFilter, tagsFilter map[string]bool,
) *types.ScanReport {
	var sevList []string
	for k := range sevFilter {
		sevList = append(sevList, k)
	}
	sort.Strings(sevList)

	return &types.ScanReport{
		Version:   version,
		Timestamp: scanStart,
		System: types.ScanSystem{
			Hostname:      ctx.Environment.Hostname,
			OS:            ctx.OS.Name,
			OSVersion:     ctx.OS.Version,
			Arch:          ctx.OS.Arch,
			DistroID:      ctx.Distro.ID,
			DistroVersion: ctx.Distro.Version,
			DistroFamily:  ctx.Distro.Family,
			EnvType:       ctx.Environment.Type,
			EnvRuntime:    ctx.Environment.Runtime,
			ContainerID:   ctx.Environment.ContainerID,
			Profile:       cfg.Profile,
			MachineID:     ctx.Environment.MachineID,
			IsRoot:        isRoot,
		},
		Filters: types.ScanFilters{
			Show:     cfg.Show,
			Severity: sevList,
			Profile:  cfg.Profile,
			Explain:  cfg.Explain,
			CheckID:  cfg.CheckID,
			Tags:     tagsList(tagsFilter),
		},
		Summary: types.ScanSummary{
			TotalChecks: len(tests),
			Passed:      pass,
			Failed:      fail,
			Skipped:     skip,
			Errors:      errCount,
			Accepted:    accepted,
			DurationMS:  scanDuration.Milliseconds(),
		},
		Results: displayResults,
	}
}

// writeReport formats and writes the scan report to stdout or a file.
func writeReport(cfg *Config, report *types.ScanReport, isDumb bool, pass, fail, skip int) int {
	termWidth := 0
	if cfg.OutputFile == "" && cfg.Format == "text" {
		if fd := int(os.Stdout.Fd()); term.IsTerminal(fd) {
			if tw, _, err := term.GetSize(fd); err == nil && tw > 0 {
				termWidth = tw
			}
		}
	}

	var formatter output.Formatter
	switch cfg.Format {
	case "json":
		formatter = &output.JSONFormatter{}
	case "jsonl":
		formatter = &output.JSONLFormatter{}
	default:
		formatter = &output.TextFormatter{
			Explain: cfg.Explain,
			Show:    cfg.Show,
			Width:   termWidth,
			Dumb:    isDumb,
		}
	}

	w := os.Stdout
	if cfg.OutputFile != "" {
		if err := validateOutputPath(cfg.OutputFile); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ Unsafe output path: %v\n", err)
			return 1
		}
		f, err := os.Create(cfg.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ Failed to create output file: %v\n", err)
			return 1
		}
		defer f.Close()
		w = f
	}

	if err := formatter.Write(w, report); err != nil {
		fmt.Fprintf(os.Stderr, "  ✗ Failed to write output: %v\n", err)
		return 1
	}

	if cfg.OutputFile != "" {
		fmt.Fprintf(os.Stderr, "  ✓ Scan complete: %d passed · %d failed · %d skipped — written to %s\n",
			pass, fail, skip, cfg.OutputFile)
	}

	return exitCode(fail, report.Summary.Errors)
}

// exitCode returns the sesha exit code: 0 = clean, 1 = findings, 2 = errors only.
func exitCode(fail, errCount int) int {
	if fail > 0 {
		return 1
	}
	if errCount > 0 {
		return 2
	}
	return 0
}

// handleValidate validates YAML check files without executing any checks.
// Returns an exit code (0 = success, 1 = validation errors).
func handleValidate(path string) int {
	registry := engine.NewFunctionRegistry(nil)
	ldr := loader.New(registry.FunctionNames())

	info, err := os.Stat(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ✗ Cannot access %q: %v\n", path, err)
		return 1
	}

	if info.IsDir() {
		errs := ldr.ValidateDirectory(path)
		if len(errs) > 0 {
			for _, e := range errs {
				fmt.Fprintf(os.Stderr, "  ✗ %v\n", e)
			}
			fmt.Fprintf(os.Stderr, "\n  Validation failed: %d error(s)\n", len(errs))
			return 1
		}
		fmt.Fprintf(os.Stdout, "  ✓ All checks in %s are valid\n", path)
		return 0
	}

	if err := ldr.ValidateOnly(path); err != nil {
		fmt.Fprintf(os.Stderr, "  ✗ %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stdout, "  ✓ %s is valid\n", path)
	return 0
}

// parseSeverityFilter builds a set of allowed severities from the --severity flag.
func parseSeverityFilter(raw string) (map[string]bool, error) {
	if raw == "" {
		return nil, nil
	}
	allowed := make(map[string]bool)
	valid := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	var invalid []string
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" {
			continue
		}
		if valid[s] {
			allowed[s] = true
		} else {
			invalid = append(invalid, s)
		}
	}
	if len(invalid) > 0 {
		return nil, fmt.Errorf("invalid severity values: %s (valid: critical, high, medium, low, info)",
			strings.Join(invalid, ", "))
	}
	if len(allowed) == 0 {
		return nil, nil
	}
	return allowed, nil
}

// parseTagsFilter builds a set of requested tags from the --tags flag.
func parseTagsFilter(raw string) map[string]bool {
	if raw == "" {
		return nil
	}
	tags := make(map[string]bool)
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(strings.ToLower(s))
		if s != "" {
			tags[s] = true
		}
	}
	if len(tags) == 0 {
		return nil
	}
	return tags
}

// matchesTags returns true if the check has at least one tag in the filter set.
func matchesTags(test types.TestDefinition, filter map[string]bool) bool {
	if filter == nil {
		return true
	}
	for _, tag := range test.Tags {
		if filter[strings.ToLower(tag)] {
			return true
		}
	}
	return false
}

// tagsList converts a tags filter map to a sorted slice for the report.
func tagsList(filter map[string]bool) []string {
	if filter == nil {
		return nil
	}
	var tags []string
	for t := range filter {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	return tags
}

// printCheckList prints a formatted table of check IDs, respecting --profile and --tags.
func printCheckList(tests []types.TestDefinition, ctx types.SystemContext, profile string) {
	var filtered []types.TestDefinition
	for _, t := range tests {
		if profile != "all" {
			if skip, _ := engine.ShouldSkip(t, ctx); skip {
				continue
			}
		}
		filtered = append(filtered, t)
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].ID < filtered[j].ID
	})

	maxID := 0
	for _, t := range filtered {
		if len(t.ID) > maxID {
			maxID = len(t.ID)
		}
	}

	fmt.Fprintf(os.Stdout, "\n  Available checks (%d):\n\n", len(filtered))
	for _, t := range filtered {
		sev := fmt.Sprintf("%-8s", t.Severity)
		fmt.Fprintf(os.Stdout, "    %-*s  %s  %s\n", maxID, t.ID, sev, t.Name)
	}
	fmt.Fprintln(os.Stdout)
	if profile != "all" && profile != "auto" {
		fmt.Fprintf(os.Stdout, "  Filtered by profile: %s\n\n", profile)
	}
}

// shouldDisplay returns true if a result should be printed based on --show and --severity filters.
func shouldDisplay(r types.TestResult, show string, sevFilter map[string]bool) bool {
	if sevFilter != nil && !sevFilter[r.Severity] {
		return false
	}
	switch show {
	case "findings":
		return r.Status == types.StatusFail || r.Status == types.StatusError
	case "fail":
		return r.Status == types.StatusFail
	case "pass":
		return r.Status == types.StatusPass
	case "all":
		return true
	default:
		return true
	}
}

// unsafeOutputPrefixes are path prefixes where writing output files is rejected.
// Prevents accidental overwrite of system files when running as root.
var unsafeOutputPrefixes = []string{"/etc/", "/proc/", "/sys/", "/dev/", "/boot/", "/sbin/", "/bin/", "/usr/"}

// validateOutputPath checks that the output file path is safe to write to.
func validateOutputPath(path string) error {
	cleaned := filepath.Clean(path)
	if filepath.IsAbs(cleaned) {
		for _, prefix := range unsafeOutputPrefixes {
			if strings.HasPrefix(cleaned, prefix) {
				return fmt.Errorf("refusing to write to system path %q", cleaned)
			}
		}
	}
	return nil
}
