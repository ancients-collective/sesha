package output

import (
	"encoding/json"
	"io"

	"github.com/ancients-collective/sesha/internal/types"
)

// JSONLFormatter writes scan results as newline-delimited JSON (one object per line).
// The first line is a header with system and summary information.
// Subsequent lines are individual check results.
type JSONLFormatter struct{}

// Write renders the scan as JSONL: header line + one line per result.
func (f *JSONLFormatter) Write(w io.Writer, report *types.ScanReport) error {
	enc := json.NewEncoder(w)

	// Header line
	header := struct {
		Type      string            `json:"type"`
		Version   string            `json:"version"`
		Timestamp string            `json:"timestamp"`
		System    types.ScanSystem  `json:"system"`
		Summary   types.ScanSummary `json:"summary"`
	}{
		Type:      "header",
		Version:   report.Version,
		Timestamp: report.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
		System:    report.System,
		Summary:   report.Summary,
	}
	if err := enc.Encode(header); err != nil {
		return err
	}

	// One line per result
	for _, r := range report.Results {
		line := struct {
			Type   string           `json:"type"`
			Result types.TestResult `json:"result"`
		}{
			Type:   "result",
			Result: r,
		}
		if err := enc.Encode(line); err != nil {
			return err
		}
	}

	return nil
}
