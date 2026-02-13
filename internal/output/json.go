package output

import (
	"encoding/json"
	"io"

	"github.com/ancients-collective/sesha/internal/types"
)

// JSONFormatter writes a scan report as a single JSON object.
type JSONFormatter struct{}

// Write renders the full report as pretty-printed JSON.
func (f *JSONFormatter) Write(w io.Writer, report *types.ScanReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(report)
}
