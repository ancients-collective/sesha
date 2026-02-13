// Package output provides formatters that render scan reports in different formats.
package output

import (
	"io"

	"github.com/ancients-collective/sesha/internal/types"
)

// Formatter writes a scan report to the given writer.
type Formatter interface {
	Write(w io.Writer, report *types.ScanReport) error
}
