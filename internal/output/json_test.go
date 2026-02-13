package output

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ancients-collective/sesha/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// updateGolden controls whether golden files are rewritten.
// Run with: go test -run TestJSON -update-golden
var updateGolden = os.Getenv("UPDATE_GOLDEN") == "1"

func TestJSONFormatter_Write(t *testing.T) {
	report := newTestReport()
	var buf bytes.Buffer
	f := &JSONFormatter{}

	err := f.Write(&buf, report)
	require.NoError(t, err)

	golden := filepath.Join("testdata", "report.json.golden")
	if updateGolden {
		require.NoError(t, os.WriteFile(golden, buf.Bytes(), 0o644))
		t.Log("Updated golden file")
		return
	}

	expected, err := os.ReadFile(golden)
	if err != nil {
		// First run — create the golden file
		require.NoError(t, os.WriteFile(golden, buf.Bytes(), 0o644))
		t.Log("Created golden file — re-run to verify")
		return
	}

	assert.Equal(t, string(expected), buf.String())
}

func TestJSONFormatter_RoundTrip(t *testing.T) {
	report := newTestReport()
	var buf bytes.Buffer
	f := &JSONFormatter{}

	require.NoError(t, f.Write(&buf, report))

	var decoded types.ScanReport
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))

	assert.Equal(t, report.Version, decoded.Version)
	assert.Equal(t, report.System.Hostname, decoded.System.Hostname)
	assert.Equal(t, report.Summary.TotalChecks, decoded.Summary.TotalChecks)
	assert.Equal(t, report.Summary.Failed, decoded.Summary.Failed)
	assert.Len(t, decoded.Results, len(report.Results))

	for i, r := range decoded.Results {
		assert.Equal(t, report.Results[i].ID, r.ID)
		assert.Equal(t, report.Results[i].Status, r.Status)
		assert.Equal(t, report.Results[i].Severity, r.Severity)
	}
}

func TestJSONFormatter_EmptyResults(t *testing.T) {
	report := newEmptyReport()
	var buf bytes.Buffer
	f := &JSONFormatter{}

	require.NoError(t, f.Write(&buf, report))

	var decoded types.ScanReport
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))

	assert.Empty(t, decoded.Results)
	assert.Equal(t, 0, decoded.Summary.TotalChecks)
}
