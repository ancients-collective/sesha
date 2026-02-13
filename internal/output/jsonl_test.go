package output

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONLFormatter_Write(t *testing.T) {
	report := newTestReport()
	var buf bytes.Buffer
	f := &JSONLFormatter{}

	err := f.Write(&buf, report)
	require.NoError(t, err)

	golden := filepath.Join("testdata", "report.jsonl.golden")
	if updateGolden {
		require.NoError(t, os.WriteFile(golden, buf.Bytes(), 0o644))
		t.Log("Updated golden file")
		return
	}

	expected, err := os.ReadFile(golden)
	if err != nil {
		require.NoError(t, os.WriteFile(golden, buf.Bytes(), 0o644))
		t.Log("Created golden file — re-run to verify")
		return
	}

	assert.Equal(t, string(expected), buf.String())
}

func TestJSONLFormatter_LineCount(t *testing.T) {
	report := newTestReport()
	var buf bytes.Buffer
	f := &JSONLFormatter{}

	require.NoError(t, f.Write(&buf, report))

	scanner := bufio.NewScanner(&buf)
	lineCount := 0
	for scanner.Scan() {
		lineCount++
	}

	// 1 header + N results
	expected := 1 + len(report.Results)
	assert.Equal(t, expected, lineCount, "should have 1 header line + %d result lines", len(report.Results))
}

func TestJSONLFormatter_HeaderLine(t *testing.T) {
	report := newTestReport()
	var buf bytes.Buffer
	f := &JSONLFormatter{}

	require.NoError(t, f.Write(&buf, report))

	scanner := bufio.NewScanner(&buf)
	require.True(t, scanner.Scan(), "should have at least one line")

	var header map[string]interface{}
	require.NoError(t, json.Unmarshal(scanner.Bytes(), &header))

	assert.Equal(t, "header", header["type"])
	assert.Equal(t, "1.0.2", header["version"])
	assert.NotNil(t, header["system"])
	assert.NotNil(t, header["summary"])
}

func TestJSONLFormatter_ResultLines(t *testing.T) {
	report := newTestReport()
	var buf bytes.Buffer
	f := &JSONLFormatter{}

	require.NoError(t, f.Write(&buf, report))

	scanner := bufio.NewScanner(&buf)
	scanner.Scan() // skip header

	lineIdx := 0
	for scanner.Scan() {
		var line map[string]interface{}
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &line))
		assert.Equal(t, "result", line["type"])
		assert.NotNil(t, line["result"])
		lineIdx++
	}
	assert.Equal(t, len(report.Results), lineIdx)
}

func TestJSONLFormatter_EmptyResults(t *testing.T) {
	report := newEmptyReport()
	var buf bytes.Buffer
	f := &JSONLFormatter{}

	require.NoError(t, f.Write(&buf, report))

	scanner := bufio.NewScanner(&buf)
	lineCount := 0
	for scanner.Scan() {
		lineCount++
	}

	assert.Equal(t, 1, lineCount, "should have only the header line")
}
