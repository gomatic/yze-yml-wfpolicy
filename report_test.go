package wfpolicy_test

import (
	"testing"

	errs "github.com/gomatic/go-error"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	wfpolicy "github.com/gomatic/yze-yml-wfpolicy"
)

// errUnreadable stands in for whatever the filesystem refuses with.
const errUnreadable errs.Const = "unreadable"

// reader serves file contents from a map, refusing anything absent.
func reader(files map[string]string) wfpolicy.FileReader {
	return func(path string) ([]byte, error) {
		data, ok := files[path]
		if !ok {
			return nil, errUnreadable
		}
		return []byte(data), nil
	}
}

// TestReportAggregatesEveryFilesFindings pins that a run over several files
// yields all their findings, each naming the file it came from.
func TestReportAggregatesEveryFilesFindings(t *testing.T) {
	t.Parallel()

	read := reader(map[string]string{
		"a.yml": "jobs:\n  b:\n    steps:\n      - uses: o/a@main\n",
		"b.yml": "jobs:\n  b:\n    steps:\n      - uses: o/a@v1\n",
	})

	report, err := wfpolicy.Report(read, []string{"a.yml", "b.yml"}, nil)

	require.NoError(t, err)
	require.Len(t, report.Diagnostics, 1)
	assert.Equal(t, "a.yml", report.Diagnostics[0].Path)
}

// TestReportSurfacesAReadFailure pins that an unreadable file aborts the run
// with its own sentinel rather than being skipped into a clean result.
func TestReportSurfacesAReadFailure(t *testing.T) {
	t.Parallel()

	_, err := wfpolicy.Report(reader(nil), []string{"missing.yml"}, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, wfpolicy.ErrReadFile)
	assert.ErrorIs(t, err, errUnreadable, "the cause survives so the reason is visible")
}

// TestReportContainsAParseFailureToItsOwnFile pins the containment that
// replaced an aborting run. `%YAML 1.2` is a legal directive GitHub accepts and
// this parser rejects, and aborting on it destroyed every other file's findings.
// The file is still REPORTED, so nothing is passed over in silence.
func TestReportContainsAParseFailureToItsOwnFile(t *testing.T) {
	t.Parallel()

	read := reader(map[string]string{
		"broken.yml": "jobs:\n  - [unclosed\n",
		"pinned.yml": "jobs:\n  b:\n    steps:\n      - uses: o/a@main\n",
	})

	report, err := wfpolicy.Report(read, []string{"broken.yml", "pinned.yml"}, nil)

	require.NoError(t, err, "one unreadable file is not the whole run's failure")
	paths := map[string]string{}
	for _, d := range report.Diagnostics {
		paths[d.Path] += d.Message
	}
	assert.Contains(t, paths["broken.yml"], "cannot be analyzed as a workflow")
	assert.Contains(t, paths["pinned.yml"], "a ref that moves", "its neighbour keeps every finding it earned")
}

// TestReportOfNoFilesIsAnEmptyReport pins the trivial case explicitly.
func TestReportOfNoFilesIsAnEmptyReport(t *testing.T) {
	t.Parallel()

	report, err := wfpolicy.Report(reader(nil), nil, nil)

	require.NoError(t, err)
	assert.Empty(t, report.Diagnostics)
}
