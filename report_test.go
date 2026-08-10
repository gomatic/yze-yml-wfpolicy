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

	report, err := wfpolicy.Report(read, []string{"a.yml", "b.yml"})

	require.NoError(t, err)
	require.Len(t, report.Diagnostics, 1)
	assert.Equal(t, "a.yml", report.Diagnostics[0].Path)
}

// TestReportSurfacesAReadFailure pins that an unreadable file aborts the run
// with its own sentinel rather than being skipped into a clean result.
func TestReportSurfacesAReadFailure(t *testing.T) {
	t.Parallel()

	_, err := wfpolicy.Report(reader(nil), []string{"missing.yml"})

	require.Error(t, err)
	assert.ErrorIs(t, err, wfpolicy.ErrReadFile)
	assert.ErrorIs(t, err, errUnreadable, "the cause survives so the reason is visible")
}

// TestReportSurfacesAParseFailure pins that malformed YAML aborts the run.
func TestReportSurfacesAParseFailure(t *testing.T) {
	t.Parallel()

	_, err := wfpolicy.Report(reader(map[string]string{"a.yml": "jobs:\n  - [unclosed\n"}), []string{"a.yml"})

	require.Error(t, err)
	assert.ErrorIs(t, err, wfpolicy.ErrParse)
}

// TestReportOfNoFilesIsAnEmptyReport pins the trivial case explicitly.
func TestReportOfNoFilesIsAnEmptyReport(t *testing.T) {
	t.Parallel()

	report, err := wfpolicy.Report(reader(nil), nil)

	require.NoError(t, err)
	assert.Empty(t, report.Diagnostics)
}
