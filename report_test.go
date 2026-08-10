package wfpolicy_test

import (
	"fmt"
	"strings"
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

	report := wfpolicy.Report(read, []string{"a.yml", "b.yml"}, nil)

	require.Len(t, report.Diagnostics, 1)
	assert.Equal(t, "a.yml", report.Diagnostics[0].Path)
}

// TestReportContainsAReadFailureToItsOwnFile pins the containment that replaced
// an aborting run. A file the gate cannot open used to abort and return an empty
// report, so one unreadable file cost every OTHER file its findings — and a gate
// reporting nothing is indistinguishable from a clean one. Both siblings already
// answered this way. The file is still REPORTED, with the cause, so nothing is
// passed over in silence; it simply can no longer silence its neighbours.
func TestReportContainsAReadFailureToItsOwnFile(t *testing.T) {
	t.Parallel()

	read := reader(map[string]string{"pinned.yml": "jobs:\n  b:\n    steps:\n      - uses: o/a@main\n"})

	report := wfpolicy.Report(read, []string{"missing.yml", "pinned.yml"}, nil)

	paths := map[string]string{}
	for _, d := range report.Diagnostics {
		paths[d.Path] += d.Message
	}
	assert.Contains(t, paths["missing.yml"], "cannot read workflow file")
	assert.Contains(t, paths["missing.yml"], "unreadable", "the cause survives so the reason is visible")
	assert.Contains(t, paths["pinned.yml"], "a ref that moves", "its neighbour keeps every finding it earned")
}

// TestUnreadableReportsEveryTreeTheWalkCouldNotEnter pins the other half of the
// same rule, one level up: a directory the gate cannot descend into is a finding
// rather than a silence, and it does not take the run down with it.
func TestUnreadableReportsEveryTreeTheWalkCouldNotEnter(t *testing.T) {
	t.Parallel()

	diags := wfpolicy.Unreadable([]string{"locked", "also-locked"})

	require.Len(t, diags, 2)
	assert.Equal(t, "locked", diags[0].Path)
	assert.Equal(t, 1, diags[0].Line)
	assert.Equal(t, wfpolicy.Rule, diags[0].Rule)
	assert.Contains(t, diags[0].Message, "cannot read workflow file")
	assert.Empty(t, wfpolicy.Unreadable(nil), "and nothing unreadable is nothing to report")
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

	report := wfpolicy.Report(read, []string{"broken.yml", "pinned.yml"}, nil)

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

	report := wfpolicy.Report(reader(nil), nil, nil)

	assert.Empty(t, report.Diagnostics)
}

// TestTheReportIsBoundedByFileAndByRun pins the two caps the size limit does not
// provide. Three hundred files each WITHIN the size limit produced 1 092 000
// diagnostics, a 437 MB report and 1.94 GB resident — a gate falling over on
// input it had already accepted as fine.
func TestTheReportIsBoundedByFileAndByRun(t *testing.T) {
	t.Parallel()
	crowded := "jobs:\n  b:\n    steps:\n" + strings.Repeat("      - uses: o/a@main\n", 1500)
	files := make([]string, 0, 12)
	contents := map[string]string{}
	for i := range 12 {
		name := fmt.Sprintf("w%02d.yml", i)
		files = append(files, name)
		contents[name] = crowded
	}

	report := wfpolicy.Report(reader(contents), files, nil)

	assert.LessOrEqual(t, len(report.Diagnostics), 10_001, "the run is bounded")
	last := report.Diagnostics[len(report.Diagnostics)-1]
	assert.Contains(t, last.Message, "onward are omitted", "and says so rather than passing over it")
	assert.Contains(t, last.Message, "18000 pin findings", "naming the true total, not the reported one")
	assert.NotEmpty(t, last.Path, "attributed to a file the runner can key on")
}

// TestOneCrowdedFileIsBoundedOnItsOwn names what fileFindings promises and
// pins the per-file cap, so a single
// pathological workflow cannot fill a run's whole allowance.
func TestOneCrowdedFileIsBoundedOnItsOwn(t *testing.T) {
	t.Parallel()
	crowded := "jobs:\n  b:\n    steps:\n" + strings.Repeat("      - uses: o/a@main\n", 1500)

	report := wfpolicy.Report(reader(map[string]string{"w.yml": crowded}), []string{"w.yml"}, nil)

	require.Len(t, report.Diagnostics, 1001)
	assert.Contains(t, report.Diagnostics[1000].Message, "1500 pin findings in this file")
}

// TestTheLibraryRefusesAFileTooLargeToBeAWorkflow pins the bound in the LIBRARY.
// It was installed at the one place the COMMAND reads a file and nowhere else,
// so every other caller of this package — and the exported API is the package —
// had none: 64 times the limit was 463 MB resident, and 512 times it was 3.6 GB,
// each returning a clean result.
func TestTheLibraryRefusesAFileTooLargeToBeAWorkflow(t *testing.T) {
	t.Parallel()
	head := "jobs:\n  b:\n    steps:\n      - uses: o/a@v1\n"
	atLimit := head + strings.Repeat("#", int(wfpolicy.SizeLimit)-len(head))
	require.Len(t, atLimit, int(wfpolicy.SizeLimit))

	_, err := wfpolicy.Diagnostics("w.yml", wfpolicy.Source(atLimit), nil)
	assert.NoError(t, err, "a file exactly at the limit is read")

	_, over := wfpolicy.Diagnostics("w.yml", wfpolicy.Source(atLimit+"#"), nil)
	assert.ErrorIs(t, over, wfpolicy.ErrTooLarge, "and one byte more is refused")
}
