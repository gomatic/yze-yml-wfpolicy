package wfpolicy_test

import (
	"testing"

	errs "github.com/gomatic/go-error"
	goyze "github.com/gomatic/go-yze"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	wfpolicy "github.com/gomatic/yze-yml-wfpolicy"
)

// errUnreadable stands in for whatever the filesystem refuses with.
const errUnreadable errs.Const = "unreadable"

// analyze runs the analyzer over one workflow, failing the test on a parse
// error.
func analyze(t *testing.T, source string) []goyze.Diagnostic {
	t.Helper()
	diags, err := wfpolicy.Diagnostics("workflow.yml", wfpolicy.Source(source))
	require.NoError(t, err)
	return diags
}

// TestAFixedRefIsSilent pins the conforming shapes, which is the load-bearing
// direction: a tag, a full commit SHA, a local action and a container action
// are every form the fleet actually writes, and a rule that fired on any of
// them would be switched off the day it landed.
func TestAFixedRefIsSilent(t *testing.T) {
	t.Parallel()

	diags := analyze(t, `
jobs:
  build:
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-go@v5.2.0
      - uses: actions/cache@0c907a75c2c80ebcb7f088228285e798b750cf8f
      - uses: ./.github/actions/local
      - uses: docker://alpine:3.20
`)

	assert.Empty(t, diags)
}

// TestAMovingBranchIsReported pins the rule itself, and that the finding names
// both the offending value and the branch, so the author does not have to
// re-derive which part is wrong.
func TestAMovingBranchIsReported(t *testing.T) {
	t.Parallel()

	diags := analyze(t, `
jobs:
  build:
    steps:
      - uses: owner/action@main
`)

	require.Len(t, diags, 1)
	assert.Contains(t, diags[0].Message, "owner/action@main")
	assert.Contains(t, diags[0].Message, `"main"`)
	assert.Equal(t, "yze/wfpin", diags[0].Rule)
}

// TestEveryConventionalBranchNameIsReported pins the denylist's membership.
// Each of these is a branch by construction; a ref outside the list is presumed
// fixed, which is the decision that keeps the rule free of guesses.
func TestEveryConventionalBranchNameIsReported(t *testing.T) {
	t.Parallel()

	for _, ref := range []string{"main", "master", "HEAD", "develop", "dev", "trunk", "latest"} {
		diags := analyze(t, "jobs:\n  b:\n    steps:\n      - uses: o/a@"+ref+"\n")
		assert.Len(t, diags, 1, "%s names a branch", ref)
	}

	for _, ref := range []string{"v1", "v2.3.4", "release-1.0", "0c907a75c2c80ebcb7f088228285e798b750cf8f"} {
		diags := analyze(t, "jobs:\n  b:\n    steps:\n      - uses: o/a@"+ref+"\n")
		assert.Empty(t, diags, "%s is not provably a branch, so it is not guessed at", ref)
	}
}

// TestUsesIsFoundWhereverItAppears pins that the walk looks for the KEY rather
// than a fixed path to it. A workflow spells `uses` in a step, in a reusable
// workflow job, and in a composite action's step; enumerating those paths would
// silently miss whichever shape is added next.
func TestUsesIsFoundWhereverItAppears(t *testing.T) {
	t.Parallel()

	diags := analyze(t, `
jobs:
  reusable:
    uses: owner/repo/.github/workflows/x.yml@main
  build:
    steps:
      - uses: owner/action@master
runs:
  steps:
    - uses: owner/composite@develop
`)

	assert.Len(t, diags, 3, "a step, a reusable job, and a composite step are all read")
}

// TestTheFindingPointsAtTheValue pins the position: a reader jumps to the line
// and column of the `uses:` value, not to the top of the file.
func TestTheFindingPointsAtTheValue(t *testing.T) {
	t.Parallel()

	diags := analyze(t, "jobs:\n  b:\n    steps:\n      - uses: o/a@main\n")

	require.Len(t, diags, 1)
	assert.Equal(t, 4, diags[0].Line)
	assert.Positive(t, diags[0].Col)
}

// TestAKeyNamedUsesElsewhereIsStillRead documents a deliberate consequence of
// looking for the key: a mapping whose key happens to be `uses` is read
// wherever it sits. Inside a workflow file that is the right call — every such
// key GitHub defines IS an action reference — and the command only ever hands
// this analyzer files under .github/workflows.
func TestAKeyNamedUsesElsewhereIsStillRead(t *testing.T) {
	t.Parallel()

	diags := analyze(t, "anything:\n  nested:\n    uses: o/a@main\n")

	assert.Len(t, diags, 1)
}

// TestANonScalarUsesIsNotRead pins a guard against malformed input: `uses:`
// with a list or mapping value is not an action reference, and reading one
// would invent a finding from a shape GitHub itself rejects.
func TestANonScalarUsesIsNotRead(t *testing.T) {
	t.Parallel()

	assert.Empty(t, analyze(t, "jobs:\n  b:\n    steps:\n      - uses:\n          - o/a@main\n"))
}

// TestAnEmptyDocumentIsSilent pins the trivial input, which a walk over a nil
// document could otherwise panic on.
func TestAnEmptyDocumentIsSilent(t *testing.T) {
	t.Parallel()

	assert.Empty(t, analyze(t, ""))
	assert.Empty(t, analyze(t, "\n"))
	assert.Empty(t, analyze(t, "# only a comment\n"))
}

// TestInvalidYAMLIsAToolFailure pins that unreadable input is an error rather
// than a clean pass — a gate reporting success over a file it could not parse
// is the failure this suite exists to prevent.
func TestInvalidYAMLIsAToolFailure(t *testing.T) {
	t.Parallel()

	_, err := wfpolicy.Diagnostics("workflow.yml", "jobs:\n  - [unclosed\n")

	require.Error(t, err)
	assert.ErrorIs(t, err, wfpolicy.ErrParse)
}

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

// TestEveryDiagnosticCarriesTheSuiteContract pins the fields the stickler
// consumer reads: without the rule id a finding cannot be softened, baselined
// or attributed, and without a position it cannot be navigated to.
func TestEveryDiagnosticCarriesTheSuiteContract(t *testing.T) {
	t.Parallel()

	diags := analyze(t, "jobs:\n  b:\n    steps:\n      - uses: o/a@main\n")

	require.NotEmpty(t, diags)
	for _, d := range diags {
		assert.Equal(t, "yze", d.Tool)
		assert.Equal(t, wfpolicy.Rule, d.Rule)
		assert.Equal(t, "workflow.yml", d.Path)
		assert.Equal(t, goyze.SeverityError, d.Severity)
		assert.Positive(t, d.Line)
		assert.Positive(t, d.Col)
		assert.NotEmpty(t, d.Message)
	}
}
