package wfpolicy_test

import (
	"testing"

	goyze "github.com/gomatic/go-yze"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	wfpolicy "github.com/gomatic/yze-yml-wfpolicy"
)

// analyze runs the analyzer over one workflow, failing the test on a parse
// error.
// analyze runs the analyzer with NO configured owners, which is the third-party
// half of the rule. It goes through DiagnosticsFor rather than Diagnostics on
// purpose: Diagnostics reads the process environment, so a suite built on it
// passed or failed according to what the developer happened to have exported —
// verified, `YZE_WFPOLICY_OWNERS=actions go test` used to fail. A unit test may not
// depend on the world.
func analyze(t *testing.T, source string) []goyze.Diagnostic {
	t.Helper()
	diags, err := wfpolicy.Diagnostics("workflow.yml", wfpolicy.Source(source), nil)
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
	assert.Equal(t, "yze/wfpolicy", diags[0].Rule)
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

// TestTheFindingPointsAtTheValue pins the position: a reader jumps to the line
// and column of the `uses:` value, not to the top of the file.
func TestTheFindingPointsAtTheValue(t *testing.T) {
	t.Parallel()

	diags := analyze(t, "jobs:\n  b:\n    steps:\n      - uses: o/a@main\n")

	require.Len(t, diags, 1)
	assert.Equal(t, 4, diags[0].Line)
	assert.Positive(t, diags[0].Col)
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

	_, err := wfpolicy.Diagnostics("workflow.yml", "jobs:\n  - [unclosed\n", nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, wfpolicy.ErrParse)
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

// TestEveryDocumentIsRead pins that a multi-document file is read past its
// first `---`. yaml.Unmarshal decodes only the first document, which made every
// pin after the separator invisible.
func TestEveryDocumentIsRead(t *testing.T) {
	t.Parallel()

	diags := analyze(
		t,
		"jobs:\n  b:\n    steps:\n      - uses: o/a@v1\n---\njobs:\n  c:\n    steps:\n      - uses: o/a@main\n",
	)

	require.Len(t, diags, 1, "the second document is analyzed too")
	assert.Contains(t, diags[0].Message, `"main"`)
}

// TestASyntaxErrorInALaterDocumentIsAToolFailure pins the other half of
// multi-document reading, and the more dangerous half: decoding only the first
// document turned a file whose second document is unparseable into a CLEAN
// PASS, which is exactly the silent success this rule exists to prevent.
func TestASyntaxErrorInALaterDocumentIsAToolFailure(t *testing.T) {
	t.Parallel()

	_, err := wfpolicy.Diagnostics("workflow.yml", "jobs: {}\n---\njobs:\n  - [unclosed\n", nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, wfpolicy.ErrParse)
}

// TestASurroundingSpaceDoesNotHideARef pins that a quoted value's whitespace is
// trimmed. GitHub resolves `"o/a@main "` to the same branch, so a trailing
// space inside the quotes must not buy an author a silent pass.
func TestASurroundingSpaceDoesNotHideARef(t *testing.T) {
	t.Parallel()

	assert.Len(t, analyze(t, "jobs:\n  b:\n    steps:\n      - uses: \"o/a@main \"\n"), 1)
}

// TestAContainerImageIsNotAGitRef pins that `docker://` is not read. Its `@`
// introduces an image digest or tag, and calling an image tag a branch is a
// claim about a thing git does not own.
func TestAContainerImageIsNotAGitRef(t *testing.T) {
	t.Parallel()

	assert.Empty(t, analyze(t, "jobs:\n  b:\n    steps:\n      - uses: docker://alpine:latest\n"))
	assert.Empty(t, analyze(t, "jobs:\n  b:\n    steps:\n      - uses: docker://ghcr.io/o/i@main\n"))
}

// TestALocalActionCarriesNoRef pins that a path reference is silent: it names
// this repository's own code at this commit, so there is nothing to pin.
func TestALocalActionCarriesNoRef(t *testing.T) {
	t.Parallel()

	assert.Empty(t, analyze(t, "jobs:\n  b:\n    steps:\n      - uses: ./.github/actions/main\n"))
}

// TestTheFindingPointsAtTheColumnOfTheValue pins the column exactly, not merely
// that one is present: a position that is always 1 navigates to the wrong place
// on every indented step, which is every step a workflow has.
func TestTheFindingPointsAtTheColumnOfTheValue(t *testing.T) {
	t.Parallel()

	diags := analyze(t, "jobs:\n  b:\n    steps:\n      - uses: o/a@main\n")

	require.Len(t, diags, 1)
	assert.Equal(t, 4, diags[0].Line)
	assert.Equal(t, 15, diags[0].Col, "the value begins at column 15 of `      - uses: o/a@main`")
}
