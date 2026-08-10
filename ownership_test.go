package wfpolicy_test

import (
	"testing"

	goyze "github.com/gomatic/go-yze"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	wfpolicy "github.com/gomatic/yze-yml-wfpolicy"
)

// analyzeFor runs the analyzer with an explicit owner list.
func analyzeFor(t *testing.T, owners wfpolicy.Owners, source string) []goyze.Diagnostic {
	t.Helper()
	diags, err := wfpolicy.DiagnosticsFor("workflow.yml", wfpolicy.Source(source), owners)
	require.NoError(t, err)
	return diags
}

// TestAnOwnedActionMustTrackItsMajorTag pins the rule that is the exact
// opposite of the moving-ref one, and which applies turns entirely on who owns
// the action. An action this fleet publishes must float: pinning a patch means
// a CVE fix or a gate change needs an edit in every repository that consumes
// it, which is how a fleet ends up on four different versions of its own gate.
func TestAnOwnedActionMustTrackItsMajorTag(t *testing.T) {
	t.Parallel()

	owners := wfpolicy.Owners{"acme": true}

	for _, ref := range []string{"v2", "v10"} {
		diags := analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: acme/build-tools/ci/go@"+ref+"\n")
		assert.Empty(t, diags, "@%s is the major tag, which is what ours must track", ref)
	}

	for _, ref := range []string{"v2.19.1", "v2.0.0", "0c907a75c2c80ebcb7f088228285e798b750cf8f"} {
		diags := analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: acme/build-tools/ci/go@"+ref+"\n")
		require.Len(t, diags, 1, "@%s freezes an action we publish", ref)
		assert.Contains(t, diags[0].Message, "is ours", "the message says why the rule inverted")
		assert.Contains(t, diags[0].Message, "pins", "a frozen version is described as pinned")
	}
}

// TestAnOwnedActionOnABranchIsNamedAsABranch pins the third case, which is the
// one the whole fleet is actually in. `@main` is neither frozen nor a
// deliberate upgrade path: it can be force-pushed and names no release, so
// calling it a "pin" would describe it as the opposite of what it is.
func TestAnOwnedActionOnABranchIsNamedAsABranch(t *testing.T) {
	t.Parallel()

	owners := wfpolicy.Owners{"acme": true}

	diags := analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: acme/admin-tools@main\n")

	require.Len(t, diags, 1)
	assert.Contains(t, diags[0].Message, "a branch", "it rides a branch, it does not pin one")
	assert.NotContains(t, diags[0].Message, "pins", "and the message never calls a branch a pin")
	assert.Contains(t, diags[0].Message, "major tag")
}

// TestTheFloatRuleNamesTheRefTheAuthorShouldHaveWritten pins the fix in the
// message: a reader should not have to work out which major tag a pinned
// version belongs to.
func TestTheFloatRuleNamesTheRefTheAuthorShouldHaveWritten(t *testing.T) {
	t.Parallel()

	owners := wfpolicy.Owners{"acme": true}

	diags := analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: acme/build-tools@v2.19.1\n")

	require.Len(t, diags, 1)
	assert.Contains(t, diags[0].Message, "`@v2`", "the major tag is named outright")
}

// TestRefDiagnosticInvertsOnlyForAnOwnedAccount pins that the inversion is
// scoped to owned accounts, which is the whole hinge of the rule: a third
// party's pinned `@v5.1.2` must stay exactly where it is — we do not control
// what they retag — while their `@main` is still the supply-chain hole this
// analyzer was built for.
func TestRefDiagnosticInvertsOnlyForAnOwnedAccount(t *testing.T) {
	t.Parallel()

	owners := wfpolicy.Owners{"acme": true}

	assert.Empty(t, analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v5.1.2\n"),
		"a third party's pinned patch is correct, not a finding")
	assert.Len(t, analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@main\n"), 1,
		"and their moving ref is still reported")
}

// TestAnUnconfiguredRunNeverInventsAnOwnershipFinding pins the default. Which
// accounts are "ours" is a property of the fleet, not of the rule, so a run
// that was never told the accounts reports only the half it can know.
func TestAnUnconfiguredRunNeverInventsAnOwnershipFinding(t *testing.T) {
	t.Parallel()

	source := "jobs:\n  b:\n    steps:\n      - uses: acme/build-tools@v2.19.1\n"

	assert.Empty(t, analyzeFor(t, wfpolicy.Owners{}, source))
	assert.Empty(t, analyzeFor(t, nil, source))
}

// TestConfiguredOwnersReadsTheEnvironment pins how the fleet's accounts reach
// the rule, including the shapes a hand-written list arrives in.
func TestConfiguredOwnersReadsTheEnvironment(t *testing.T) {
	t.Parallel()

	owners := wfpolicy.ConfiguredOwners(func(string) string { return " acme , acme-labs ,, " })

	assert.Equal(t, wfpolicy.Owners{"acme": true, "acme-labs": true}, owners)
	assert.Empty(t, wfpolicy.ConfiguredOwners(func(string) string { return "" }), "unset means inert")
}

// TestALocalOrContainerActionIsNeverOwned pins that the float rule reads only
// what it can attribute: a path reference names no account, and a container
// image's tag is not a git ref at all.
func TestALocalOrContainerActionIsNeverOwned(t *testing.T) {
	t.Parallel()

	owners := wfpolicy.Owners{"acme": true, "docker:": true}

	assert.Empty(t, analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: ./.github/actions/x@v1.2.3\n"))
	assert.Empty(t, analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: docker://alpine:3.20\n"))
}

// TestDiagnosticsReadsTheOwnerListFromTheEnvironment pins the ONE path that
// connects the configuration to the rule. Nothing exercised it: a change making
// Diagnostics ignore the environment entirely, and a change renaming the
// variable, both passed the whole suite at 100% coverage — so the documented
// configuration surface of the analyzer could have been dead in every
// production invocation without a single test noticing.
//
// It does not run in parallel because it sets a process-wide variable, and it
// sets it rather than reading whatever was there: that is what makes it a unit
// test.
func TestDiagnosticsReadsTheOwnerListFromTheEnvironment(t *testing.T) {
	source := wfpolicy.Source("jobs:\n  b:\n    steps:\n      - uses: acme/build-tools@v2.19.1\n")

	t.Setenv("YZE_WFPIN_OWNERS", "acme")
	configured, err := wfpolicy.Diagnostics("workflow.yml", source)
	require.NoError(t, err)
	require.Len(t, configured, 1, "the account is ours, so a pinned patch is a finding")
	assert.Contains(t, configured[0].Message, "is ours")

	t.Setenv("YZE_WFPIN_OWNERS", "someone-else")
	other, err := wfpolicy.Diagnostics("workflow.yml", source)
	require.NoError(t, err)
	assert.Empty(t, other, "a third party's pinned patch is correct, not a finding")

	t.Setenv("YZE_WFPIN_OWNERS", "")
	unset, err := wfpolicy.Diagnostics("workflow.yml", source)
	require.NoError(t, err)
	assert.Empty(t, unset, "and an unconfigured run leaves the float half inert")
}

// TestOwnershipIgnoresTheCaseOfAnAccountName pins the fold. GitHub resolves an
// account case-insensitively — `Actions/Checkout` IS `actions/checkout` — so a
// mis-cased reference ran the identical action while receiving the OPPOSITE
// instruction, and a mis-cased entry in the owner list silently made this half
// of the analyzer inert with no error at all.
func TestOwnershipIgnoresTheCaseOfAnAccountName(t *testing.T) {
	t.Parallel()

	for _, spelling := range []string{"acme", "Acme", "ACME"} {
		owners := wfpolicy.ConfiguredOwners(func(string) string { return spelling })
		for _, reference := range []string{"acme/act@v1.2.3", "Acme/act@v1.2.3", "ACME/act@v1.2.3"} {
			diags := analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: "+reference+"\n")
			require.Len(t, diags, 1, "owners=%s reference=%s", spelling, reference)
			assert.Contains(t, diags[0].Message, "is ours", "owners=%s reference=%s", spelling, reference)
		}
	}
}

// TestAPinnedRefNamesTheMajorTagOnlyWhenItHasOne pins what the message tells an
// author to write. A commit SHA belongs to no major version, and printing a
// literal "vN" into an instruction naming the ref they should use handed them
// something that is not a ref.
func TestAPinnedRefNamesTheMajorTagOnlyWhenItHasOne(t *testing.T) {
	t.Parallel()

	owners := wfpolicy.Owners{"acme": true}
	find := func(ref string) string {
		diags := analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: acme/act@"+ref+"\n")
		require.Len(t, diags, 1)
		return diags[0].Message
	}

	assert.Contains(t, find("v2.19.1"), "`@v2`")
	assert.Contains(t, find("2.3.4"), "`@v2`", "a version without the conventional v still has a major")
	for _, ref := range []string{"0c907a75c2c80ebcb7f088228285e798b750cf8f", "v2-beta", "release", "release-1.2"} {
		assert.NotContains(t, find(ref), "vN", "%s belongs to no major version, so none is invented", ref)
		assert.Contains(t, find(ref), "track the major tag")
	}
	assert.NotContains(t, find("release-1.2"), "`@v1`",
		"the version must OPEN the ref; finding one buried inside it invents a major tag the ref never had")
}

// TestAnOwnedReferenceIsTrimmedAndAttributed pins the two guards the owned half
// shares with the moving-ref half: surrounding space inside a quoted value is
// not part of the reference, and a local path names no account at all.
func TestAnOwnedReferenceIsTrimmedAndAttributed(t *testing.T) {
	t.Parallel()

	owners := wfpolicy.Owners{"acme": true, ".": true}

	assert.Len(t, analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: \" acme/act@v1.2.3 \"\n"), 1,
		"a quoted value's whitespace is not part of the reference")
	assert.Empty(t, analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: ./.github/actions/x@v1.2.3\n"),
		"a path reference names no account, whatever the owner list says")
}

// TestAnOwnedReferenceWithNoRefNamesNothing pins the degenerate spelling, which
// GitHub rejects outright: `owner/action@` carries no ref to judge in either
// direction.
func TestAnOwnedReferenceWithNoRefNamesNothing(t *testing.T) {
	t.Parallel()

	diags := analyzeFor(t, wfpolicy.Owners{"acme": true}, "jobs:\n  b:\n    steps:\n      - uses: acme/act@\n")

	require.Len(t, diags, 1, "an empty ref is not the major tag, so it is still reported")
	assert.Contains(t, diags[0].Message, "is ours")
}
