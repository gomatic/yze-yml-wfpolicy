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
