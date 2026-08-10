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
	diags, err := wfpolicy.Diagnostics("workflow.yml", wfpolicy.Source(source), owners)
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

// TestAnOwnedActionOnAMovingRefIsNamedAsOneNotAsABranch pins the third case,
// which is the one the whole fleet is actually in. `@main` is neither frozen
// nor a deliberate upgrade path, so calling it a "pin" would describe it as the
// opposite of what it is — and calling it a BRANCH would contradict the
// denylist's own reason for holding `latest`, which is conventionally a tag
// that gets re-pointed.
func TestAnOwnedActionOnAMovingRefIsNamedAsOneNotAsABranch(t *testing.T) {
	t.Parallel()

	owners := wfpolicy.Owners{"acme": true}

	diags := analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: acme/admin-tools@main\n")

	require.Len(t, diags, 1)
	assert.Contains(t, diags[0].Message, "a ref that moves", "it rides a moving ref, it does not pin one")
	assert.NotContains(t, diags[0].Message, "pins", "and the message never calls a moving ref a pin")
	assert.Contains(t, diags[0].Message, "major tag")

	// `latest` is in the same denylist and is conventionally a re-pointed TAG,
	// so the wording must not call it a branch either.
	tagged := analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: acme/act@latest\n")
	require.Len(t, tagged, 1)
	assert.NotContains(t, tagged[0].Message, "a branch", "a re-pointed tag is not a branch")
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
