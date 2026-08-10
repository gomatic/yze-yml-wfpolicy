package wfpolicy_test

// Reading the owner list out of the environment. Every test here is a spelling a
// user actually pastes, and every one of them used to make the float half of the
// analyzer silently inert with no way to learn it had.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	wfpolicy "github.com/gomatic/yze-yml-wfpolicy"
)

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
	assert.Empty(t, analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: docker://alpine@3.20\n"),
		"an image REFERENCE carries an @, and cutting there names the owner `docker:` — the guard has to "+
			"run before the split or it can never fire")
	assert.Empty(t, analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: \" docker://alpine@latest\"\n"),
		"and a leading space must not turn an image tag into a git ref")
	assert.Empty(t, analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: \" ./.github/actions/x@main\"\n"),
		"nor a local action into a remote one")
}

// TestDiagnosticsNeverReadsTheProcessEnvironment pins that the
// library never reads the process itself. Reading ambient state made every
// caller and every test depend on what happened to be exported — the suite
// passed or failed according to the developer's shell — so the environment is
// read once, by the command, and handed in as a value.
func TestDiagnosticsNeverReadsTheProcessEnvironment(t *testing.T) {
	t.Parallel()

	source := wfpolicy.Source("jobs:\n  b:\n    steps:\n      - uses: acme/build-tools@v2.19.1\n")

	configured, err := wfpolicy.Diagnostics(
		"workflow.yml", source, wfpolicy.ConfiguredOwners(func(string) string { return "acme" }),
	)
	require.NoError(t, err)
	require.Len(t, configured, 1, "the account is ours, so a pinned patch is a finding")
	assert.Contains(t, configured[0].Message, "is ours")

	unset, err := wfpolicy.Diagnostics(
		"workflow.yml",
		source,
		wfpolicy.ConfiguredOwners(func(string) string { return "" }),
	)
	require.NoError(t, err)
	assert.Empty(t, unset, "an unconfigured run leaves the float half inert")
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
	assert.Contains(t, find("2.3.4"), "`@2`", "a version without the conventional v still has a major")
	for _, ref := range []string{"0c907a75c2c80ebcb7f088228285e798b750cf8f", "v2-beta", "release", "release-1.2"} {
		assert.NotContains(t, find(ref), "(`@", "%s belongs to no major version, so none is suggested", ref)
	}
	assert.NotContains(t, find("release-1.2"), "`@1`",
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

// TestAnOwnerEntryIsReducedToItsAccount pins the configuration surface against
// the paste that makes it inert. A reference is attributed by its FIRST path
// segment, so an entry of `owner/repo` matched nothing and said nothing — the
// same silent inertness case sensitivity used to cause, by a different route.
func TestAnOwnerEntryIsReducedToItsAccount(t *testing.T) {
	t.Parallel()

	source := "jobs:\n  b:\n    steps:\n      - uses: acme/act@v1.2.3\n"

	for _, entry := range []string{"acme", "acme/act", "acme/act/sub", "  ACME/Act  "} {
		owners := wfpolicy.ConfiguredOwners(func(string) string { return entry })
		diags := analyzeFor(t, owners, source)
		require.Len(t, diags, 1, "%q names the acme account", entry)
		assert.Contains(t, diags[0].Message, "is ours", "%q", entry)
	}

	assert.Empty(t, analyzeFor(t, wfpolicy.ConfiguredOwners(func(string) string { return "/" }), source),
		"an entry naming no account owns nothing")
}

// TestAZeroPaddedVersionIsNotSuggestedAsATag pins that the advice names a ref
// somebody could actually publish: `@v02` is not one, so a version padded that
// way must not be echoed back as the tag to use.
func TestAZeroPaddedVersionIsNotSuggestedAsATag(t *testing.T) {
	t.Parallel()

	owners := wfpolicy.Owners{"acme": true}
	diags := analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: acme/act@v02.1\n")

	require.Len(t, diags, 1)
	assert.NotContains(t, diags[0].Message, "`@v02`", "no such tag is published")
	assert.NotContains(t, diags[0].Message, "`@v2`", "and neither is a major the ref never named")
	assert.Contains(t, diags[0].Message, "names no major version")
}

// TestAZeroPaddedMajorTagIsNotCompliantEither pins the OTHER half of the same
// rule. The two halves disagreed: the advice refused to ever suggest `@v02`
// because no such tag is published, while the compliance test accepted a
// workflow that wrote one — so a ref this analyzer says cannot exist was
// silently blessed.
func TestAZeroPaddedMajorTagIsNotCompliantEither(t *testing.T) {
	t.Parallel()

	owners := wfpolicy.Owners{"acme": true}

	assert.Len(t, analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: acme/act@v02\n"), 1,
		"a zero-padded major is not a tag anyone publishes")
	assert.Empty(t, analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: acme/act@v2\n"))
}

// TestAnAccountThatTagsWithoutTheVHasACompliantState pins that the rule can be
// SATISFIED by an account following the other convention. `@2` was reported for
// already complying, and `@2.3.4` was told to write a `@v2` such an account
// never publishes — so there was no ref its author could write that this
// analyzer would accept.
func TestAnAccountThatTagsWithoutTheVHasACompliantState(t *testing.T) {
	t.Parallel()

	owners := wfpolicy.Owners{"acme": true}

	assert.Empty(t, analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: acme/act@2\n"),
		"a bare major tag is the compliant form for an account that tags that way")

	diags := analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: acme/act@2.3.4\n")
	require.Len(t, diags, 1)
	assert.Contains(t, diags[0].Message, "`@2`", "the advice keeps the ref's own convention")
	assert.NotContains(t, diags[0].Message, "`@v2`", "and never invents the one it does not use")
}

// TestAFrozenRefIsNamedForWhatItActuallyIs pins the discrimination the frozen
// half was missing. A commit and a ref that is simply not a version are
// different mistakes: the commit sentence explains that a CVE fix needs an edit
// in every consuming repository, which is true of a commit and says nothing at
// all to somebody who wrote `@release-1.2`.
func TestAFrozenRefIsNamedForWhatItActuallyIs(t *testing.T) {
	t.Parallel()

	owners := wfpolicy.Owners{"acme": true}
	find := func(ref string) string {
		diags := analyzeFor(t, owners, "jobs:\n  b:\n    steps:\n      - uses: acme/act@"+ref+"\n")
		require.Len(t, diags, 1, "%s earns a finding", ref)
		return diags[0].Message
	}

	for _, sha := range []string{"0c907a75c2c80ebcb7f088228285e798b750cf8f", "0c907a7"} {
		assert.Contains(t, find(sha), "a pinned commit", "%s is a commit", sha)
	}
	for _, ref := range []string{"v2-beta", "release", "release-1.2", "refs/tags/v2.1.0", ""} {
		assert.Contains(t, find(ref), "names no major version", "%s is not a version", ref)
		assert.NotContains(t, find(ref), "a pinned commit", "%s is provably not a commit", ref)
	}
}

// TestAnAtPrefixedAccountIsStillAnAccount pins the spelling GitHub itself uses.
// `@owner` is how every GitHub surface renders an account, so it is what a user
// pastes into the variable — and it matched nothing, silently, leaving the float
// half of the analyzer inert with no way to learn the list had been rejected.
func TestAnAtPrefixedAccountIsStillAnAccount(t *testing.T) {
	t.Parallel()

	for _, spelling := range []string{"acme", "@acme", "ACME", "@ACME", " @acme ", "acme/act", "@acme/act"} {
		owners := wfpolicy.ConfiguredOwners(func(string) string { return spelling })

		assert.True(t, owners["acme"], "%q names the acme account", spelling)
	}
}
