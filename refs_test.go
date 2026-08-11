package wfpolicy_test

// How a `uses:` value is cut into an account and a ref, and what makes a ref one
// that moves. Every case here is a spelling that classified into the WRONG one of
// the analyzer's two opposite rules — which is worse than a missing finding,
// because it tells an author to change something that is already right.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	wfpolicy "github.com/gomatic/yze-yml-wfpolicy"
)

// ourOwners is an account list naming nobody real. The accounts a run treats as
// its own are configuration with no default, so the fixtures use a name no
// registry holds rather than any organisation's.
var ourOwners = wfpolicy.Owners{"acme": true}

// step is a workflow whose one step uses the given reference.
func step(uses string) string {
	return "jobs:\n  b:\n    steps:\n      - uses: " + uses + "\n"
}

// TestACommitIsReadInEitherCaseOfHex pins the classification git itself makes.
// An object name resolves case-insensitively — `@0C907A75…` IS `@0c907a75…` —
// and reading only lowercase told an author who pasted an upper-cased SHA that
// their ref "names no major version we can track", the sentence reserved for a
// ref nobody can classify. This one provably is a commit.
func TestACommitIsReadInEitherCaseOfHex(t *testing.T) {
	t.Parallel()

	for name, ref := range map[string]string{
		"lower": "0c907a75c2c80ebcb7f088228285e798b750cf8f",
		"upper": "0C907A75C2C80EBCB7F088228285E798B750CF8F",
		"mixed": "0c907A75c2c80ebcb7f088228285e798b750cf8F",
	} {
		diags := analyzeFor(t, ourOwners, step("acme/act@"+ref))

		require.Len(t, diags, 1, "%s: an owned action frozen to a commit", name)
		assert.Contains(t, diags[0].Message, "a pinned commit", "%s: named for what it is", name)
		assert.NotContains(t, diags[0].Message, "names no major version", "%s", name)
	}
}

// TestTheCommitLengthBoundsAreTheOnesGitUses pins both ends of the abbreviation
// window, which nothing held: seven is git's own default abbreviation, and below
// it a hex string is far likelier a name somebody chose than a commit anybody
// shortened. Forty is the length of a SHA-1 object name; a longer run is not one.
func TestTheCommitLengthBoundsAreTheOnesGitUses(t *testing.T) {
	t.Parallel()

	for name, ref := range map[string]string{
		"seven":  "0c907a7",
		"forty":  strings.Repeat("a", 40),
		"twenty": strings.Repeat("b", 20),
	} {
		diags := analyzeFor(t, ourOwners, step("acme/act@"+ref))
		require.Len(t, diags, 1, "%s", name)
		assert.Contains(t, diags[0].Message, "a pinned commit", "%s is within the abbreviation window", name)
	}

	for name, ref := range map[string]string{
		"six":        "0c907a",
		"forty-one":  strings.Repeat("a", 41),
		"sixty-four": strings.Repeat("a", 64),
	} {
		diags := analyzeFor(t, ourOwners, step("acme/act@"+ref))
		require.Len(t, diags, 1, "%s", name)
		assert.Contains(t, diags[0].Message, "names no major version", "%s is not a commit anyone abbreviated", name)
	}
}

// TestAFullyQualifiedBranchRefIsOneThatMoves closes the denylist's one hole. A
// ref spelled out in full is a branch BY CONSTRUCTION whatever it is called, so
// it needs no entry and no guess about which names a project uses — and without
// this, writing a ref MORE precisely made it silent.
func TestAFullyQualifiedBranchRefIsOneThatMoves(t *testing.T) {
	t.Parallel()

	for _, ref := range []string{"refs/heads/main", "refs/heads/release/2026", "refs/heads/anything-at-all"} {
		diags := analyzeFor(t, wfpolicy.Owners{}, step("third/party@"+ref))

		require.Len(t, diags, 1, "%s is a branch by construction", ref)
		assert.Contains(t, diags[0].Message, "a ref that moves")
	}

	assert.Empty(t, analyzeFor(t, wfpolicy.Owners{}, step("third/party@refs/tags/v1.2.3")),
		"a tag is presumed fixed, which is the presumption every unlisted ref gets")
}

// TestAReferenceIsCutAtTheFirstAt pins WHICH `@` separates the repository from
// the ref, and holds both halves of the analyzer to the same answer. A repository
// name cannot contain one, so everything past the first is the ref; cutting at
// the last would read `o/a@v1@main` as the branch `main` and report a reference
// that names no such thing.
func TestAReferenceIsCutAtTheFirstAt(t *testing.T) {
	t.Parallel()

	assert.Empty(t, analyzeFor(t, wfpolicy.Owners{}, step("third/party@v1@main")),
		"the ref is `v1@main`, which is not a branch this rule knows")

	diags := analyzeFor(t, ourOwners, step("acme/act@v1@main"))
	require.Len(t, diags, 1, "and the owned half cuts at the same place")
	assert.Contains(t, diags[0].Message, "v1@main", "so both halves name the one ref the value carries")
	assert.NotContains(t, diags[0].Message, `pins "main"`)
}

// TestAnOwnedReferenceWithNoAtNamesNothing pins the guard that keeps a local or
// bare reference out of the owned rule. `acme/act` carries no ref at all, and
// reading one anyway reported that it "pins \"\"" — a finding about an empty
// string, which no author can act on.
func TestAnOwnedReferenceWithNoAtNamesNothing(t *testing.T) {
	t.Parallel()

	assert.Empty(t, analyzeFor(t, ourOwners, step("acme/act")), "no @, no ref, no finding")
	assert.Empty(t, analyzeFor(t, wfpolicy.Owners{}, step("third/party")), "and the same for anyone else's")
}

// TestBothHalvesAgreeAFullyQualifiedBranchIsABranch pins the consistency, not
// just each half. The owned rule read the denylist directly while the third-party
// rule went through the predicate, so one ref got two answers: `refs/heads/main`
// was a moving ref for somebody else's action and a ref that "names no major
// version" for one of ours — two different sentences about the same branch.
func TestBothHalvesAgreeAFullyQualifiedBranchIsABranch(t *testing.T) {
	t.Parallel()

	diags := analyzeFor(t, ourOwners, step("acme/act@refs/heads/main"))

	require.Len(t, diags, 1)
	assert.Contains(t, diags[0].Message, "a ref that moves", "ours rides a branch, and is told so")
	assert.NotContains(t, diags[0].Message, "names no major version")
}

// TestOneSplitAnswersForBothHalvesOfTheRule names repositoryAndRef and pins that
// it is the only reader of a `uses:` value. Each half of the analyzer kept its
// own copy of the same three decisions — trim, refuse a container or a local
// path, cut at the first `@` — and nothing made them agree except that somebody
// wrote them the same way twice. This package has already paid for that drift
// once, in the `@` they cut at.
func TestOneSplitAnswersForBothHalvesOfTheRule(t *testing.T) {
	t.Parallel()

	for name, uses := range map[string]string{
		"container":        "docker://alpine@3.20",
		"container spaced": `" docker://alpine@latest"`,
		"local":            "./.github/actions/x@main",
		"local spaced":     `" ./.github/actions/x@main"`,
		"no ref":           "third/party",
	} {
		assert.Empty(t, analyzeFor(t, wfpolicy.Owners{}, step(uses)),
			"%s: names no git ref, for the third-party half", name)
		assert.Empty(t, analyzeFor(t, wfpolicy.Owners{"third": true, "docker:": true}, step(uses)),
			"%s: and none for the owned half either", name)
	}

	// The same value, read by each half, yields the same ref.
	assert.Empty(t, analyzeFor(t, wfpolicy.Owners{}, step(`" third/party@v1@main"`)),
		"the ref is `v1@main`, which is no branch this rule knows")
	owned := analyzeFor(t, ourOwners, step(`" acme/act@v1@main"`))
	require.Len(t, owned, 1)
	assert.Contains(t, owned[0].Message, "v1@main", "and the owned half reads the same one")
}
