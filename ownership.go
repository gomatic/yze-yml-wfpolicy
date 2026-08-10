package wfpolicy

// Ownership decides WHICH of this analyzer's two opposite rules applies to a
// reference. Somebody else's action must not move under us; ours must not be
// frozen by us. Both are the same concern — the code a workflow runs should
// change only when someone decides it should — and they point in opposite
// directions purely because of who holds the tag.

import (
	"fmt"
	"regexp"
	"strings"
)

// gitRef is the ref half of a `uses:` value — what follows the `@`.
type gitRef string

// majorTag is the only ref an owned action may name: a bare major version,
// never `@v2.19.1` and never a commit SHA.
//
// The leading `v` is OPTIONAL, and zero-padding is refused, because both had to
// agree with [majorPrefix] and neither did. `@v02` was accepted as compliant
// while the advice half refused to ever suggest it — the repo's own test says
// no such tag is published — and an account that tags `2.3.4` without the `v`
// had NO compliant state at all: `@2` was reported for already complying, and
// `@2.3.4` was told to write a `@v2` it never publishes.
var majorTag = regexp.MustCompile(`^v?(0|[1-9][0-9]*)$`)

// refDiagnostic is the message one `uses:` value earns, if any. The two rules
// are exact opposites and which applies turns entirely on who owns the action:
// somebody else's must not move under us, and ours must not be frozen by us.
func refDiagnostic(owners Owners, uses usesRef) (string, bool) {
	owner, ref, ok := ownedRef(owners, uses)
	if ok {
		return ownedDiagnostic(owner, uses, ref)
	}
	moving, isMoving := movingRef(uses)
	if !isMoving {
		return "", false
	}
	return fmt.Sprintf(message, uses, moving), true
}

// ownedDiagnostic is the message an owned action's ref earns. The major tag is
// silent; a branch and a frozen version are different mistakes and are named
// differently, because the fix a reader needs is not the same sentence.
func ownedDiagnostic(owner Owner, uses usesRef, ref gitRef) (string, bool) {
	switch {
	case commitSHA.MatchString(string(ref)):
		// Tested BEFORE the major tag, because the two patterns overlap: an
		// all-decimal abbreviated SHA — about one in twenty-seven — is also a
		// bare major version, and `@1234567` passed as compliant while
		// `@0123456` beside it was reported. A frozen commit reading as a
		// floating tag is the silent pass this rule exists to prevent.
		return fmt.Sprintf(ownedCommitMessage, uses, ref, owner), true
	case majorTag.MatchString(string(ref)):
		return "", false
	case movingRefs[string(ref)]:
		return fmt.Sprintf(ownedBranchMessage, uses, ref, owner), true
	}
	if major, ok := majorOf(ref); ok {
		// The advice keeps the ref's OWN convention. Advising `@v2` to an
		// account that publishes `2.3.4` hands them a tag they never cut, on
		// exactly the reasoning that made the unknown-major branch exist.
		return fmt.Sprintf(ownedMessage, uses, ref, owner, major), true
	}
	return fmt.Sprintf(ownedUnknownMessage, uses, ref, owner), true
}

// commitSHA is a ref that IS a commit — full or abbreviated. It is told apart
// from an unrecognised ref because the two are different mistakes needing
// different sentences: the frozen-commit message explains that a CVE fix would
// need an edit in every consuming repository, which is true of a commit and
// says nothing at all to somebody who wrote `@release-1.2`.
var commitSHA = regexp.MustCompile(`^[0-9a-f]{7,40}$`)

// ownedRef is the account and ref of an action this fleet owns, when the value
// names one.
func ownedRef(owners Owners, uses usesRef) (Owner, gitRef, bool) {
	trimmed := strings.TrimSpace(string(uses))
	// Checked on the WHOLE value, before the split: cutting `docker://img@tag`
	// at its first `@` yields the owner `docker:`, so a guard applied to that
	// could only ever fire for an owner list that literally contained
	// `docker:` — it was unreachable in every real configuration.
	if strings.HasPrefix(trimmed, containerScheme) || strings.HasPrefix(trimmed, ".") {
		return "", "", false
	}
	repo, ref, found := strings.Cut(trimmed, "@")
	if !found {
		return "", "", false
	}
	owner, _, _ := strings.Cut(repo, "/")
	// FOLDED. GitHub resolves an account name case-insensitively — `Actions/
	// Checkout` IS `actions/checkout` — so a mis-cased reference ran the same
	// action while getting the OPPOSITE rule, and a mis-cased entry in the
	// owner list silently made this half of the analyzer inert with no error.
	// The REF keeps its case, because git refs really are case-sensitive.
	if !owners[Owner(strings.ToLower(owner))] {
		return "", "", false
	}
	return Owner(owner), gitRef(ref), true
}

// majorOf is the major version a pinned ref belongs to, reporting whether it
// has one at all. A commit SHA does not, and neither does a ref that is not a
// version — printing a literal "vN" into an instruction that tells an author
// which ref to write handed them something that is not a ref.
func majorOf(ref gitRef) (string, bool) {
	version := majorPrefix.FindStringSubmatch(string(ref))
	if version == nil {
		return "", false
	}
	// The leading `v` is carried through EXACTLY as the ref wrote it. The tag
	// suggested has to be one the account actually publishes, and an account
	// that tags `2.3.4` does not publish `v2` — advising it hands the author a
	// ref that does not exist, which is the very reason the no-major branch
	// below refuses to invent one.
	return version[1] + version[2], true
}

// majorPrefix reads the major version out of a pinned tag, with or without the
// conventional leading v: `v2.19.1`, `2.3.4` and `v2.19` all belong to major 2.
var majorPrefix = regexp.MustCompile(`^(v?)(0|[1-9][0-9]*)\.`)
