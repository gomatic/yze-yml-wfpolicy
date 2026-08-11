package wfpolicy

// Ownership decides WHICH of this analyzer's two opposite rules applies to a
// reference. Somebody else's action must not move under us; ours must not be
// frozen by us. Both are the same concern — the code a workflow runs should
// change only when someone decides it should — and they point in opposite
// directions purely because of who holds the tag.

import (
	"fmt"
	"strings"
)

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
	case isMovingRef(ref):
		// The SAME question the other half asks, asked through the same
		// predicate. Reading the denylist directly here meant the two halves
		// could answer differently about one ref, and they did: a fully
		// qualified `refs/heads/main` was a moving ref for a third party and a
		// ref that "names no major version" for us.
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
