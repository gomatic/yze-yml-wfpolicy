package wfpolicy

// Ownership decides WHICH of this analyzer's two opposite rules applies to a
// reference. Somebody else's action must not move under us; ours must not be
// frozen by us. Both are the same concern — the code a workflow runs should
// change only when someone decides it should — and they point in opposite
// directions purely because of who holds the tag.

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// gitRef is the ref half of a `uses:` value — what follows the `@`.
type gitRef string

// Owner is an account or organisation whose actions this fleet owns.
type Owner string

// Owners are the accounts whose actions must FLOAT. It is configuration rather
// than a constant, and it has NO default, because which accounts are "ours" is
// a property of whoever is running the check — never of this tool. Anyone can
// use this analyzer; they list their own accounts and the rule inverts for
// those. A list shipped in the tool would be wrong for every user but one, and
// would publish the account names of the one it was right for.
type Owners map[Owner]bool

// ownersVariable is the environment variable the owner list is read from: a
// comma-separated list of accounts. Empty leaves the float rule inert, so an
// unconfigured run reports only the moving-ref half rather than inventing a
// finding about a repository whose ownership it was told nothing about.
//
// An environment variable is the whole configuration surface on purpose. The
// value is the user's private business — it names the accounts they control —
// so it must be settable from somewhere private, and it must reach a CI run
// without ever appearing in a public repository. A repository or organisation
// secret/variable passed through in a workflow's `env:` does both: the public
// workflow names the VARIABLE, and the value stays wherever its owner put it.
const ownersVariable = "YZE_WFPIN_OWNERS"

// majorTag is the only ref an owned action may name: `@v2`, never `@v2.19.1`
// and never a commit SHA.
var majorTag = regexp.MustCompile(`^v[0-9]+$`)

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
	case majorTag.MatchString(string(ref)):
		return "", false
	case movingRefs[string(ref)]:
		return fmt.Sprintf(ownedBranchMessage, uses, ref, owner), true
	}
	return fmt.Sprintf(ownedMessage, uses, ref, owner, majorOf(ref)), true
}

// ownedRef is the account and ref of an action this fleet owns, when the value
// names one.
func ownedRef(owners Owners, uses usesRef) (Owner, gitRef, bool) {
	repo, ref, found := strings.Cut(strings.TrimSpace(string(uses)), "@")
	if !found || strings.HasPrefix(repo, containerScheme) || strings.HasPrefix(repo, ".") {
		return "", "", false
	}
	owner, _, _ := strings.Cut(repo, "/")
	if !owners[Owner(owner)] {
		return "", "", false
	}
	return Owner(owner), gitRef(ref), true
}

// majorOf is the major version a pinned ref belongs to, for a message that
// names the ref the author should have written. A ref that is not a version at
// all — a branch, a SHA — yields "N", because guessing a number from a commit
// hash would be inventing one.
func majorOf(ref gitRef) string {
	if version := majorPrefix.FindStringSubmatch(string(ref)); version != nil {
		return version[1]
	}
	return "N"
}

// majorPrefix reads the major version out of a fully-pinned tag.
var majorPrefix = regexp.MustCompile(`^v([0-9]+)\.`)

// environmentOwners is the owner list this process was configured with.
func environmentOwners() Owners {
	return ConfiguredOwners(os.Getenv)
}

// ConfiguredOwners is the owner list this process was configured with, read
// from the environment. It is a function rather than a package variable so a
// test can set the variable and see the change, and so an unset variable is
// plainly an empty list rather than a nil surprise.
func ConfiguredOwners(lookup func(string) string) Owners {
	owners := Owners{}
	for _, name := range strings.Split(lookup(ownersVariable), ",") {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			owners[Owner(trimmed)] = true
		}
	}
	return owners
}
