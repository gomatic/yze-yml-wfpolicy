package wfpolicy

// What a `uses:` reference IS: the ref it names, whether that ref moves, and
// which major version it belongs to. Ownership decides which RULE applies to a
// reference; this file decides what the reference says, and the two halves of
// the analyzer both read it here so they can never disagree about one value.

import (
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

// commitSHA is a ref that IS a commit — full or abbreviated. It is told apart
// from an unrecognised ref because the two are different mistakes needing
// different sentences: the frozen-commit message explains that a CVE fix would
// need an edit in every consuming repository, which is true of a commit and
// says nothing at all to somebody who wrote `@release-1.2`.
//
// Either case of hex, because git resolves an object name case-insensitively:
// `@0C907A75…` is the same commit as `@0c907a75…`. Reading only lowercase told
// an author who pasted an upper-cased SHA that their ref "names no major version
// we can track", which is the sentence for a ref nobody can classify — and this
// one provably IS a commit, the exact thing [ownedCommitMessage] exists to say.
//
// Seven is the floor because it is git's own default abbreviation: below it a
// hex string is far more likely a name somebody chose — `abc123` is a plausible
// tag — than a commit anybody abbreviated. Forty is the ceiling because that is
// the length of a SHA-1 object name; a longer hex run is not one.
var commitSHA = regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`)

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

// movingRefs are the refs that MOVE by construction — branches, the symbolic
// HEAD, and `latest`, which is conventionally a tag that is re-pointed rather
// than a branch. The set is a denylist on purpose: every other ref is presumed
// fixed, because telling an immutable tag from a re-pointed one is not
// decidable from the text, and a gate that guesses is a gate that gets
// switched off.
var movingRefs = map[string]bool{
	"main":    true,
	"master":  true,
	"HEAD":    true,
	"develop": true,
	"dev":     true,
	"trunk":   true,
	"latest":  true,
}

// branchNamespace is the ref path under which every branch lives. A ref spelled
// out in full is a branch BY CONSTRUCTION — `refs/heads/anything` is one
// whatever it is called — so it needs no entry in the denylist above and no
// guess about which names a project uses. Without it the fully-qualified
// spelling of the very refs listed above was silent, which is the denylist's
// one hole reachable by writing a ref more precisely.
//
// `refs/tags/` is deliberately absent: a tag is presumed fixed, which is the
// same presumption every unlisted ref gets.
const branchNamespace = "refs/heads/"

// isMovingRef reports a ref that moves by construction.
func isMovingRef(ref gitRef) bool {
	return movingRefs[string(ref)] || strings.HasPrefix(string(ref), branchNamespace)
}

// containerScheme marks a `uses:` value naming a container image rather than an
// action repository. Its `@` introduces an image digest or tag, which is not a
// git ref, so reading one would tell an author their image tag is a branch.
const containerScheme = "docker://"

// movingRef is the ref a `uses:` value resolves, when it resolves one. A value
// with no `@` names a local action, which carries no ref to move, and a
// container reference names no git ref at all.
func movingRef(uses usesRef) (string, bool) {
	// Trimmed FIRST. YAML preserves the space inside a quoted scalar, and
	// testing the prefixes before trimming meant a single leading space turned
	// a container image into a git ref and a local action into a remote one —
	// each producing a finding the doc says this rule never makes.
	trimmed := strings.TrimSpace(string(uses))
	if strings.HasPrefix(trimmed, containerScheme) || strings.HasPrefix(trimmed, ".") {
		return "", false
	}
	// Cut at the FIRST `@`, which is where GitHub cuts: a repository name cannot
	// contain one, so everything past it is the ref — and a ref may, so cutting
	// at the last would read `o/a@v1@main` as the branch `main` and report a
	// reference that names no such thing. [ownedRef] cuts the same way, and a
	// test holds them to it: the two halves disagreeing about which `@` is the
	// separator would give one value two different refs.
	_, ref, found := strings.Cut(trimmed, "@")
	if !found {
		return "", false
	}
	return ref, isMovingRef(gitRef(ref))
}
