package wfpolicy

// The owner list: which accounts this run treats as its own, and how a user
// spells them. It has NO default and never will — which accounts are "ours" is
// a property of whoever runs the check, never of this tool. A list shipped in
// the tool would be wrong for every user but one, and would publish the account
// names of the one it was right for.

import "strings"

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
const ownersVariable = "YZE_WFPOLICY_OWNERS"

// It is named for the analyzer, like the rule id: the variable was
// YZE_WFPIN_OWNERS while the analyzer had grown a second, opposite rule that
// has nothing to do with pinning, and configuration that contradicts the thing
// it configures is read wrong by whoever inherits it.

// ConfiguredOwners is the owner list this process was configured with, read
// from the environment. It is a function rather than a package variable so a
// test can set the variable and see the change, and so an unset variable is
// plainly an empty list rather than a nil surprise.
func ConfiguredOwners(lookup func(string) string) Owners {
	owners := Owners{}
	for _, name := range strings.Split(lookup(ownersVariable), ",") {
		// Reduced to the ACCOUNT, because a reference is attributed by its
		// first path segment: pasting `owner/repo` where an owner belongs
		// matched nothing and said nothing, the same silent inertness that
		// case sensitivity used to cause.
		// The leading `@` is stripped: GitHub renders an account as `@owner`
		// everywhere in its own UI, so it is the spelling a user pastes — and
		// it silently matched nothing, which is the same inertness that case
		// sensitivity and the `owner/repo` paste used to cause.
		account, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimSpace(name), "@"), "/")
		if account != "" {
			owners[Owner(strings.ToLower(account))] = true
		}
	}
	return owners
}
