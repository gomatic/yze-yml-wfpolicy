package main

// The one configuration this command has, exercised end to end. Every other
// test in this package runs with the owner list neutralised, which is right for
// them and left the wiring itself — the variable's name, the lookup, the value's
// journey into the library — with nothing behind it at all.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTheOwnerListReachesTheReportFromTheEnvironment is the one end-to-end pass
// through the only configuration this tool has, and nothing exercised it: every
// test in this package ran with the owner list neutralised, so the whole float
// half of the analyzer could be unwired — the variable renamed, the lookup
// replaced by a constant, the list dropped on the way to the library — with the
// suite fully green and every user's rule silently inert. That is the exact
// "no way to learn it had" this package's own comments were written against,
// unguarded at the one layer where the wiring actually happens.
func TestTheOwnerListReachesTheReportFromTheEnvironment(t *testing.T) {
	// t.Setenv sets the process environment for this test alone and restores it
	// after, so the run stays isolated; it forbids t.Parallel, which no test in
	// this package uses.
	t.Setenv("YZE_WFPOLICY_OWNERS", "acme")
	lookupEnv = realLookupEnv
	t.Cleanup(func() { lookupEnv = func(string) string { return "" } })

	dir := t.TempDir()
	writeWorkflow(t, dir, ".github/workflows/ci.yml",
		"jobs:\n  b:\n    steps:\n      - uses: acme/act@v1.2.3\n      - uses: third/party@main\n")
	buf := swapStdout(t)

	require.Equal(t, 0, run([]string{dir}))
	assert.Contains(t, buf.String(), "acme is ours",
		"the configured account inverts the rule, all the way from the environment to stdout")
	assert.Contains(t, buf.String(), "a ref that moves",
		"and the half that needs no configuration still applies")
}

// TestWithNoOwnerListConfiguredOnlyThePinningHalfApplies pins the other side of
// the same wiring: an unconfigured run is not a broken one. It reports what needs
// no local knowledge and says nothing about ownership it was told nothing about.
func TestWithNoOwnerListConfiguredOnlyThePinningHalfApplies(t *testing.T) {
	t.Setenv("YZE_WFPOLICY_OWNERS", "")
	lookupEnv = realLookupEnv
	t.Cleanup(func() { lookupEnv = func(string) string { return "" } })

	dir := t.TempDir()
	writeWorkflow(t, dir, ".github/workflows/ci.yml",
		"jobs:\n  b:\n    steps:\n      - uses: acme/act@v1.2.3\n      - uses: third/party@main\n")
	buf := swapStdout(t)

	require.Equal(t, 0, run([]string{dir}))
	assert.NotContains(t, buf.String(), "is ours", "nothing is ours until somebody says so")
	assert.Contains(t, buf.String(), "a ref that moves")
}

// TestConfiguredOwnersHasNoDefault names configuredOwners and pins the claim
// its doc makes. There is no built-in owner list and never will be: shipping one
// would be wrong for every user but the author, and would publish that author's
// account names inside a public tool.
func TestConfiguredOwnersHasNoDefault(t *testing.T) {
	t.Setenv("YZE_WFPOLICY_OWNERS", "")
	lookupEnv = realLookupEnv
	t.Cleanup(func() { lookupEnv = func(string) string { return "" } })

	assert.Empty(t, configuredOwners(), "an unconfigured run owns nothing")

	t.Setenv("YZE_WFPOLICY_OWNERS", "acme")
	assert.Len(t, configuredOwners(), 1, "and owns exactly what it was told to")
}
