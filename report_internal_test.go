package wfpolicy

import (
	"strings"
	"testing"

	errs "github.com/gomatic/go-error"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// errRefused stands in for whatever the filesystem refuses with.
const errRefused errs.Const = "refused"

// TestAReadFailureFindingCarriesItsSentinelAndItsCause pins what a contained
// read failure has to tell its reader. Containment is only safe if the finding
// says as much as the aborted run used to: the sentinel names WHAT failed and
// the cause names WHY, and both survive into the message an author reads.
func TestAReadFailureFindingCarriesItsSentinelAndItsCause(t *testing.T) {
	t.Parallel()

	err := ErrReadFile.With(errRefused, "path", "a.yml")

	require.ErrorIs(t, err, ErrReadFile, "the sentinel is matchable")
	require.ErrorIs(t, err, errRefused, "and so is the cause beneath it")
	assert.Contains(t, unreadable("a.yml", errRefused).Message, err.Error(),
		"and the finding carries the whole of it")
}

// TestSizeLimitAdmitsAnyRealWorkflow pins the claim the constant makes about
// itself. A limit that turned away a file somebody wrote would be a rule
// silencing itself, which is worse than the unbounded read it replaced.
func TestSizeLimitAdmitsAnyRealWorkflow(t *testing.T) {
	t.Parallel()

	assert.Greater(t, int64(SizeLimit), int64(40<<10),
		"the largest workflow in the fleet is under forty kilobytes")
}

// TestFollowResolvesAnAliasedKey pins the half of follow the orphan test cannot
// reach. A KEY may be written as an alias — `*k: value` — and reading the alias
// node's own empty Value instead of the anchor's made `uses` spelled that way
// invisible, which is a one-line evasion of the whole rule.
func TestFollowResolvesAnAliasedKey(t *testing.T) {
	t.Parallel()

	anchor := &yaml.Node{Kind: yaml.ScalarNode, Value: usesKey}

	assert.Same(t, anchor, follow(&yaml.Node{Kind: yaml.AliasNode, Alias: anchor}))
}

// TestAnUnresolvedAliasValueIsWalkedPastRatherThanDereferenced pins the guard on
// the value half, which the key half already had. An alias normally carries a
// pointer to its anchor; a node built by hand — or one a parser leaves dangling
// — does not, and dereferencing it would crash the analyzer on a document
// instead of reporting it.
func TestAnUnresolvedAliasValueIsWalkedPastRatherThanDereferenced(t *testing.T) {
	t.Parallel()
	orphan := &yaml.Node{Kind: yaml.AliasNode, Value: "missing"}

	visits := 0
	assert.NotPanics(t, func() {
		walk(orphan, schemaKeys, newVisited(), func(*yaml.Node) { visits++ })
	})
	assert.Zero(t, visits, "an alias naming nothing yields nothing")
}

// TestFileFindingsContainsAReadFailureAndBoundsTheRest names fileFindings and
// pins both claims it makes: a file the gate cannot open becomes ONE finding
// against that file rather than the run's error, and a file with more findings
// than anyone can act on is cut with its true count named.
func TestFileFindingsContainsAReadFailureAndBoundsTheRest(t *testing.T) {
	t.Parallel()

	refused, held := fileFindings(func(string) ([]byte, error) { return nil, errRefused }, "locked.yml", nil)
	require.Len(t, refused, 1, "one unreadable file is one finding")
	assert.Equal(t, 1, held)
	assert.Equal(t, "locked.yml", refused[0].Path)

	crowded := "jobs:\n  b:\n    steps:\n" + strings.Repeat("      - uses: o/a@main\n", findingLimit+250)
	found, all := fileFindings(func(string) ([]byte, error) { return []byte(crowded), nil }, "w.yml", nil)

	assert.Len(t, found, findingLimit+1, "the cut, plus the notice that says so")
	assert.Equal(t, findingLimit+250, all, "and the count is what the file holds, not what was reported")
}
