package wfpolicy_test

// Following an alias to what it names. An alias carries no content of its own,
// so treating it as a leaf meant a `<<:` merge of an anchor defined under `with:`
// — a subtree the walk deliberately skips — was seen in neither place: not where
// it was written, and not where it was used.

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAnAnchorHiddenUnderAnAuthoredKeyIsStillFollowed pins the evasion the
// alias rule closes. The anchor is DEFINED inside `with:`, which the walk skips
// because its keys are the author's, and USED through a merge key elsewhere —
// so the reference existed in neither place the walker looked.
func TestAnAnchorHiddenUnderAnAuthoredKeyIsStillFollowed(t *testing.T) {
	t.Parallel()

	source := "jobs:\n  a:\n    steps:\n      - uses: actions/github-script@v7\n        with:\n" +
		"          script: &hide\n            uses: actions/checkout@main\n" +
		"  b:\n    steps:\n      - <<: *hide\n"

	diags := analyzeFor(t, nil, source)

	require.Len(t, diags, 1, "the hidden reference is found through the alias that uses it")
	assert.Contains(t, diags[0].Message, "actions/checkout@main")
}

// TestARecursiveAnchorTerminates pins the guard that makes following aliases
// safe. A document may legally name the same anchor from many places; only a
// CYCLE is refused, and refusing it silently is correct — the anchor's contents
// were already walked by the reference that opened the cycle.
func TestARecursiveAnchorTerminates(t *testing.T) {
	t.Parallel()

	for name, source := range map[string]string{
		"self reference": "jobs: &loop\n  a:\n    steps:\n      - uses: o/a@main\n  b: *loop\n",
		"mutual":         "x: &one\n  uses: o/a@main\n  next: &two\n    back: *one\n    self: *two\n",
	} {
		done := make(chan int, 1)
		go func() { done <- len(analyzeFor(t, nil, source)) }()
		select {
		case found := <-done:
			assert.GreaterOrEqual(t, found, 1, "%s: the reference inside the cycle is still reported", name)
		case <-timeAfter():
			t.Fatalf("%s: following the alias did not terminate", name)
		}
	}
}

// timeAfter bounds a walk that might not terminate, so a cycle shows up as a
// failing test rather than a suite that hangs until the harness kills it.
func timeAfter() <-chan time.Time { return time.After(10 * time.Second) }

// TestAliasAmplificationTerminates pins the bound that makes following aliases
// safe against a hostile author — which is the whole reason the walk follows
// them. Guarding only cycles on the current path let ONE anchor be re-expanded
// once per reference: ten anchors each naming the previous one ten times is 574
// bytes of legal YAML and ten billion nodes. The gate did not fail on it, it
// HUNG, and the size limit cannot help because the blowup is in the nesting
// depth rather than in the bytes.
func TestAliasAmplificationTerminates(t *testing.T) {
	t.Parallel()
	source := "a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n"
	for level := 1; level <= 9; level++ {
		source += fmt.Sprintf("a%d: &a%d [", level, level)
		for copies := 0; copies < 10; copies++ {
			source += fmt.Sprintf("*a%d,", level-1)
		}
		source = source[:len(source)-1] + "]\n"
	}
	require.Less(t, len(source), 1024, "the bomb is under a kilobyte, as the real one was")

	done := make(chan int, 1)
	go func() { done <- len(analyzeFor(t, nil, source)) }()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("following the aliases did not terminate")
	}
}

// TestOneAnchorIsOneFinding pins the other half of walking each anchor once. A
// reference WRITTEN once is one defect; expanding it per use reported it three
// times for two uses, every copy at the anchor's line rather than at any use
// site, so a ratchet moved by three for a one-line fix.
func TestOneAnchorIsOneFinding(t *testing.T) {
	t.Parallel()
	source := "s: &s\n  uses: actions/checkout@main\njobs:\n  b:\n    steps:\n      - *s\n      - *s\n"

	diags := analyzeFor(t, nil, source)

	require.Len(t, diags, 1, "one written reference is one finding")
	assert.Equal(t, 2, diags[0].Line, "reported where the author wrote it")
}

// TestAMergeIntoJobsDoesNotDescendALevel pins the key that splices rather than
// nests. `jobs: {<<: *common}` merges the anchor's keys INTO the jobs mapping,
// so they are job IDs — read as an ordinary key, the merged mapping became a job
// BODY, and the whole-job evasion the positional rule closed was available again
// through a merge.
func TestAMergeIntoJobsDoesNotDescendALevel(t *testing.T) {
	t.Parallel()
	merged := "x: &common\n  env:\n    runs-on: ubuntu-latest\n    steps:\n" +
		"      - uses: actions/checkout@main\njobs:\n  <<: *common\n"

	assert.Len(t, analyzeFor(t, nil, merged), 1, "a job named env, reached through a merge, is still a job")

	direct := "jobs:\n  env:\n    steps:\n      - uses: actions/checkout@main\n"
	assert.Len(t, analyzeFor(t, nil, direct), 1, "as it is when written directly")

	input := "jobs:\n  a:\n    steps:\n      - uses: o/a@v1\n        with:\n          uses: not-an-action@main\n"
	assert.Empty(t, analyzeFor(t, nil, input), "and a real step input is still exempt")
}

// TestAuthoredKeysCoverEveryContextTheAuthorNames pins the four mappings whose
// keys GitHub does not define. A `uses` among secret names or matrix dimensions
// is an input named uses that GitHub never resolves, and reporting one is a
// finding nobody can act on — the same reasoning `with` and `env` were exempted
// for.
func TestAuthoredKeysCoverEveryContextTheAuthorNames(t *testing.T) {
	t.Parallel()

	for name, source := range map[string]string{
		"secrets": "jobs:\n  call:\n    uses: ./.github/workflows/r.yml\n    secrets:\n      uses: nope/nope@main\n",
		"matrix": "jobs:\n  m:\n    strategy:\n      matrix:\n        uses: [nope/nope@main]\n" +
			"    steps:\n      - run: echo\n",
		"with": "jobs:\n  a:\n    steps:\n      - uses: o/a@v1\n        with:\n          uses: nope@main\n",
		"env":  "jobs:\n  a:\n    env:\n      uses: nope@main\n    steps:\n      - run: echo\n",
	} {
		assert.Empty(t, analyzeFor(t, nil, source), "%s holds keys the author chose", name)
	}
}

// TestTheVisitedSetBoundsTheWalkWithoutLosingAPosition names `visited` and both
// halves of what it must do at once. It is never cleared, or one anchor is
// re-expanded per reference and the walk is exponential in nesting depth; and it
// is keyed on the POSITION as well as the node, or whichever position reached an
// anchor first decides for every other — which lost every step of a job merged
// into `jobs` from an anchor defined above it.
func TestTheVisitedSetBoundsTheWalkWithoutLosingAPosition(t *testing.T) {
	t.Parallel()

	// One anchor, reached from two positions that judge it differently: at the
	// top level `env` is an author's context and its contents are skipped; under
	// `jobs` the same key is a job id and its steps are read.
	both := "x: &common\n  env:\n    steps:\n      - uses: actions/checkout@main\njobs:\n  <<: *common\n"

	diags := analyzeFor(t, nil, both)

	require.Len(t, diags, 1, "the position that reads it still reads it")
	assert.Contains(t, diags[0].Message, "actions/checkout@main")
}

// TestOneWrittenReferenceIsOneFindingHoweverManyPositionsReachIt pins the split
// between the two things a walk remembers. A node must be walked once per
// POSITION, because the same anchor spliced under `jobs` and sitting at the top
// level is judged by different rules — but a `uses:` VALUE is one written
// reference however many positions reach it, and reporting it per position
// emitted two byte-identical diagnostics at one line and column.
func TestOneWrittenReferenceIsOneFindingHoweverManyPositionsReachIt(t *testing.T) {
	t.Parallel()

	for name, source := range map[string]string{
		"aliased into jobs": "x: &a\n  uses: actions/checkout@main\njobs: *a\n",
		"merged into jobs":  "x: &a\n  uses: actions/checkout@main\njobs:\n  <<: *a\n",
		"used twice":        "s: &s\n  uses: actions/checkout@main\njobs:\n  b:\n    steps:\n      - *s\n      - *s\n",
		"three positions":   "x: &a\n  uses: actions/checkout@main\njobs: *a\nother: *a\n",
	} {
		diags := analyzeFor(t, nil, source)

		require.Len(t, diags, 1, "%s: one written reference is one defect", name)
		assert.Equal(t, 2, diags[0].Line, "%s: reported where the author wrote it", name)
	}
}

// TestAMatrixHoldsTheAuthorsOwnKeys pins the skip added for `strategy.matrix`,
// which nothing covered. Its keys are dimension names the author chose, so a
// `uses` among them is a matrix dimension called uses — GitHub resolves no
// action from it, and reporting one is a finding nobody can act on.
func TestAMatrixHoldsTheAuthorsOwnKeys(t *testing.T) {
	t.Parallel()

	// A SCALAR value, because a sequence yields no reference either way and so
	// could not tell the skip from its absence — the test that used one passed
	// with the skip removed.
	exempt := "jobs:\n  a:\n    strategy:\n      matrix:\n        uses: x/y@main\n" +
		"    steps:\n      - run: echo\n"
	assert.Empty(t, analyzeFor(t, nil, exempt), "a matrix dimension named uses is not an action")

	genuine := "jobs:\n  a:\n    strategy:\n      matrix:\n        go: ['1.26']\n" +
		"    steps:\n      - uses: actions/checkout@main\n"
	assert.Len(t, analyzeFor(t, nil, genuine), 1, "and a real step beside it is still read")
}

// TestAMappingsKeysAndValuesNeverSwapPlaces pins the step of two. YAML stores a
// mapping as one flat alternating list, so walking it one entry at a time pairs
// each VALUE with the following KEY: a document whose value happens to read
// "uses" would then take the next key as its action reference and report a
// finding about a string that is not one.
func TestAMappingsKeysAndValuesNeverSwapPlaces(t *testing.T) {
	t.Parallel()

	assert.Empty(t, analyze(t, "a: uses\no/a@main: x\n"),
		"the value `uses` is a value; the key beside it is not its reference")

	diags := analyze(t, "uses: o/a@main\nb: c\n")
	assert.Len(t, diags, 1, "and a real key/value pair is still read")
}

// TestAnAuthorNamedOutputIsNotAnActionReference pins the key that was missing
// from the exempt set and is reachable in ordinary syntax. `jobs.<id>.outputs`
// holds names the AUTHOR chose and takes scalar values, so an output called
// `uses` is a legal workflow — and it earned a finding whose only remedy was to
// rename a variable for the linter.
func TestAnAuthorNamedOutputIsNotAnActionReference(t *testing.T) {
	t.Parallel()

	assert.Empty(t, analyze(t, "jobs:\n  resolve:\n    outputs:\n      uses: actions/checkout@main\n"),
		"an output named uses is an output, not an action GitHub resolves")

	assert.Len(t, analyze(t, "jobs:\n  resolve:\n    steps:\n      - uses: actions/checkout@main\n"), 1,
		"and a step in the same job is still read")
}

// TestEveryAuthorNamedContextIsExempt pins the whole set at once, in both
// directions. Each of these keys holds names the author chose, so a `uses`
// among them is a field called uses; a step beside it is still an action.
func TestEveryAuthorNamedContextIsExempt(t *testing.T) {
	t.Parallel()

	for _, key := range []string{"with", "env", "secrets", "matrix", "outputs", "inputs", "services"} {
		assert.Empty(t, analyze(t, "jobs:\n  b:\n    "+key+":\n      uses: o/a@main\n"),
			"%s holds the author's own names", key)
	}
}
