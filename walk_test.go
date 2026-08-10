package wfpolicy_test

// Following an alias to what it names. An alias carries no content of its own,
// so treating it as a leaf meant a `<<:` merge of an anchor defined under `with:`
// — a subtree the walk deliberately skips — was seen in neither place: not where
// it was written, and not where it was used.

import (
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
