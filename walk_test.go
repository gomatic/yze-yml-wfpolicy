package wfpolicy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAnInputNamedUsesIsNotAnActionReference pins the one place a `uses` key is
// NOT a schema field. `with:` and `env:` hold keys the author chose, so GitHub
// never resolves what is under them — and both shapes below are legal workflow
// syntax, so reporting them was an error-severity finding nobody could act on.
func TestAnInputNamedUsesIsNotAnActionReference(t *testing.T) {
	t.Parallel()

	assert.Empty(t, analyze(t, `
jobs:
  b:
    steps:
      - uses: actions/github-script@v7
        with:
          uses: o/a@main
      - uses: some/action@v1
        env:
          uses: docs mention o/a@main
`))
}

// TestAStepInsideAnAuthoredKeyIsStillNotRead pins the depth of that exemption:
// everything under an author-named key is the author's data, however it is
// shaped.
func TestAStepInsideAnAuthoredKeyIsStillNotRead(t *testing.T) {
	t.Parallel()

	assert.Empty(
		t,
		analyze(t, "jobs:\n  b:\n    steps:\n      - with:\n          steps:\n            - uses: o/a@main\n"),
	)
}

// TestAnAliasedKeyIsFollowedLikeAnAliasedValue pins the other half of alias
// resolution. An alias carries the ANCHOR's name as its own value, so a key
// written as an alias evaded the rule in exactly the way an aliased value once
// did — the same one-line evasion, on the other side of the colon.
func TestAnAliasedKeyIsFollowedLikeAnAliasedValue(t *testing.T) {
	t.Parallel()

	diags := analyze(t, "k: &k uses\njobs:\n  b:\n    steps:\n      - *k : o/a@main\n")

	assert.Len(t, diags, 1, "the aliased key resolves to `uses`, so its value is an action reference")
}

// TestUsesIsFoundWhereverItAppears pins that the walk looks for the KEY rather
// than a fixed path to it. A workflow spells `uses` in a step, in a reusable
// workflow job, and in a composite action's step; enumerating those paths would
// silently miss whichever shape is added next.
func TestUsesIsFoundWhereverItAppears(t *testing.T) {
	t.Parallel()

	diags := analyze(t, `
jobs:
  reusable:
    uses: owner/repo/.github/workflows/x.yml@main
  build:
    steps:
      - uses: owner/action@master
runs:
  steps:
    - uses: owner/composite@develop
`)

	assert.Len(t, diags, 3, "a step, a reusable job, and a composite step are all read")
}

// TestAKeyNamedUsesElsewhereIsStillRead documents a deliberate consequence of
// looking for the key: a mapping whose key happens to be `uses` is read
// wherever it sits. Inside a workflow file that is the right call — every such
// key GitHub defines IS an action reference — and the command only ever hands
// this analyzer files under .github/workflows.
func TestAKeyNamedUsesElsewhereIsStillRead(t *testing.T) {
	t.Parallel()

	diags := analyze(t, "anything:\n  nested:\n    uses: o/a@main\n")

	assert.Len(t, diags, 1)
}

// TestANonScalarUsesIsNotRead pins a guard against malformed input: `uses:`
// with a list or mapping value is not an action reference, and reading one
// would invent a finding from a shape GitHub itself rejects.
func TestANonScalarUsesIsNotRead(t *testing.T) {
	t.Parallel()

	assert.Empty(t, analyze(t, "jobs:\n  b:\n    steps:\n      - uses:\n          - o/a@main\n"))
}

// TestAValueIsNeverMistakenForAKey pins the mapping's key/value pairing. YAML
// stores a mapping as a flat alternating list, so a walk that stepped by one
// would read every value as a key and report the entry that FOLLOWS a value
// reading "uses".
func TestAValueIsNeverMistakenForAKey(t *testing.T) {
	t.Parallel()

	assert.Empty(t, analyze(t, "jobs:\n  b:\n    steps:\n      - name: uses\n        o/a@main: irrelevant\n"))
}

// TestASequenceIsNotReadAsAMapping pins the kind guard on the walk: a sequence
// holding the word `uses` next to a reference is a list of two strings, and
// pairing its elements would report a finding from a document that has none.
func TestASequenceIsNotReadAsAMapping(t *testing.T) {
	t.Parallel()

	assert.Empty(t, analyze(t, "tags:\n  - uses\n  - o/a@main\n"))
}

// TestAnAliasResolvesToWhatItNames pins that a YAML alias is followed. An alias
// node carries the ANCHOR's name as its value, so reading it directly compares
// the label rather than the reference — a one-line evasion of the whole rule.
func TestAnAliasResolvesToWhatItNames(t *testing.T) {
	t.Parallel()

	diags := analyze(
		t,
		"defaults:\n  action: &pinned o/a@main\njobs:\n  b:\n    steps:\n      - uses: *pinned\n      - uses: *pinned\n",
	)

	require.Len(t, diags, 2, "each use of the anchor is its own finding")
	for i, d := range diags {
		assert.Contains(t, d.Message, `"main"`, "the alias is followed to what it names")
		assert.Equal(t, 6+i, d.Line, "the finding lands where the reference was written, not on the shared anchor")
	}
}

// TestAJobMayBeNamedEnvOrWith pins the one place a mapping's keys are the
// AUTHOR's rather than GitHub's. `with` and `env` are GitHub's keys on a step
// or a job; as a JOB ID they are the author's, and treating the job as an
// author-named context silenced every step inside it — a whole-job evasion
// available by renaming a job.
func TestAJobMayBeNamedEnvOrWith(t *testing.T) {
	t.Parallel()

	diags := analyze(t, `
jobs:
  env:
    steps:
      - uses: o/a@main
  with:
    steps:
      - uses: o/a@master
  build:
    steps:
      - uses: o/a@develop
`)

	assert.Len(t, diags, 3, "a job is a job whatever it is called")
}

// TestAnInputNamedUsesIsStillSkippedInsideAJobNamedEnv pins that making the
// exemption positional did not lose it: within such a job, `with:` on a step is
// still the author's.
func TestAnInputNamedUsesIsStillSkippedInsideAJobNamedEnv(t *testing.T) {
	t.Parallel()

	diags := analyze(
		t,
		"jobs:\n  env:\n    steps:\n      - uses: actions/x@v1\n        with:\n          uses: o/a@main\n",
	)

	assert.Empty(t, diags, "the step's inputs are the author's, even in a job called env")
}
