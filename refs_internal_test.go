package wfpolicy

// The one split, asked directly. Both halves of the analyzer read a `uses:`
// value through it, and each used to carry its own copy of the same decisions.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRepositoryAndRefIsTheOnlyReaderOfAUsesValue names repositoryAndRef and
// pins each of the three decisions it makes, so neither half can drift from the
// other by having its own answer.
func TestRepositoryAndRefIsTheOnlyReaderOfAUsesValue(t *testing.T) {
	t.Parallel()

	repo, ref, names := repositoryAndRef(" acme/act@v1.2.3 ")
	assert.True(t, names, "a spaced value is trimmed before anything else is asked of it")
	assert.Equal(t, repository("acme/act"), repo)
	assert.Equal(t, gitRef("v1.2.3"), ref)

	for name, uses := range map[string]usesRef{
		"container":        "docker://alpine@3.20",
		"spaced container": " docker://alpine@3.20",
		"local":            "./.github/actions/x@main",
		"spaced local":     " ./.github/actions/x@main",
		"no ref":           "acme/act",
	} {
		_, _, found := repositoryAndRef(uses)
		assert.False(t, found, "%s names no git reference", name)
	}

	_, first, _ := repositoryAndRef("acme/act@v1@main")
	assert.Equal(t, gitRef("v1@main"), first, "the cut is at the FIRST @, which is where GitHub cuts")
}
