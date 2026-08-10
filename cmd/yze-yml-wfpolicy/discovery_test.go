package main

// What this command claims, and nothing else. The walk itself — the symlinked
// root, the identity of a path reached two ways, the tree that cannot be read,
// the size bound, the ignore filter — belongs to the shared discovery and is
// proven there, once, rather than three times in three ways that disagreed.

import (
	"path/filepath"
	"testing"

	goyze "github.com/gomatic/go-yze"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsWorkflowFileMatchesPathComponents pins where GitHub actually reads a
// workflow from. The directory must END IN the two components
// `.github/workflows`, not merely end with those characters: a suffix test also
// claimed `my.github/workflows`, whose files GitHub never opens, so the gate
// reported a pin that could never run.
func TestIsWorkflowFileMatchesPathComponents(t *testing.T) {
	t.Parallel()

	for path, want := range map[string]bool{
		".github/workflows/ci.yml":         true,
		".github/workflows/ci.yaml":        true,
		"repo/.github/workflows/ci.yml":    true,
		"my.github/workflows/ci.yml":       false,
		"github/workflows/ci.yml":          false,
		".github/ci.yml":                   false,
		".github/workflows/notes.md":       false,
		".github/workflows/sub/deep.yml":   false,
		"anywhere/action.yml":              true,
		"anywhere/action.yaml":             true,
		"deep/nested/dir/action.yml":       true,
		"action.yml":                       true,
		".github/workflows/../other.yml":   false,
		".github/actions/thing/action.yml": true,
	} {
		assert.Equal(t, want, isWorkflowFile(goyze.FilePath(path)), "%s", path)
	}
}

// TestCompositeNamesAreNeverMatchedLooselyByCase pins the exactness. GitHub
// reads these paths literally on a case-sensitive filesystem, so `ACTION.YML` is
// a file it never opens — claiming one reports a pin that can never run.
func TestCompositeNamesAreNeverMatchedLooselyByCase(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"ACTION.YML", "Action.yml", "dir/ACTION.YAML", ".GITHUB/WORKFLOWS/CI.YML"} {
		assert.False(t, isWorkflowFile(goyze.FilePath(path)), "%s is not a file GitHub reads", path)
	}
}

// TestPrunedSkipsSomebodyElsesTreesAndKeepsDotGithub pins this analyzer's own
// list. A dependency ships its own workflows, and reporting them tells this
// repository to fix a pin it does not own — three such findings turned up in
// node_modules the first time this walked a real checkout. `.github` is
// deliberately absent despite being hidden: it is the ONLY directory a workflow
// can live in, and pruning it would silence the analyzer entirely.
func TestPrunedSkipsSomebodyElsesTreesAndKeepsDotGithub(t *testing.T) {
	t.Parallel()

	for _, name := range []goyze.DirName{"node_modules", "vendor", "testdata"} {
		assert.True(t, pruned(name), "%s holds somebody else's workflows", name)
	}
	for _, name := range []goyze.DirName{".github", "workflows", "src", "actions"} {
		assert.False(t, pruned(name), "%s is this repository's own", name)
	}
}

// TestDiscoveryClaimsOnlyWhatGitHubReads is the wiring check: the shared walk,
// driven by this command's predicates, over a tree holding both.
func TestDiscoveryClaimsOnlyWhatGitHubReads(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, ".github/workflows/ci.yml", pinned)
	writeWorkflow(t, dir, "action.yml", pinned)
	writeWorkflow(t, dir, ".github/dependabot.yml", pinned)
	writeWorkflow(t, dir, "node_modules/dep/.github/workflows/theirs.yml", pinned)
	writeWorkflow(t, dir, "docs/notes.yml", pinned)

	found, err := discovery().Expand([]string{dir})

	require.NoError(t, err)
	assert.ElementsMatch(t, []string{
		filepath.Join(dir, ".github/workflows/ci.yml"),
		filepath.Join(dir, "action.yml"),
	}, found.Files)
}
