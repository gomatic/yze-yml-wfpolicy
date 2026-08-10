package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDiscoveryClaimsOnlyRealWorkflows pins which files a walk reads: a .yml or
// .yaml directly under .github/workflows, which is the only place GitHub reads
// a workflow from. YAML elsewhere is not a workflow, and a `uses:` key in it
// means something else entirely — reading those would invent findings in
// ordinary config.
func TestDiscoveryClaimsOnlyRealWorkflows(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, ".github/workflows/ci.yml", pinned)
	writeWorkflow(t, dir, ".github/workflows/release.yaml", pinned)
	writeWorkflow(t, dir, "deploy/values.yml", pinned)
	writeWorkflow(t, dir, ".github/workflows/nested/deep.yml", pinned)
	writeWorkflow(t, dir, ".github/workflows/README.md", "uses: o/a@main\n")
	buf := swapStdout(t)

	require.Equal(t, 0, run([]string{dir}))
	out := buf.String()
	assert.Contains(t, out, "ci.yml")
	assert.Contains(t, out, "release.yaml")
	assert.NotContains(t, out, "values.yml", "ordinary config is not a workflow")
	assert.NotContains(t, out, "deep.yml", "GitHub reads no nested workflow directory")
	assert.NotContains(t, out, "README.md", "a non-YAML file in the workflows directory is not a workflow")
}

// TestDiscoveryClaimsCompositeActions pins the other half of the promise this
// analyzer's own doc makes. A composite action spells `uses:` and its steps run
// with the calling job's credentials, so a branch pin there is the same
// supply-chain hole — and scanning only `.github/workflows` meant the analyzer
// could never be handed one, leaving the fleet's own composite actions
// unchecked while the doc claimed otherwise.
func TestDiscoveryClaimsCompositeActions(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, ".github/actions/thing/action.yml", pinned)
	writeWorkflow(t, dir, "deploy/action.yaml", pinned)
	buf := swapStdout(t)

	require.Equal(t, 0, run([]string{dir}))
	out := buf.String()
	assert.Contains(t, out, "action.yml", "a composite action under .github is read")
	assert.Contains(t, out, "action.yaml", "an action is referenced by directory, so it is read at any path")
}

// TestDiscoverySkipsSomebodyElsesWorkflows pins the pruning: a dependency ships
// its own workflows, and reporting them tells this repository to fix a pin it
// does not own.
func TestDiscoverySkipsSomebodyElsesWorkflows(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, ".github/workflows/ci.yml", pinned)
	writeWorkflow(t, dir, "node_modules/dep/.github/workflows/ci.yml", pinned)
	writeWorkflow(t, dir, "vendor/dep/.github/workflows/ci.yml", pinned)
	writeWorkflow(t, dir, "testdata/fixture/.github/workflows/ci.yml", pinned)
	writeWorkflow(t, dir, ".git/modules/dep/.github/workflows/ci.yml", pinned)
	buf := swapStdout(t)

	require.Equal(t, 0, run([]string{dir}))
	out := buf.String()
	assert.Contains(t, out, filepath.Join(dir, ".github"))
	assert.NotContains(t, out, "node_modules")
	assert.NotContains(t, out, "vendor")
	assert.NotContains(t, out, "testdata")
	assert.NotContains(t, out, ".git/", "the object store is not this repository's source")
}

// TestDiscoverySkipsANestedRepository pins that a submodule or a sibling
// checkout inside the tree is somebody else's too: its workflows are gated by
// its own run, and reporting them here asks an author to fix a file this
// checkout does not own.
func TestDiscoverySkipsANestedRepository(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, ".github/workflows/ci.yml", pinned)
	writeWorkflow(t, dir, "submodule/.git/HEAD", "ref: refs/heads/main\n")
	writeWorkflow(t, dir, "submodule/.github/workflows/ci.yml", pinned)
	buf := swapStdout(t)

	require.Equal(t, 0, run([]string{dir}))
	assert.NotContains(t, buf.String(), "submodule")
}

// TestPrunedDirNeverPrunesTheWalkRoot pins that naming a pruned directory outright
// still analyzes it. Applying the prune list to the walk root answered a
// deliberate request with a silent clean pass, which is the one result a gate
// must never invent.
func TestPrunedDirNeverPrunesTheWalkRoot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "testdata")
	writeWorkflow(t, dir, ".github/workflows/ci.yml", pinned)
	buf := swapStdout(t)

	require.Equal(t, 0, run([]string{dir}))
	assert.Contains(t, buf.String(), "ci.yml")
}

// TestIsWorkflowFileMatchesPathComponents pins that the workflows directory is
// matched by its components, not by its characters: a suffix test also claimed
// `my.github/workflows`, a perfectly ordinary directory GitHub never reads.
func TestIsWorkflowFileMatchesPathComponents(t *testing.T) {
	t.Parallel()

	assert.True(t, isWorkflowFile(entryPath(filepath.Join(".github", "workflows", "ci.yml"))))
	assert.True(t, isWorkflowFile(entryPath(filepath.Join("repo", ".github", "workflows", "ci.yaml"))))
	assert.False(t, isWorkflowFile(entryPath(filepath.Join("my.github", "workflows", "ci.yml"))),
		"a directory merely ending in those characters is not the workflows directory")
	assert.False(t, isWorkflowFile(entryPath(filepath.Join("workflows", "ci.yml"))))
	assert.False(t, isWorkflowFile(entryPath(filepath.Join(".github", "workflows", "ci.json"))))
	assert.False(t, isWorkflowFile(entryPath(filepath.Join("anywhere", "ACTION.YML"))),
		"GitHub opens these paths literally, so a differently-cased name is a file it never reads")
	assert.False(t, isWorkflowFile(entryPath(filepath.Join(".github", "workflows", "RELEASE.YML"))),
		"and the workflow extension is matched the same way, so the two agree")
	assert.True(t, isWorkflowFile(entryPath(filepath.Join("anywhere", "action.yml"))))
}

// TestDiscoverySkipsNonRegularFiles pins that only a regular file is read. A
// FIFO named like a workflow blocks forever on open, hanging the whole gate on
// a file that is not source in any case.
func TestDiscoverySkipsNonRegularFiles(t *testing.T) {
	dir := t.TempDir()
	workflows := filepath.Join(dir, ".github", "workflows")
	require.NoError(t, os.MkdirAll(workflows, 0o750))
	require.NoError(t, syscall.Mkfifo(filepath.Join(workflows, "pipe.yml"), 0o600))
	writeWorkflow(t, dir, ".github/workflows/ci.yml", pinned)
	buf := swapStdout(t)

	require.Equal(t, 0, run([]string{dir}))
	out := buf.String()
	assert.Contains(t, out, "ci.yml")
	assert.NotContains(t, out, "pipe.yml")
}

// TestCompositeNamesAreNeverMatchedLooselyByCase pins that these paths are read
// literally. GitHub opens them on a case-sensitive filesystem, so a
// differently-cased name is a file it never reads, and claiming one would
// report a pin that can never run.
func TestCompositeNamesAreNeverMatchedLooselyByCase(t *testing.T) {
	t.Parallel()

	assert.True(t, isWorkflowFile("deploy/action.yml"))
	assert.False(t, isWorkflowFile("deploy/Action.yml"))
	assert.False(t, isWorkflowFile("deploy/ACTION.YAML"))
}
