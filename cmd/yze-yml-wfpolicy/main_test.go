package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// swapStdout captures what the command writes, restoring the real writer after
// so tests cannot leak into one another.
func swapStdout(t *testing.T) *bytes.Buffer {
	t.Helper()
	original := stdout
	buf := &bytes.Buffer{}
	stdout = buf
	t.Cleanup(func() { stdout = original })
	return buf
}

// writeWorkflow puts a file at a path relative to dir, creating the parents.
func writeWorkflow(t *testing.T, dir, rel, content string) string {
	t.Helper()
	path := filepath.Join(dir, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// pinned is a workflow whose action moves with a branch.
const pinned = "jobs:\n  b:\n    steps:\n      - uses: o/a@main\n"

// TestRunEmitsReportForDirectory pins the ordinary invocation: a tree is walked
// and its findings reach stdout as the report the runner consumes.
func TestRunEmitsReportForDirectory(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, ".github/workflows/ci.yml", pinned)
	buf := swapStdout(t)

	require.Equal(t, 0, run([]string{dir}))
	assert.Contains(t, buf.String(), "yze/wfpin")
	assert.Contains(t, buf.String(), "a ref that moves")
}

// TestRunAcceptsExplicitFile pins that a named file is analyzed verbatim,
// without the discovery rules a directory walk applies — so a workflow kept
// somewhere unusual can still be checked deliberately.
func TestRunAcceptsExplicitFile(t *testing.T) {
	dir := t.TempDir()
	file := writeWorkflow(t, dir, "elsewhere/ci.yml", pinned)
	buf := swapStdout(t)

	require.Equal(t, 0, run([]string{file}))
	assert.Contains(t, buf.String(), "yze/wfpin")
}

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
	assert.True(t, isWorkflowFile(entryPath(filepath.Join("anywhere", "ACTION.YML"))),
		"the action file name is matched case-insensitively")
}

// TestRunFailsOnMissingPath pins that a path that does not exist is an error,
// not an empty success.
func TestRunFailsOnMissingPath(t *testing.T) {
	assert.Equal(t, 1, run([]string{filepath.Join(t.TempDir(), "absent.yml")}))
}

// TestRunFailsWhenWalkErrors pins that a walk failure aborts rather than
// reporting whatever it collected first.
func TestRunFailsWhenWalkErrors(t *testing.T) {
	original := walkDir
	walkDir = func(_ string, _ fs.WalkDirFunc) error { return errors.New("walk failed") }
	t.Cleanup(func() { walkDir = original })

	assert.Equal(t, 1, run([]string{t.TempDir()}))
}

// TestRunFailsWhenTheWalkCallbackErrors pins the other half of walk failure: an
// entry the walk could not stat aborts the run rather than being skipped, so
// the gate never passes over a tree it read incompletely.
func TestRunFailsWhenTheWalkCallbackErrors(t *testing.T) {
	original := walkDir
	walkDir = func(root string, fn fs.WalkDirFunc) error {
		return fn(root, nil, errors.New("entry failed"))
	}
	t.Cleanup(func() { walkDir = original })

	assert.Equal(t, 1, run([]string{t.TempDir()}))
}

// TestRunFailsWhenReadErrors pins that a file the analyzer cannot read aborts
// the run — the gate never passes over a file it did not see.
func TestRunFailsWhenReadErrors(t *testing.T) {
	dir := t.TempDir()
	file := writeWorkflow(t, dir, ".github/workflows/ci.yml", pinned)
	original := readFile
	readFile = func(string) ([]byte, error) { return nil, errors.New("read failed") }
	t.Cleanup(func() { readFile = original })

	assert.Equal(t, 1, run([]string{file}))
}

// TestRunFailsWhenSourceIsNotYAML pins that malformed input is a tool failure
// the exit code reports.
func TestRunFailsWhenSourceIsNotYAML(t *testing.T) {
	dir := t.TempDir()
	file := writeWorkflow(t, dir, ".github/workflows/ci.yml", "jobs:\n  - [unclosed\n")

	assert.Equal(t, 1, run([]string{file}))
}

// failingWriter refuses every write, standing in for a closed pipe.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

// TestRunFailsWhenEncodeErrors pins that a report which cannot be written is a
// failure: exiting zero would tell the runner a check passed when its result
// never arrived.
func TestRunFailsWhenEncodeErrors(t *testing.T) {
	dir := t.TempDir()
	file := writeWorkflow(t, dir, ".github/workflows/ci.yml", pinned)
	original := stdout
	stdout = failingWriter{}
	t.Cleanup(func() { stdout = original })

	assert.Equal(t, 1, run([]string{file}))
}

// TestMainExits pins the entry point's wiring: main runs the command and exits
// with its status rather than swallowing it.
func TestMainExits(t *testing.T) {
	original, originalArgs := osExit, os.Args
	code := -1
	osExit = func(status int) { code = status }
	os.Args = []string{"yze-yml-wfpolicy", filepath.Join(t.TempDir(), "absent.yml")}
	t.Cleanup(func() { osExit, os.Args = original, originalArgs })

	main()

	assert.Equal(t, 1, code)
}

// TestDiscoverySkipsSomebodyElsesTrees pins the pruning: a dependency ships its
// own workflows, and reporting them tells this repository to fix a pin it does
// not own. `.github` is not pruned despite being hidden, because it is the only
// directory a workflow can live in — pruning by hiddenness would silence the
// rule entirely.
func TestDiscoverySkipsSomebodyElsesTrees(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, ".github/workflows/ci.yml", pinned)
	writeWorkflow(t, dir, "node_modules/dep/.github/workflows/ci.yml", pinned)
	writeWorkflow(t, dir, "vendor/dep/.github/workflows/ci.yml", pinned)
	writeWorkflow(t, dir, "testdata/fixture/.github/workflows/ci.yml", pinned)
	writeWorkflow(t, dir, ".git/modules/dep/.github/workflows/ci.yml", pinned)
	buf := swapStdout(t)

	require.Equal(t, 0, run([]string{dir}))
	out := buf.String()
	assert.Contains(t, out, filepath.Join(".github", "workflows", "ci.yml"))
	assert.NotContains(t, out, "node_modules")
	assert.NotContains(t, out, "vendor")
	assert.NotContains(t, out, "testdata")
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
