package main

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	errs "github.com/gomatic/go-error"
	goyze "github.com/gomatic/go-yze"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	wfpolicy "github.com/gomatic/yze-yml-wfpolicy"
)

// realLookupEnv is the command's OWN environment reader, captured at package
// initialisation — before [TestMain] replaces it. A test that wants the real
// wiring has to restore THIS, not assign os.Getenv itself: assigning it would
// re-create the wiring under test, so unwiring line by line in main.go would
// leave every test green.
var realLookupEnv = lookupEnv

// TestMain neutralises the one ambient input this command has. The owner list
// is deliberately read from the environment at this boundary, so every test
// here would otherwise pass or fail according to what the developer exported —
// which is precisely the defect that moved the read out of the library.
func TestMain(m *testing.M) {
	lookupEnv = func(string) string { return "" }
	os.Exit(m.Run())
}

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
	assert.Contains(t, buf.String(), "yze/wfpolicy")
	assert.Contains(t, buf.String(), "a ref that moves")
}

// TestRunAcceptsExplicitFile pins what naming a file outright does, and what it
// does not. A file this analyzer judges is analyzed whatever the ignore rules
// say about it; a file GitHub would never READ is not, because a moving ref in a
// `.yml` outside `.github/workflows` is a finding about something that cannot
// run — nobody can act on it, and a runner passing a changed-file list would
// produce one for every stray YAML file in the repository.
func TestRunAcceptsExplicitFile(t *testing.T) {
	dir := t.TempDir()
	workflow := writeWorkflow(t, dir, ".github/workflows/ci.yml", pinned)
	action := writeWorkflow(t, dir, "elsewhere/action.yml", pinned)
	stray := writeWorkflow(t, dir, "elsewhere/ci.yml", pinned)
	notes := writeWorkflow(t, dir, "notes.md", pinned)

	buf := swapStdout(t)
	require.Equal(t, 0, run([]string{workflow}))
	assert.Contains(t, buf.String(), "yze/wfpolicy", "a workflow where GitHub reads them")

	buf = swapStdout(t)
	require.Equal(t, 0, run([]string{action}))
	assert.Contains(t, buf.String(), "yze/wfpolicy", "an action definition, which GitHub reads at any path")

	for name, at := range map[string]string{"stray yaml": stray, "prose": notes} {
		buf = swapStdout(t)
		require.Equal(t, 0, run([]string{at}), name)
		assert.NotContains(t, buf.String(), "yze/wfpolicy", "%s: GitHub never reads it", name)
	}
}

// TestRunFailsOnMissingPath pins that a path that does not exist is an error,
// not an empty success.
func TestRunFailsOnMissingPath(t *testing.T) {
	assert.Equal(t, 1, run([]string{filepath.Join(t.TempDir(), "absent.yml")}))
}

// TestRunFailsWhenWalkErrors pins that a walk failure aborts rather than
// reporting whatever it collected first.
func TestRunFailsWhenWalkErrors(t *testing.T) {
	original := files.WalkDir
	files.WalkDir = func(string, fs.WalkDirFunc) error { return errWalkFailed }
	t.Cleanup(func() { files.WalkDir = original })

	assert.Equal(t, 1, run([]string{t.TempDir()}))
}

// TestRunReportsAnUnparseableFileWithoutFailingTheRun pins the containment at
// the command's edge: the file becomes a finding of its own, the run keeps
// going, and the report still reaches the runner that has to act on it.
func TestRunReportsAnUnparseableFileWithoutFailingTheRun(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, ".github/workflows/broken.yml", "jobs:\n  - [unclosed\n")
	writeWorkflow(t, dir, ".github/workflows/ci.yml", pinned)
	buf := swapStdout(t)

	require.Equal(t, 0, run([]string{dir}))
	out := buf.String()
	assert.Contains(t, out, "cannot be analyzed as a workflow")
	assert.Contains(t, out, "a ref that moves", "the readable file keeps its findings")
}

// errWalkFailed and errWriteFailed stand in for a walk that cannot run and a
// closed pipe.
const (
	errWalkFailed  errs.Const = "walk failed"
	errWriteFailed errs.Const = "write failed"
)

// failingWriter refuses every write, standing in for a closed pipe.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWriteFailed }

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

// TestANamedNonRegularFileIsRefusedRatherThanRead pins that a FIFO or device
// named outright is an error carrying its own sentinel. It skips the walk's
// guard, and READING one hangs the gate forever instead of failing it.
func TestANamedNonRegularFileIsRefusedRatherThanRead(t *testing.T) {
	dir := t.TempDir()
	pipe := filepath.Join(dir, "ci.yml")
	require.NoError(t, syscall.Mkfifo(pipe, 0o600))

	_, err := discovery().Expand([]string{pipe})

	require.Error(t, err)
	assert.ErrorIs(t, err, goyze.ErrNotRegularFile)
	assert.Equal(t, 1, run([]string{pipe}), "and the command reports the failure")
}

// TestARunWithNoPathsIsAFailure pins that being given nothing is an error. A
// runner whose root placeholder expands to nothing would otherwise green the
// gate over a repository no analyzer ever looked at.
func TestARunWithNoPathsIsAFailure(t *testing.T) {
	assert.Equal(t, 1, run(nil))
	// The error the CODE produces, not one the assertion builds. Asserting that
	// `ErrNoPaths.With(nil)` matches `ErrNoPaths` exercises the error helper and
	// holds whatever run returns — swapping this failure's sentinel for any
	// other left the whole suite green, in all three of these analyzers.
	assert.ErrorIs(t, report(nil), wfpolicy.ErrNoPaths)
	assert.ErrorIs(t, report([]string{}), wfpolicy.ErrNoPaths)
}

// TestOverlappingArgumentsReportEachWorkflowOnce pins deduplication: a runner
// that passes a directory and a file inside it is not making a mistake, and
// reporting one workflow twice doubles a count the ratchet is measured against.
func TestOverlappingArgumentsReportEachWorkflowOnce(t *testing.T) {
	dir := t.TempDir()
	file := writeWorkflow(t, dir, ".github/workflows/ci.yml", pinned)
	buf := swapStdout(t)

	require.Equal(t, 0, run([]string{dir, file, file}))
	assert.Equal(t, 1, bytes.Count(buf.Bytes(), []byte("a ref that moves")))
}

// TestANamedWorkflowIsNotFilteredWhateverTheArgumentOrder pins the rule against
// the ordering that broke it. One shared identity set let whichever argument
// came first claim the file, so a directory listed before the named workflow
// sent it through the ignore filter after all — the same two arguments, the
// opposite order, the opposite verdict.
func TestANamedWorkflowIsNotFilteredWhateverTheArgumentOrder(t *testing.T) {
	dir := t.TempDir()
	ignored := writeWorkflow(t, dir, ".github/workflows/ci.yml", pinned)

	original := files.CheckIgnore
	files.CheckIgnore = func(goyze.RepoDir, []string) (map[string]bool, error) {
		return map[string]bool{ignored: true}, nil
	}
	t.Cleanup(func() { files.CheckIgnore = original })

	for name, args := range map[string][]string{
		"directory first": {dir, ignored},
		"named first":     {ignored, dir},
	} {
		buf := swapStdout(t)
		require.Equal(t, 0, run(args), name)
		assert.Contains(t, buf.String(), "ci.yml", "%s: the author asked for it by name", name)
	}
}

// TestCanonicalFallsBackWhenAPathCannotBeMadeAbsolute pins the first arm of
// identity: a path the working directory makes unresolvable keeps its own
// spelling, so the file is still analyzed rather than dropped for being
// unidentifiable.
func TestCanonicalFallsBackWhenAPathCannotBeMadeAbsolute(t *testing.T) {
	dir := t.TempDir()
	file := writeWorkflow(t, dir, ".github/workflows/ci.yml", pinned)

	original := files.Abs
	files.Abs = func(string) (string, error) { return "", os.ErrInvalid }
	t.Cleanup(func() { files.Abs = original })
	buf := swapStdout(t)

	require.Equal(t, 0, run([]string{file}))
	assert.NotEmpty(t, buf.String(), "the file is still analyzed rather than dropped for being unidentifiable")
}
