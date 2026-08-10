package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helperEnabled marks the child process the subprocess seam is pointed at.
const helperEnabled = "WFPOLICY_IGNORE_HELPER"

// TestIgnoreHelperProcess is not a test. It is the child this package's
// subprocess seam runs instead of git, so every test below needs no git binary,
// no checkout, and nothing at all from the machine beyond the Go tooling that
// built this binary.
func TestIgnoreHelperProcess(_ *testing.T) {
	if os.Getenv(helperEnabled) != "1" {
		return
	}
	// The child's output is NUL-separated, but a NUL cannot travel in an
	// environment variable — it terminates the string. The separator on the way
	// in is \x01, which no path can contain: a newline would be ambiguous for
	// the one case that matters, a path holding a newline.
	if out := os.Getenv("WFPOLICY_IGNORE_OUT"); out != "" {
		_, _ = fmt.Fprint(os.Stdout, strings.ReplaceAll(out, "\x01", "\x00"))
	}
	code, _ := strconv.Atoi(os.Getenv("WFPOLICY_IGNORE_CODE"))
	os.Exit(code)
}

// gitCall records how the seam was invoked, so the argv is verified rather than
// assumed: every earlier stub discarded it, leaving the flags, the working
// directory and the framing unpinned — including a regression the code's own
// comment says had already shipped once.
type gitCall struct {
	command *exec.Cmd
	name    string
	args    []string
}

// lastGitCall is what the most recent stubbed invocation was given.
var lastGitCall gitCall

// stubGit points the subprocess seam at this test binary, which answers with
// the given output and exit status.
func stubGit(t *testing.T, stdout string, code int) {
	t.Helper()
	original := execCommand
	execCommand = func(name string, args ...string) *exec.Cmd {
		lastGitCall = gitCall{name: name, args: args}
		command := exec.Command(os.Args[0], "-test.run=TestIgnoreHelperProcess")
		lastGitCall.command = command
		command.Env = append(os.Environ(),
			helperEnabled+"=1",
			"WFPOLICY_IGNORE_OUT="+stdout,
			"WFPOLICY_IGNORE_CODE="+strconv.Itoa(code),
		)
		return command
	}
	t.Cleanup(func() { execCommand = original })
}

// TestGitCheckIgnoreReportsTheIgnoredSubset pins the ordinary answer, and that
// the paths come back in the spelling the CALLER used: git is asked in absolute
// terms because it resolves a relative path against its own directory, but the
// report has to name the file the way the author does.
func TestGitCheckIgnoreReportsTheIgnoredSubset(t *testing.T) {
	kept, dropped := ".github/workflows/ci.yml", "vendor/dep/action.yml"
	absolute, err := filepath.Abs(dropped)
	require.NoError(t, err)
	stubGit(t, absolute+"\x01", 0)

	ignored, err := gitCheckIgnore(".", []string{kept, dropped})

	require.NoError(t, err)
	assert.Equal(t, map[string]bool{dropped: true}, ignored, "answered in the caller's spelling")
}

// TestGitCheckIgnoreTreatsNothingIgnoredAsSuccess pins git's exit status 1,
// which means "no path matched" rather than a failure. Reading it as an error
// would fail the filter open on every clean repository, quietly making it inert.
func TestGitCheckIgnoreTreatsNothingIgnoredAsSuccess(t *testing.T) {
	stubGit(t, "", 1)

	ignored, err := gitCheckIgnore(".", []string{".github/workflows/ci.yml"})

	require.NoError(t, err)
	assert.Empty(t, ignored)
}

// TestGitCheckIgnoreSurfacesARealFailure pins the other exit statuses — 128 is
// "not a git repository" — so the caller can fail open deliberately rather than
// mistaking a broken tool for an empty answer. It carries the exit status,
// because "status 1 is clean and everything else is itself" is the whole
// contract and an assertion that merely sees AN error cannot tell them apart.
func TestGitCheckIgnoreSurfacesARealFailure(t *testing.T) {
	stubGit(t, "", 128)

	_, err := gitCheckIgnore(".", []string{".github/workflows/ci.yml"})

	require.Error(t, err)
	var exit *exec.ExitError
	require.ErrorAs(t, err, &exit)
	assert.Equal(t, 128, exit.ExitCode())
}

// TestAPartialAnswerIsNotAnAnswer pins the failure that reached real trees:
// asked about two repositories at once, git prints what it could resolve and
// THEN aborts, and accepting that output dropped half the list while silently
// keeping the other half's ignored files.
func TestAPartialAnswerIsNotAnAnswer(t *testing.T) {
	stubGit(t, "/a/ignored.md\x01", 128)

	_, err := gitCheckIgnore(".", []string{"/a/ignored.yml", "/b/ignored.yml"})

	require.Error(t, err, "output alongside a failure is a partial answer, and the caller must fail open")
}

// TestAPathHoldingANewlineIsStillAsked pins the NUL protocol. Newline-delimited,
// such a path split into two questions and came back C-quoted, so the one file
// git HAD answered about was the one the filter failed to drop.
func TestAPathHoldingANewlineIsStillAsked(t *testing.T) {
	odd := ".github/workflows/ci/two\nlines.yml"
	absolute, err := filepath.Abs(odd)
	require.NoError(t, err)
	stubGit(t, absolute+"\x01", 0)

	ignored, err := gitCheckIgnore(".", []string{odd})

	require.NoError(t, err)
	assert.Equal(t, map[string]bool{odd: true}, ignored)
}

// TestGitCheckIgnoreOfNoFilesAsksNothing pins that an empty list never spawns a
// process at all.
func TestGitCheckIgnoreOfNoFilesAsksNothing(t *testing.T) {
	original := execCommand
	execCommand = func(string, ...string) *exec.Cmd { panic("git must not be run for an empty list") }
	t.Cleanup(func() { execCommand = original })

	ignored, err := gitCheckIgnore(".", nil)

	require.NoError(t, err)
	assert.Empty(t, ignored)
}

// TestAbsolutePathFailureStillAsksAboutThePath pins the arm that survives an
// unreadable working directory: the path is sent as given rather than dropped,
// so a document is never silently excluded from the ignore question and then
// silently reported.
func TestAbsolutePathFailureStillAsksAboutThePath(t *testing.T) {
	original := absolutePath
	absolutePath = func(string) (string, error) { return "", os.ErrInvalid }
	t.Cleanup(func() { absolutePath = original })
	stubGit(t, "vendor/dep/action.yml\x01", 0)

	ignored, err := gitCheckIgnore(".", []string{"vendor/dep/action.yml"})

	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"vendor/dep/action.yml": true}, ignored)
}

// TestGitIsAskedTheRightQuestionFromTheRightPlace pins the invocation itself.
// The seam's stubs inspected nothing, so deleting the working directory — the
// regression this file's own comment says "is how this first shipped" — passed
// the whole suite, as did dropping -z or the excludes neutralisation.
func TestGitIsAskedTheRightQuestionFromTheRightPlace(t *testing.T) {
	stubGit(t, "", 1)
	// A real directory: the seam runs the child THERE, which is the property
	// under test, so a path that does not exist would fail for the wrong reason.
	root := t.TempDir()

	_, err := gitCheckIgnore(repoDir(root), []string{"a.yml"})

	require.NoError(t, err)
	assert.Equal(t, "git", lastGitCall.name)
	assert.Contains(t, lastGitCall.args, "check-ignore")
	assert.Contains(t, lastGitCall.args, "--stdin")
	assert.Contains(t, lastGitCall.args, "-z", "the protocol is NUL-framed, so a path may contain a newline")
	assert.Contains(t, lastGitCall.args, "core.excludesFile=/dev/null",
		"a machine's own excludes are not the repository's answer")
	assert.Contains(t, lastGitCall.args, "core.quotePath=false")
	assert.Equal(t, root, lastGitCall.command.Dir, "asked from INSIDE the repository, not wherever the process started")
}

// TestEachRepositoryIsAskedSeparately pins the grouping. git answers only for
// the repository it is asked from: given a path outside it, it prints what it
// resolved and then aborts, so one root for the whole list dropped half the
// answer and silently kept the other half's ignored files.
func TestEachRepositoryIsAskedSeparately(t *testing.T) {
	t.Parallel()

	var asked []repoDir
	ignores := func(root repoDir, paths []string) (map[string]bool, error) {
		asked = append(asked, root)
		found := map[string]bool{}
		for _, p := range paths {
			if strings.Contains(p, "ignored") {
				found[p] = true
			}
		}
		return found, nil
	}

	kept := tracked(ignores, []string{"/a/keep.yml", "/a/ignored.yml", "/b/keep.yml", "/b/ignored.yml"})

	assert.Equal(t, []string{"/a/keep.yml", "/b/keep.yml"}, kept)
	assert.Len(t, asked, 2, "one question per repository, not one for the whole list")
}

// TestMarkIgnoredMustNotDisableTheFilterForOtherRepositories pins that failing open is
// scoped: a tree git cannot answer for must not turn the filter off everywhere.
func TestMarkIgnoredMustNotDisableTheFilterForOtherRepositories(t *testing.T) {
	t.Parallel()

	ignores := func(root repoDir, _ []string) (map[string]bool, error) {
		if strings.HasPrefix(string(root), "/a") {
			return nil, errors.New("not a git repository")
		}
		return map[string]bool{"/b/ignored.yml": true}, nil
	}

	kept := tracked(ignores, []string{"/a/ignored.yml", "/b/ignored.yml", "/b/keep.yml"})

	assert.Equal(t, []string{"/a/ignored.yml", "/b/keep.yml"}, kept,
		"the unanswerable tree keeps everything; the answerable one is still filtered")
}
