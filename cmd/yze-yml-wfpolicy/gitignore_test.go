package main

import (
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

// stubGit points the subprocess seam at this test binary, which answers with
// the given output and exit status.
func stubGit(t *testing.T, stdout string, code int) {
	t.Helper()
	original := execCommand
	execCommand = func(_ string, _ ...string) *exec.Cmd {
		command := exec.Command(os.Args[0], "-test.run=TestIgnoreHelperProcess")
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

	_, err := gitCheckIgnore(".", []string{"/a/ignored.md", "/b/ignored.md"})

	require.Error(t, err, "output alongside a failure is a partial answer, and the caller must fail open")
}

// TestAPathHoldingANewlineIsStillAsked pins the NUL protocol. Newline-delimited,
// such a path split into two questions and came back C-quoted, so the one file
// git HAD answered about was the one the filter failed to drop.
func TestAPathHoldingANewlineIsStillAsked(t *testing.T) {
	odd := ".github/workflows/two\nlines.yml"
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
