package main

// Ignored files are not this repository's prose. A prune list can only name the
// trees somebody thought of in advance — vendor, node_modules, a virtualenv, a
// coverage directory — and it grows forever, one false positive at a time,
// while still being wrong for the next repository. Git already knows the answer
// for every repository: what it ignores is not the owned surface, and telling
// an author to delete a workflow that is not in their repository is a finding
// they cannot act on.

import (
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
)

// execCommand is the subprocess seam: a REFERENCE to exec.Command rather than a
// call, so a test can drive this path with no git installed and from outside
// any repository. A unit test that needs a real git, or a real checkout, is not
// a unit test — it is an integration test wearing one's name.
var execCommand = exec.Command

// absolutePath resolves a path against the working directory. It is a seam for
// the same reason exec.Command is: its only failure is an unreadable working
// directory, which a test cannot arrange and a gate must still survive.
var absolutePath = filepath.Abs

// repoDir is a directory inside the repository the ignore question is asked
// from.
type repoDir string

// ignoreLister reports which of the given paths git ignores, asked from within
// the given directory.
type ignoreLister func(root repoDir, paths []string) (map[string]bool, error)

// gitCheckIgnore asks git which paths it ignores, feeding them on stdin so the
// argument list cannot overflow on a large tree.
func gitCheckIgnore(root repoDir, paths []string) (map[string]bool, error) {
	if len(paths) == 0 {
		return map[string]bool{}, nil
	}
	// Asked from INSIDE the repository. Run from wherever the process happened
	// to start, git answers "not in a repository" for every path, the caller
	// fails open, and the filter silently does nothing at all — which is how
	// this first shipped.
	// ABSOLUTE paths. git resolves a relative path against its own working
	// directory, so relative paths plus a changed directory answered about
	// files that do not exist — the filter silently kept everything, and then
	// silently dropped real findings once it started answering at all.
	absolute, original := absolutePaths(paths)
	// -z, so the protocol is NUL-delimited. Newline-delimited, a path
	// CONTAINING a newline split into two questions and came back C-quoted,
	// which no lookup could match — the one file git had answered about was
	// the one the filter failed to drop.
	//
	// core.excludesFile is neutralised. It points at a machine-local file that
	// is in no repository, so the gate's verdict differed between a developer's
	// machine and CI: this developer's global excludes list CHANGELOG, making
	// the rule's flagship target invisible locally and a finding in CI. What a
	// REPOSITORY ignores is the repository's business; what a machine ignores
	// is not.
	command := execCommand("git", "-c", "core.excludesFile=/dev/null", "-c", "core.quotePath=false",
		"check-ignore", "--stdin", "-z")
	command.Dir = string(root)
	command.Stdin = strings.NewReader(strings.Join(absolute, "\x00"))
	out, err := command.Output()
	if err != nil {
		// Exit status 1 means "nothing was ignored", which is not a failure.
		// ANY other status means git could not answer — and a partial answer
		// is not an answer: asked about two repositories at once, git prints
		// what it resolved and then aborts, and accepting that output dropped
		// half the list while silently keeping the other half's ignored files.
		return map[string]bool{}, exitedCleanly(err)
	}
	ignored := map[string]bool{}
	for _, path := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if given, ok := original[path]; ok {
			ignored[given] = true
		}
	}
	return ignored, nil
}

// absolutePaths is the paths as git must be given them, and the map back to the
// spellings the caller uses and the report carries.
func absolutePaths(paths []string) ([]string, map[string]string) {
	absolute := make([]string, 0, len(paths))
	original := make(map[string]string, len(paths))
	for _, path := range paths {
		full, err := absolutePath(path)
		if err != nil {
			full = path
		}
		absolute = append(absolute, full)
		original[full] = path
	}
	return absolute, original
}

// exitedCleanly reports the error as nil when git merely found nothing to
// ignore, and as itself otherwise.
func exitedCleanly(err error) error {
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return nil
	}
	return err
}

// tracked drops the paths git ignores.
//
// It FAILS OPEN: a tree that is not a git repository, or a machine with no git,
// yields every path unchanged. The alternative — treating "cannot answer" as
// "ignore everything" — would turn a missing tool into a silent clean pass,
// which is the one result a gate must never produce. This is the same policy
// the yze suite applies to the Go side.
func tracked(ignores ignoreLister, root repoDir, paths []string) []string {
	ignored, err := ignores(root, paths)
	if err != nil {
		return paths
	}
	kept := make([]string, 0, len(paths))
	for _, path := range paths {
		if !ignored[path] {
			kept = append(kept, path)
		}
	}
	return kept
}
