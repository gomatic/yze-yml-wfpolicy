// Command yze-yml-wfpolicy reports GitHub Actions workflows and composite
// actions that resolve a step's action from a moving ref instead of a fixed
// one, emitting the lean stickler-json report the stickler runner consumes.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	goyze "github.com/gomatic/go-yze"

	wfpolicy "github.com/gomatic/yze-yml-wfpolicy"
)

// Injected collaborators, so the command is testable without real I/O.
var (
	osExit                 = os.Exit
	readFile               = os.ReadFile
	statPath               = os.Stat
	walkDir                = filepath.WalkDir
	evalSymlinks           = filepath.EvalSymlinks
	checkIgnore            = goyze.GitCheckIgnore
	lookupEnv              = os.Getenv
	stdout       io.Writer = os.Stdout
)

func main() { osExit(run(os.Args[1:])) }

// run expands the arguments to workflow files, runs the analyzer, and emits the
// report.
func run(args []string) int {
	if len(args) == 0 {
		return fail(wfpolicy.ErrNoPaths.With(nil))
	}
	files, err := workflowFiles(args)
	if err != nil {
		return fail(err)
	}
	// The environment is read HERE, at the one boundary where ambient state is
	// visible, and handed to the library as a value.
	report, err := wfpolicy.Report(readFile, files, wfpolicy.ConfiguredOwners(lookupEnv))
	if err != nil {
		return fail(err)
	}
	if err := json.NewEncoder(stdout).Encode(report); err != nil {
		return fail(err)
	}
	return 0
}

// fail prints err to stderr and returns the failure exit code.
func fail(err error) int {
	_, _ = fmt.Fprintln(os.Stderr, "yze-yml-wfpolicy:", err)
	return 1
}

// workflowFiles expands each argument: a directory contributes the workflow
// files beneath it, and any other path is taken verbatim.
func workflowFiles(args []string) ([]string, error) {
	var named, walked []string
	// SEPARATE identity sets. Sharing one let whichever argument came first
	// claim a file, so a directory listed before a named workflow put it in the
	// walked list, where the ignore filter then deleted it — the same two
	// arguments in the opposite order gave the opposite verdict.
	isNamed, isWalked := map[string]bool{}, map[string]bool{}
	for _, arg := range args {
		found, isDir, err := expand(argument(arg))
		if err != nil {
			return nil, err
		}
		if isDir {
			walked = appendUnseen(walked, isWalked, found)
			continue
		}
		// A file NAMED outright is analyzed verbatim. Passing it through the
		// ignore filter answered a deliberate request with a silent clean pass
		// — the filter exists to keep a WALK from claiming files the
		// repository does not own, not to overrule an author who asked.
		named = appendUnseen(named, isNamed, found)
	}
	return append(named, goyze.Tracked(checkIgnore, without(isNamed, walked))...), nil
}

// without drops the walked files already claimed by name, so a file reached
// both ways is analyzed once, as the named file it was asked about.
func without(named map[string]bool, walked []string) []string {
	kept := make([]string, 0, len(walked))
	for _, file := range walked {
		if !named[canonical(filePath(file))] {
			kept = append(kept, file)
		}
	}
	return kept
}

// filePath is one discovered file, in the spelling the report will carry.
type filePath string

// canonical is the path with symlinks resolved, used ONLY as the identity of a
// file. Deduplication keyed on the spelling reported one workflow twice when it
// was reached two ways — through a link and directly, or by two spellings of
// one argument — which doubles a count the ratchet is measured against.
func canonical(path filePath) string {
	resolved, err := evalSymlinks(string(path))
	if err != nil {
		return string(path)
	}
	return resolved
}

// appendUnseen adds the files not already collected, in the order they were
// found. Overlapping arguments are ordinary — a runner that passes a directory
// and a file inside it is not making a mistake — and reporting one workflow
// twice doubles a count the soft-baseline ratchet is measured against.
func appendUnseen(files []string, seen map[string]bool, found []string) []string {
	for _, file := range found {
		identity := canonical(filePath(file))
		if !seen[identity] {
			seen[identity] = true
			files = append(files, file)
		}
	}
	return files
}

// expand is one argument's workflow files.
func expand(arg argument) ([]string, bool, error) {
	info, err := statPath(string(arg))
	switch {
	case err != nil:
		return nil, false, err
	case info.IsDir():
		found, walkErr := workflowFilesUnder(searchDir(arg))
		return found, true, walkErr
	case !info.Mode().IsRegular():
		// Naming a FIFO or a device outright skips the walk's guard, and
		// reading one hangs the gate rather than failing it.
		return nil, false, wfpolicy.ErrNotRegularFile.With(nil, "path", string(arg))
	}
	return []string{filepath.Clean(string(arg))}, false, nil
}

// searchDir is a directory argument expanded recursively to the workflow files
// it contains.
type searchDir string

// argument is one path this command was asked to analyze.
type argument string
