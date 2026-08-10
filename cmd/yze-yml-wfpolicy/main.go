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

	wfpolicy "github.com/gomatic/yze-yml-wfpolicy"
)

// Injected collaborators, so the command is testable without real I/O.
var (
	osExit             = os.Exit
	readFile           = os.ReadFile
	statPath           = os.Stat
	walkDir            = filepath.WalkDir
	stdout   io.Writer = os.Stdout
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
	report, err := wfpolicy.Report(readFile, files)
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
	var files []string
	seen := map[string]bool{}
	for _, arg := range args {
		found, err := expand(argument(arg))
		if err != nil {
			return nil, err
		}
		files = appendUnseen(files, seen, found)
	}
	return files, nil
}

// appendUnseen adds the files not already collected, in the order they were
// found. Overlapping arguments are ordinary — a runner that passes a directory
// and a file inside it is not making a mistake — and reporting one workflow
// twice doubles a count the soft-baseline ratchet is measured against.
func appendUnseen(files []string, seen map[string]bool, found []string) []string {
	for _, file := range found {
		if !seen[file] {
			seen[file] = true
			files = append(files, file)
		}
	}
	return files
}

// expand is one argument's workflow files.
func expand(arg argument) ([]string, error) {
	info, err := statPath(string(arg))
	switch {
	case err != nil:
		return nil, err
	case info.IsDir():
		return workflowFilesUnder(searchDir(arg))
	case !info.Mode().IsRegular():
		// Naming a FIFO or a device outright skips the walk's guard, and
		// reading one hangs the gate rather than failing it.
		return nil, wfpolicy.ErrNotRegularFile.With(nil, "path", string(arg))
	}
	return []string{filepath.Clean(string(arg))}, nil
}

// searchDir is a directory argument expanded recursively to the workflow files
// it contains.
type searchDir string

// argument is one path this command was asked to analyze.
type argument string
