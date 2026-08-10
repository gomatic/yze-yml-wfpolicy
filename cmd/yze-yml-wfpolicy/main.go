// Command yze-yml-wfpolicy reports GitHub Actions workflows and composite
// actions that resolve a step's action from a moving ref instead of a fixed
// one, emitting the lean stickler-json report the stickler runner consumes.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

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
	for _, arg := range args {
		info, err := statPath(arg)
		switch {
		case err != nil:
			return nil, err
		case info.IsDir():
			found, walkErr := workflowFilesUnder(searchDir(arg))
			if walkErr != nil {
				return nil, walkErr
			}
			files = append(files, found...)
		default:
			files = append(files, arg)
		}
	}
	return files, nil
}

// searchDir is a directory argument expanded recursively to the workflow files
// it contains.
type searchDir string

// walkRoot is the directory a walk started from.
type walkRoot string

// entryPath is the path of one entry the walk visited.
type entryPath string

// entryName is a single path element — one directory's own name.
type entryName string

// workflowFilesUnder walks dir collecting every file GitHub reads as a workflow
// or as a composite action.
func workflowFilesUnder(dir searchDir) ([]string, error) {
	root := filepath.Clean(string(dir))
	var files []string
	err := walkDir(root, func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return prunedDir(walkRoot(root), entryPath(path), entryName(d.Name()))
		// Only a regular file is read. A FIFO blocks forever on open, and a
		// device or socket is not source in any case.
		case d.Type().IsRegular() && isWorkflowFile(entryPath(path)):
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// prunedDir decides whether to descend into one directory. The walk root is
// never pruned: asking for a directory by name and being handed a silent clean
// pass is worse than any tree this skips.
func prunedDir(root walkRoot, path entryPath, name entryName) error {
	if string(path) == string(root) {
		return nil
	}
	if pruned(name) || nestedRepository(path) {
		return fs.SkipDir
	}
	return nil
}

// pruned reports the trees that hold somebody else's code. A dependency ships
// its own workflows, and reporting them tells this repository to fix a pin it
// does not own — three such findings turned up in node_modules the first time
// this walked a real checkout. `.git` holds this repository's own object
// store, not its source. `.github` is deliberately NOT pruned despite being
// hidden: it is the only directory a workflow can live in.
func pruned(name entryName) bool {
	switch name {
	case ".git", "node_modules", "vendor", "testdata":
		return true
	}
	return false
}

// nestedRepository reports a directory that is its own git checkout — a
// submodule, or a sibling repository sitting inside this tree. Its workflows
// belong to that repository and are gated by that repository's own run;
// reporting them here asks an author to fix a file this checkout does not own,
// which is the same mistake as reporting a vendored dependency.
func nestedRepository(path entryPath) bool {
	_, err := statPath(filepath.Join(string(path), ".git"))
	return err == nil
}

// workflowDir is the only directory GitHub reads a workflow from.
var workflowDir = filepath.Join(".github", "workflows")

// compositeNames are the file names a composite (or container, or JavaScript)
// action is defined in. GitHub reads one at ANY path, because an action is
// referenced by directory, so this is deliberately not anchored anywhere.
var compositeNames = map[string]bool{"action.yml": true, "action.yaml": true}

// isWorkflowFile reports a path GitHub would read as a workflow or as an
// action definition. Both are read because both spell `uses:` and both run
// with the calling job's credentials — a composite action pinned to a branch
// is the same supply-chain hole as a workflow step pinned to one, and scanning
// only workflows left the fleet's own composite actions unchecked.
func isWorkflowFile(path entryPath) bool {
	base := filepath.Base(string(path))
	if compositeNames[strings.ToLower(base)] {
		return true
	}
	if !strings.HasSuffix(base, ".yml") && !strings.HasSuffix(base, ".yaml") {
		return false
	}
	// The directory must END IN the two components `.github/workflows`, not
	// merely end with those characters: a suffix test also claimed
	// `my.github/workflows`, whose files GitHub never reads.
	dir := filepath.Dir(string(path))
	return dir == workflowDir || strings.HasSuffix(dir, string(filepath.Separator)+workflowDir)
}
