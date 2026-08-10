// Command yze-yml-wfpolicy reports shell scripts missing the required shell
// options, and `set` calls written in short flag form, emitting the lean
// stickler-json report the stickler runner consumes.
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

// shellFiles expands each argument: a directory contributes the workflow files
// beneath it, and any other path is taken verbatim.
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

// searchDir is a directory argument expanded recursively to the workflow files it
// contains.
type searchDir string

// workflowFilesUnder walks dir collecting every workflow file: a *.yml or
// *.yaml under a .github/workflows directory, which is the only place GitHub
// reads them from — a YAML file elsewhere is not a workflow and its `uses:`
// key, if it has one, means something else entirely.
func workflowFilesUnder(dir searchDir) ([]string, error) {
	var files []string
	err := walkDir(string(dir), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return pruned(d.Name())
		}
		if isWorkflowFile(path) {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// pruned skips the trees that hold somebody else's code. A dependency ships
// its own workflows, and reporting them tells this repository to fix a pin it
// does not own — three such findings turned up in node_modules the first time
// this walked a real checkout. `.github` is deliberately NOT pruned despite
// being hidden: it is the only directory a workflow can live in.
func pruned(name string) error {
	if name == "node_modules" || name == "vendor" || name == "testdata" {
		return fs.SkipDir
	}
	return nil
}

// isWorkflowFile reports a path GitHub would read as a workflow.
func isWorkflowFile(path string) bool {
	if !strings.HasSuffix(path, ".yml") && !strings.HasSuffix(path, ".yaml") {
		return false
	}
	return strings.HasSuffix(filepath.Dir(path), filepath.Join(".github", "workflows"))
}
