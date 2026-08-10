package main

// Discovery decides which files this command hands to the analyzer: what GitHub
// reads as a workflow or an action, which trees are somebody else's, and what is
// not source at all.

import (
	"io/fs"
	"path/filepath"
	"strings"
)

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
// action is defined in. They are matched EXACTLY, as is the workflow extension
// below: GitHub reads these paths literally on a case-sensitive filesystem, so
// `ACTION.YML` is a file it never opens, and claiming one would report a pin
// that can never run. GitHub reads one at ANY path, because an action is
// referenced by directory, so this is deliberately not anchored anywhere.
var compositeNames = map[string]bool{"action.yml": true, "action.yaml": true}

// isWorkflowFile reports a path GitHub would read as a workflow or as an
// action definition. Both are read because both spell `uses:` and both run
// with the calling job's credentials — a composite action pinned to a branch
// is the same supply-chain hole as a workflow step pinned to one, and scanning
// only workflows left the fleet's own composite actions unchecked.
func isWorkflowFile(path entryPath) bool {
	base := filepath.Base(string(path))
	if compositeNames[base] {
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
