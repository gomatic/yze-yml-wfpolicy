package main

// What this command claims. Everything else about turning arguments into files
// — the symlinked root, the identity of a path reached two ways, the tree that
// cannot be read, the size bound — is the shared discovery's, because three
// analyzers answering those questions separately answered them differently.

import (
	"path/filepath"
	"strings"

	goyze "github.com/gomatic/go-yze"
)

// discovery is this command's file discovery: the shared walk, told what a
// workflow is and whose trees to skip.
func discovery() goyze.Discovery {
	return goyze.Discovery{Files: files, Claims: isWorkflowFile, Prunes: pruned}
}

// pruned reports the trees that hold somebody else's code. A dependency ships
// its own workflows, and reporting them tells this repository to fix a pin it
// does not own — three such findings turned up in node_modules the first time
// this walked a real checkout. `.github` is deliberately NOT pruned despite
// being hidden: it is the only directory a workflow can live in. `.git` and
// nested checkouts are the shared walk's business, not this list's.
func pruned(name goyze.DirName) bool {
	switch name {
	case "node_modules", "vendor", "testdata":
		return true
	}
	return false
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

// isWorkflowFile reports a path GitHub would read as a workflow or as an action
// definition. Both are read because both spell `uses:` and both run with the
// calling job's credentials — a composite action pinned to a branch is the same
// supply-chain hole as a workflow step pinned to one, and scanning only
// workflows left the fleet's own composite actions unchecked.
func isWorkflowFile(path goyze.FilePath) bool {
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
