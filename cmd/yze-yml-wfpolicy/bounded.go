package main

// Bounding what is read. The limit belongs at the single place every path is
// read — not in the walk — because a bound that guards one entry point and not
// the other is not a bound. This analyzer had neither, while both its siblings
// had both: a 2 GB file reached 4.3 GB resident whether it was walked to or
// named outright.

import (
	goyze "github.com/gomatic/go-yze"

	wfpolicy "github.com/gomatic/yze-yml-wfpolicy"
)

// readFile reads a workflow, bounded. The bound sits at the ONE place every path
// is read, so the walk and a named argument cannot disagree about it.
var readFile = func(path string) ([]byte, error) {
	return goyze.BoundedRead(files, goyze.FilePath(path), wfpolicy.SizeLimit)
}
