// Command yze-yml-wfpolicy reports GitHub Actions workflows and composite
// actions whose `uses:` resolves from a ref that may change under them — a third
// party's action left on a moving ref, or one of the runner's own accounts
// frozen to a commit — emitting the lean stickler-json report the stickler
// runner consumes.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	goyze "github.com/gomatic/go-yze"

	wfpolicy "github.com/gomatic/yze-yml-wfpolicy"
)

// Injected collaborators, so the command is testable without real I/O.
//
// The filesystem is ONE value rather than a scatter of package variables. The
// three source analyzers each kept their own set, and the sets drifted: this one
// had no seam for the symlinked walk root it therefore did not resolve, and none
// for the size bound it therefore did not have.
var (
	osExit           = os.Exit
	files            = goyze.OSFileSystem()
	stdout io.Writer = os.Stdout
)

func main() { osExit(run(os.Args[1:])) }

// run expands the arguments to workflow files, runs the analyzer, and emits the
// report.
func run(args []string) int {
	if err := report(args); err != nil {
		return fail(err)
	}
	return 0
}

// report is the run itself, as an ERROR rather than an exit code. run answers
// the process, which cannot be matched: with the refusal only ever reaching an
// int and a line of stderr, this command's sentinel could be swapped for any
// other with the whole suite green, so the failure it exists to name had nothing
// behind it. The two sibling analyzers carried the same gap and it was repaired
// in each; this was the third.
func report(args []string) error {
	if len(args) == 0 {
		return wfpolicy.ErrNoPaths.With(nil)
	}
	found, err := discovery().Expand(args)
	if err != nil {
		return err
	}
	// Report cannot fail: an unreadable or unparseable file becomes a finding
	// against that file rather than the run's error, so one bad file can never
	// empty the report.
	out := wfpolicy.Report(readFile, found.Files, configuredOwners())
	out.Diagnostics = append(wfpolicy.Unreadable(found.Unreadable), out.Diagnostics...)
	return json.NewEncoder(stdout).Encode(out)
}

// fail prints err to stderr and returns the failure exit code.
func fail(err error) int {
	_, _ = fmt.Fprintln(os.Stderr, "yze-yml-wfpolicy:", err)
	return 1
}
