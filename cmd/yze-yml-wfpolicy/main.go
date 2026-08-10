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
	osExit              = os.Exit
	files               = goyze.OSFileSystem()
	lookupEnv           = os.Getenv
	stdout    io.Writer = os.Stdout
)

func main() { osExit(run(os.Args[1:])) }

// run expands the arguments to workflow files, runs the analyzer, and emits the
// report.
func run(args []string) int {
	if len(args) == 0 {
		return fail(wfpolicy.ErrNoPaths.With(nil))
	}
	found, err := discovery().Expand(args)
	if err != nil {
		return fail(err)
	}
	// The environment is read HERE, at the one boundary where ambient state is
	// visible, and handed to the library as a value.
	//
	// Report cannot fail: an unreadable or unparseable file becomes a finding
	// against that file rather than the run's error, so one bad file can never
	// empty the report.
	report := wfpolicy.Report(readFile, found.Files, wfpolicy.ConfiguredOwners(lookupEnv))
	report.Diagnostics = append(wfpolicy.Unreadable(found.Unreadable), report.Diagnostics...)
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
