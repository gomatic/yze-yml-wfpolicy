package wfpolicy

import (
	"fmt"

	errs "github.com/gomatic/go-error"
	goyze "github.com/gomatic/go-yze"
)

// ErrParse reports a file that is not YAML.
const ErrParse errs.Const = "cannot parse workflow YAML"

// ErrReadFile reports that a workflow file could not be read.
const ErrReadFile errs.Const = "cannot read workflow file"

// ErrNoPaths reports a run given nothing to analyze. A runner whose root
// placeholder expands to nothing would otherwise green the gate over a
// repository no analyzer ever looked at.
const ErrNoPaths errs.Const = "no paths to analyze"

// ErrNotRegularFile reports a named path whose contents cannot be read. A FIFO
// blocks forever on open and a character device never ends, so a single such
// argument hangs the gate instead of failing it — the one outcome nobody can
// diagnose from a stuck CI job.
const ErrNotRegularFile errs.Const = "not a regular file"

// unreadableMessage formats the finding for a file that could not be parsed.
const unreadableMessage = "cannot be analyzed as a workflow: %v; the gate cannot vouch for a file it could not " +
	"read, so this is reported rather than passed over"

// FileReader reads a file's bytes; injected so aggregation is testable without
// the filesystem.
type FileReader func(path string) ([]byte, error)

// Report runs the pin check over each file and aggregates the diagnostics into
// the lean stickler-json report. A read failure aborts with ErrReadFile; a file
// that is not YAML aborts with the wrapped ErrParse.
func Report(read FileReader, files []string, owners Owners) (goyze.Report, error) {
	report := goyze.Report{}
	for _, file := range files {
		data, err := read(file)
		if err != nil {
			return goyze.Report{}, ErrReadFile.With(err, "path", file)
		}
		report.Diagnostics = append(report.Diagnostics, fileDiagnostics(Path(file), Source(data), owners)...)
	}
	return report, nil
}

// fileDiagnostics is one file's findings, with a parse failure reported as a
// finding of its own rather than raised as the whole run's error.
//
// `%YAML 1.2` is a legal directive GitHub accepts and this 1.1 parser rejects,
// and aborting on it destroyed every other file's findings in the run. The file
// is still REPORTED, so nothing is passed over in silence; it simply can no
// longer silence its neighbours.
func fileDiagnostics(file Path, source Source, owners Owners) []goyze.Diagnostic {
	diags, err := Diagnostics(file, source, owners)
	if err != nil {
		return []goyze.Diagnostic{{
			Tool:     Tool,
			Rule:     Rule,
			Path:     string(file),
			Line:     1,
			Col:      1,
			Severity: goyze.SeverityError,
			Message:  fmt.Sprintf(unreadableMessage, err),
		}}
	}
	return diags
}
