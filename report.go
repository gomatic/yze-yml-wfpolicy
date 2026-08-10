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

// finding is one diagnostic's rendered message.
type finding string

// ErrTooLarge reports a file past the size this rule will read. A workflow is
// not megabytes; a file that big is generated output, a data dump, or a mistake,
// and reading it costs its own size in memory for a rule that cannot apply.
const ErrTooLarge errs.Const = "workflow is too large to analyze"

// findingLimit bounds how many findings ONE file contributes, and reportLimit
// how many one RUN carries.
//
// The size bound alone does not bound the report: three hundred files each
// WITHIN it produced 1 092 000 diagnostics, a 437 MB report and 1.94 GB
// resident. A file with a thousand moving refs is one problem rather than a
// thousand, and so is a tree with ten thousand.
const (
	findingLimit = 1_000
	reportLimit  = 10_000
)

// truncationMessage formats the finding that stands for the ones not reported.
const truncationMessage = "%d pin findings in this file, of which %d are reported; a file with this many is " +
	"one problem rather than that many, and reporting them all costs more memory than reading it did"

// runTruncationMessage formats the finding that stands for the rest of a run.
const runTruncationMessage = "%d pin findings across this run, of which %d are reported; findings from %s " +
	"onward are omitted, because a tree with this many is one problem rather than that many"

// SizeLimit is the largest file read, in bytes.
//
// A workflow is a few kilobytes; the largest in the fleet is under forty. A file
// past this is a data dump, generated output, or a mistake, and reading it costs
// its own size in memory for a rule that cannot apply — a 2 GB file reached 4.3
// GB resident by BOTH entry points, because this analyzer had no bound at all
// while both its siblings did. The limit is generous by orders of magnitude over
// any real workflow, so it bounds the pathological case while still admitting
// every file anyone wrote.
const SizeLimit goyze.ByteCount = 128 << 10

// Report runs the pin check over each file and aggregates the diagnostics into
// the lean stickler-json report.
//
// It does not fail. A file that cannot be read, or that is not YAML, becomes one
// finding against that file and the run continues — a single unreadable file
// used to abort the run and return an empty report, so one bad file cost every
// other file its findings, and a gate reporting nothing is indistinguishable
// from a clean one. Both siblings already answered this way; this one did it for
// parse failures and not for read failures, which is the same outage reached
// through the one door still open.
func Report(read FileReader, files []string, owners Owners) goyze.Report {
	report := goyze.Report{}
	total := 0
	truncatedAt := Path("")
	for _, file := range files {
		found, held := fileFindings(read, Path(file), owners)
		// The TRUE count, not the reported one: a file past its own limit hands
		// back a truncated slice, and summing slices counted this analyzer's
		// truncation instead of the file's findings.
		total += held
		if truncatedAt != "" {
			// Past the limit the run keeps COUNTING but stops collecting, so
			// the total it reports is the true one.
			continue
		}
		room := reportLimit - len(report.Diagnostics)
		if len(found) > room {
			report.Diagnostics = append(report.Diagnostics, found[:room]...)
			truncatedAt = Path(file)
			continue
		}
		report.Diagnostics = append(report.Diagnostics, found...)
	}
	if truncatedAt != "" {
		report.Diagnostics = append(report.Diagnostics,
			diagnostic(truncatedAt, finding(fmt.Sprintf(runTruncationMessage, total, reportLimit, truncatedAt))))
	}
	return report
}

// fileFindings is one file's diagnostics, whether it could be read or not,
// bounded so a single pathological file cannot carry a run away.
func fileFindings(read FileReader, file Path, owners Owners) ([]goyze.Diagnostic, int) {
	data, err := read(string(file))
	if err != nil {
		return []goyze.Diagnostic{unreadable(file, err)}, 1
	}
	found := fileDiagnostics(file, Source(data), owners)
	held := len(found)
	if held <= findingLimit {
		return found, held
	}
	// Counted BEFORE the notice is appended: the notice is this analyzer's own
	// bookkeeping, not something the file contains.
	return append(found[:findingLimit],
		diagnostic(file, finding(fmt.Sprintf(truncationMessage, held, findingLimit)))), held
}

// Unreadable is the finding for each tree the walk could not enter. A directory
// the gate cannot descend into is reported rather than passed over, so nothing
// is lost in silence and the run still yields every other file's findings.
func Unreadable(paths []string) []goyze.Diagnostic {
	diags := make([]goyze.Diagnostic, 0, len(paths))
	for _, path := range paths {
		diags = append(diags, unreadable(Path(path), nil))
	}
	return diags
}

// unreadable is the finding for a path the analyzer could not read at all.
func unreadable(file Path, cause error) goyze.Diagnostic {
	return diagnostic(file, finding(fmt.Sprintf(unreadableMessage, ErrReadFile.With(cause, "path", string(file)))))
}

// diagnostic builds one finding at the head of a file.
func diagnostic(file Path, message finding) goyze.Diagnostic {
	return goyze.Diagnostic{
		Tool:     Tool,
		Rule:     Rule,
		Path:     string(file),
		Line:     1,
		Col:      1,
		Severity: goyze.SeverityError,
		Message:  string(message),
	}
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
		return []goyze.Diagnostic{diagnostic(file, finding(fmt.Sprintf(unreadableMessage, err)))}
	}
	return diags
}
