package wfpolicy

import (
	errs "github.com/gomatic/go-error"
	goyze "github.com/gomatic/go-yze"
)

// ErrParse reports a file that is not YAML.
const ErrParse errs.Const = "cannot parse workflow YAML"

// ErrReadFile reports that a workflow file could not be read.
const ErrReadFile errs.Const = "cannot read workflow file"

// FileReader reads a file's bytes; injected so aggregation is testable without
// the filesystem.
type FileReader func(path string) ([]byte, error)

// Report runs the pin check over each file and aggregates the diagnostics into
// the lean stickler-json report. A read failure aborts with ErrReadFile; a file
// that is not YAML aborts with the wrapped ErrParse.
func Report(read FileReader, files []string) (goyze.Report, error) {
	report := goyze.Report{}
	for _, file := range files {
		data, err := read(file)
		if err != nil {
			return goyze.Report{}, ErrReadFile.With(err, "path", file)
		}
		diags, parseErr := Diagnostics(Path(file), Source(data))
		if parseErr != nil {
			return goyze.Report{}, parseErr
		}
		report.Diagnostics = append(report.Diagnostics, diags...)
	}
	return report, nil
}
