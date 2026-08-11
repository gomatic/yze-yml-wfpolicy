package main

// Where this command reads its configuration: the process environment, at the
// one boundary where ambient state is visible, handed to the library as a value.
// The library takes the owner list as a parameter and never reaches for the
// environment itself — a library that does makes every caller, and every test,
// depend on what happened to be exported.

import (
	"os"

	wfpolicy "github.com/gomatic/yze-yml-wfpolicy"
)

// lookupEnv reads one environment variable. It is a seam so a test can supply a
// value without exporting one, and so this command's ONE ambient input can be
// neutralised for the tests that are not about it.
var lookupEnv = os.Getenv

// configuredOwners is the accounts this run treats as its own. There is no
// default and never will be: which accounts are "ours" belongs to whoever runs
// the check, so an unconfigured run reports only the half that needs no local
// knowledge rather than inventing a finding about a repository whose ownership
// it was told nothing about.
func configuredOwners() wfpolicy.Owners {
	return wfpolicy.ConfiguredOwners(lookupEnv)
}
