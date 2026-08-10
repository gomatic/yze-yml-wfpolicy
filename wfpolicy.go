// Package wfpolicy reports GitHub Actions workflow steps that resolve an
// action from a moving branch instead of a fixed ref.
//
// `uses: owner/action@main` re-resolves on every run, so the code a workflow
// executes changes without a single line of that workflow changing — the
// supply-chain shape where an upstream force-push, or a compromised upstream,
// runs inside a job holding this repository's credentials. A tag or a commit
// SHA names something that does not move on its own.
//
// The rule is a DENYLIST of refs that are branches by construction — main,
// master, HEAD and the handful of conventional development-branch names — and
// nothing else. The alternative, guessing whether an arbitrary ref is a tag or
// a branch, cannot be done from the text: `@release-1.0` is a plausible name
// for either, and a gate that guesses reports findings nobody can act on. A
// SHA and a `@v2` tag are both silent, which is what the fleet writes.
//
// A local action (`uses: ./.github/actions/x`) names no ref at all and is this
// repository's own code, and a container action (`uses: docker://…`) is pinned
// by its image reference; neither can be branch-pinned, so neither is read.
package wfpolicy

import (
	"fmt"
	"strings"

	goyze "github.com/gomatic/go-yze"
	"gopkg.in/yaml.v3"
)

// Name is the analyzer's stable identifier — the suffix of its flat rule id and
// the key the yze suite catalogs it under.
const Name = "wfpin"

// Tool is the suite name stamped on every diagnostic.
const Tool = "yze"

// Rule is the stable, flat rule id every diagnostic carries: "yze/" + [Name].
const Rule = Tool + "/" + Name

// Category is the language group this analyzer belongs to, used by the yze
// suite to run it only when processing workflows.
const Category = "workflow"

// Path is the file path stamped on each diagnostic's location.
type Path string

// Source is the text of one workflow file.
type Source string

// message formats a moving-ref finding.
const message = "`uses: %s` resolves %q, a branch that moves; pin a tag or a commit SHA so the " +
	"action this workflow runs cannot change without the workflow changing"

// usesKey is the workflow field naming the action a step runs.
const usesKey = "uses"

// movingRefs are the refs that name a branch by construction. The set is a
// denylist on purpose: every other ref is presumed fixed, because telling a tag
// from a branch is not decidable from the text and a gate that guesses is a
// gate that gets switched off.
var movingRefs = map[string]bool{
	"main":    true,
	"master":  true,
	"HEAD":    true,
	"develop": true,
	"dev":     true,
	"trunk":   true,
	"latest":  true,
}

// Diagnostics reports every workflow step pinned to a moving branch. path is
// stamped on each diagnostic's location. A source that is not YAML yields the
// parse error, so the caller surfaces a tool failure rather than a clean pass.
func Diagnostics(path Path, source Source) ([]goyze.Diagnostic, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(source), &root); err != nil {
		return nil, ErrParse.With(err, "path", string(path))
	}
	var diags []goyze.Diagnostic
	walk(&root, func(value *yaml.Node) {
		if diag, ok := pinDiagnostic(path, value); ok {
			diags = append(diags, diag)
		}
	})
	return diags, nil
}

// walk visits the value of every `uses:` key in the document, at any depth. The
// key is looked for rather than the path to it, because a workflow spells
// `uses` in three places — a step, a reusable-workflow job, and a composite
// action's step — and enumerating those paths would silently miss whichever
// shape GitHub adds next.
func walk(node *yaml.Node, visit func(*yaml.Node)) {
	if node.Kind == yaml.MappingNode {
		visitMapping(node, visit)
	}
	for _, child := range node.Content {
		walk(child, visit)
	}
}

// visitMapping reports the `uses` values of one mapping's key/value pairs,
// which YAML stores as a flat alternating list.
func visitMapping(node *yaml.Node, visit func(*yaml.Node)) {
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Value == usesKey && value.Kind == yaml.ScalarNode {
			visit(value)
		}
	}
}

// pinDiagnostic reports the finding for one `uses:` value, if it names a moving
// branch.
func pinDiagnostic(path Path, value *yaml.Node) (goyze.Diagnostic, bool) {
	ref, ok := movingRef(value.Value)
	if !ok {
		return goyze.Diagnostic{}, false
	}
	return goyze.Diagnostic{
		Tool:     Tool,
		Rule:     Rule,
		Path:     string(path),
		Line:     value.Line,
		Col:      value.Column,
		Severity: goyze.SeverityError,
		Message:  fmt.Sprintf(message, value.Value, ref),
	}, true
}

// movingRef is the branch a `uses:` value resolves, when it resolves one. A
// value with no `@` names a local or container action, which carries no ref to
// move.
func movingRef(uses string) (string, bool) {
	_, ref, found := strings.Cut(uses, "@")
	if !found {
		return "", false
	}
	return ref, movingRefs[ref]
}
