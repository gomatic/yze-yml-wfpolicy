// Package wfpolicy reports GitHub Actions workflow steps that resolve an
// action from a moving branch instead of a fixed ref.
//
// `uses: owner/action@main` re-resolves on every run, so the code a workflow
// executes changes without a single line of that workflow changing — the
// supply-chain shape where an upstream force-push, or a compromised upstream,
// runs inside a job holding this repository's credentials. A tag or a commit
// SHA names something that does not move on its own — for an action we do NOT
// control. For one we publish the rule inverts, because a major tag moving is
// the point: see [Owners].
//
// The rule is a DENYLIST of refs that are branches by construction — main,
// master, HEAD and the handful of conventional development-branch names — and
// nothing else. The alternative, guessing whether an arbitrary ref is a tag or
// a branch, cannot be done from the text: `@release-1.0` is a plausible name
// for either, and a gate that guesses reports findings nobody can act on. A
// SHA and a `@v2` tag are both silent, which is what the fleet writes.
//
// A local action (`uses: ./.github/actions/x`) names no ref at all and is this
// repository's own code, and a container action (`uses: docker://…`) names an
// image whose tag is not a git ref at all — telling an author their image tag
// is a branch would be false — so neither is read. The composite action a local
// reference points AT is read, because its steps run with the job's
// credentials and that file is where its own pins live.
package wfpolicy

import (
	"errors"
	"io"
	"strings"

	goyze "github.com/gomatic/go-yze"
	"gopkg.in/yaml.v3"
)

// Name is the analyzer's stable identifier. It MATCHES the repository suffix,
// as every other analyzer in the family does — `yze-go-errconst` emits
// `yze/errconst`. This one emitted `yze/wfpin` after the repository was renamed
// to describe both of its opposite rules rather than only the pinning half, and
// a rule id is the identifier a baseline, a ratchet and a `//nolint` all name.
// It could be corrected only before publication, and it was. — the suffix of its flat rule id and
// the key the yze suite catalogs it under.
const Name = "wfpolicy"

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

// usesRef is the value of a `uses:` key: the action a step runs, and the ref it
// is pinned to.
type usesRef string

// message formats a moving-ref finding.
const message = "`uses: %s` resolves %q, a ref that moves; pin an immutable tag or a commit SHA so the " +
	"action this workflow runs cannot change without the workflow changing"

// ownedMessage formats a pinned-own-action finding, which is the OPPOSITE
// defect: an action this fleet publishes must track its major tag, so a fix
// reaches every consumer on their next run.
const ownedMessage = "`uses: %s` pins %q, but %s is ours; track the major tag (`@%s`) instead — a pinned " +
	"patch means a CVE fix or a gate change needs an edit in every repository that consumes it"

// ownedCommitMessage formats an owned action frozen to a COMMIT, which has no
// major version to track. The sentence names the real cost of a frozen commit:
// nothing about it moves, so every consuming repository needs an edit.
const ownedCommitMessage = "`uses: %s` pins %q, but %s is ours; track the major tag instead — a pinned commit " +
	"means a CVE fix or a gate change needs an edit in every repository that consumes it"

// ownedUnknownMessage formats an owned action pinned to a ref that is neither a
// version nor a commit nor a branch — `@release-1.2`, `@refs/tags/v2.1.0`, an
// empty ref. No major version can be read out of it, so none is suggested:
// printing a number derived from a ref that carries none would hand the author
// a tag that does not exist. It is deliberately NOT told it pinned a commit,
// which it provably did not.
const ownedUnknownMessage = "`uses: %s` pins %q, but %s is ours; that ref names no major version we can track — " +
	"tag the release and reference the major tag, so a consumer picks up fixes without an edit"

// ownedBranchMessage formats the other owned-action defect: not frozen, but
// riding a ref that MOVES. Such a ref names no release and can be re-pointed
// under you, so it is neither the immutability a third-party pin gives nor the
// deliberate movement a major tag gives — it is the worst of both.
const ownedBranchMessage = "`uses: %s` rides %q, a ref that moves, but %s is ours; track the major tag " +
	"instead — a moving ref names no release and can be re-pointed under you, so it gives neither immutability " +
	"nor a deliberate upgrade"

// usesKey is the workflow field naming the action a step runs.
const usesKey = "uses"

// movingRefs are the refs that MOVE by construction — branches, the symbolic
// HEAD, and `latest`, which is conventionally a tag that is re-pointed rather
// than a branch. The set is a denylist on purpose: every other ref is presumed
// fixed, because telling an immutable tag from a re-pointed one is not
// decidable from the text, and a gate that guesses is a gate that gets
// switched off.
var movingRefs = map[string]bool{
	"main":    true,
	"master":  true,
	"HEAD":    true,
	"develop": true,
	"dev":     true,
	"trunk":   true,
	"latest":  true,
}

// Diagnostics reports every action reference that should not be where it is:
// a moving ref on somebody else's action, and a frozen or branch ref on one of
// the runner's own. path is stamped on each diagnostic's location.
//
// The owner list is a PARAMETER, never read from the process. A library that
// reaches for the environment makes every caller — and every test — depend on
// what happened to be exported: this one did, and the suite passed or failed
// according to the developer's shell. Reading ambient state is main's job, at
// the one boundary where it is visible.
func Diagnostics(path Path, source Source, owners Owners) ([]goyze.Diagnostic, error) {
	// EVERY document, not just the first. yaml.Unmarshal decodes one, which
	// left a syntax error in any later document reported as a clean pass — the
	// exact failure this rule's own contract forbids — and hid every pin
	// written after the first `---`.
	decoder := yaml.NewDecoder(strings.NewReader(string(source)))
	var diags []goyze.Diagnostic
	for {
		root, err := nextDocument(decoder)
		if err != nil {
			return nil, ErrParse.With(err, "path", string(path))
		}
		if root == nil {
			return diags, nil
		}
		diags = append(diags, documentDiagnostics(path, owners, root)...)
	}
}

// nextDocument reads one document, reporting a nil document at the end of the
// stream. Every document is read, not just the first: decoding one left a
// syntax error in any later document reported as a clean pass — the exact
// silent success this rule exists to prevent — and hid every pin written after
// the first separator.
func nextDocument(decoder *yaml.Decoder) (*yaml.Node, error) {
	var root yaml.Node
	switch err := decoder.Decode(&root); {
	case errors.Is(err, io.EOF):
		return nil, nil
	case err != nil:
		return nil, err
	}
	return &root, nil
}

// documentDiagnostics reports every moving-ref pin in one document.
func documentDiagnostics(path Path, owners Owners, root *yaml.Node) []goyze.Diagnostic {
	var diags []goyze.Diagnostic
	walk(root, schemaKeys, visited{}, func(value *yaml.Node) {
		if diag, ok := pinDiagnostic(path, owners, value); ok {
			diags = append(diags, diag)
		}
	})
	return diags
}

// reference is the action a `uses:` value names, or the empty string when it
// names none. An alias is FOLLOWED, because it carries the anchor's label as
// its own value and comparing that label against the denylist is a one-line
// evasion of the whole rule; the node itself is still what carries the
// position, so the finding lands where the author wrote the reference rather
// than on a shared anchor several steps away. A mapping or sequence names no
// action at all — GitHub rejects that shape, and reading it would invent a
// finding from a document that has none.
func reference(value *yaml.Node) usesRef {
	resolved := follow(value)
	switch resolved.Kind {
	case yaml.ScalarNode:
		return usesRef(resolved.Value)
	case yaml.DocumentNode, yaml.SequenceNode, yaml.MappingNode, yaml.AliasNode:
		// None of these names an action. GitHub rejects the shape, and reading
		// it would invent a finding from a document that has none.
	}
	return ""
}

// follow resolves an alias to the node it names, and yields anything else
// unchanged. An alias whose target is absent names nothing; the parser never
// produces one, and standing on that assumption would trade a finding for a
// panic.
func follow(value *yaml.Node) *yaml.Node {
	switch value.Kind {
	case yaml.AliasNode:
		if value.Alias != nil {
			return value.Alias
		}
	case yaml.DocumentNode, yaml.SequenceNode, yaml.MappingNode, yaml.ScalarNode:
	}
	return value
}

// pinDiagnostic reports the finding for one `uses:` value, if it names a ref
// that should not be there — a moving one for somebody else's action, or a
// pinned one for ours.
func pinDiagnostic(path Path, owners Owners, value *yaml.Node) (goyze.Diagnostic, bool) {
	uses := reference(value)
	text, ok := refDiagnostic(owners, uses)
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
		Message:  text,
	}, true
}

// containerScheme marks a `uses:` value naming a container image rather than an
// action repository. Its `@` introduces an image digest or tag, which is not a
// git ref, so reading one would tell an author their image tag is a branch.
const containerScheme = "docker://"

// movingRef is the ref a `uses:` value resolves, when it resolves one. A value
// with no `@` names a local action, which carries no ref to move, and a
// container reference names no git ref at all.
func movingRef(uses usesRef) (string, bool) {
	// Trimmed FIRST. YAML preserves the space inside a quoted scalar, and
	// testing the prefixes before trimming meant a single leading space turned
	// a container image into a git ref and a local action into a remote one —
	// each producing a finding the doc says this rule never makes.
	trimmed := strings.TrimSpace(string(uses))
	if strings.HasPrefix(trimmed, containerScheme) || strings.HasPrefix(trimmed, ".") {
		return "", false
	}
	_, ref, found := strings.Cut(trimmed, "@")
	if !found {
		return "", false
	}
	return ref, movingRefs[ref]
}
