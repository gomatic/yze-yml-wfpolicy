package wfpolicy

// Finding the action references in a document. The KEY is looked for rather
// than the path to it, because a workflow spells `uses` in a step, a
// reusable-workflow job and a composite action's step — and enumerating those
// paths would silently miss whichever shape GitHub adds next. The exception is
// a key the AUTHOR named rather than GitHub, under which nothing is a schema
// field at all.

import "gopkg.in/yaml.v3"

// walk visits the value of every `uses:` key in the document, at any depth.
func walk(node *yaml.Node, keys keyOwner, seen visited, visit func(*yaml.Node)) {
	switch node.Kind {
	case yaml.MappingNode:
		// A mapping walks its own children, so that the values of author-named
		// keys can be skipped rather than descended into.
		visitMapping(node, keys, seen, visit)
		return
	case yaml.AliasNode:
		// An alias is FOLLOWED INTO. An AliasNode carries no Content of its own,
		// so treating it as a leaf meant a `<<:` merge of an anchor defined
		// under `with:` — a subtree the walk deliberately skips — was seen in
		// neither place: not where it was written, and not where it was used.
		// That is a whole-subtree evasion available to anyone who knows YAML.
		walkAlias(node, keys, seen, visit)
		return
	case yaml.DocumentNode, yaml.SequenceNode, yaml.ScalarNode:
		// Only a mapping holds keys, so only a mapping can hold a `uses:` key.
	}
	for _, child := range node.Content {
		walk(child, keys, seen, visit)
	}
}

// visited is the set of anchors already being followed on the current path,
// which is what keeps an anchor that refers to itself from walking forever.
type visited map[*yaml.Node]bool

// walkAlias follows an alias to the node it names, once per path. A YAML
// document may legally alias the same anchor from many places; only a CYCLE is
// refused, and refusing it silently is correct — the anchor's contents have
// already been walked by the reference that opened the cycle.
func walkAlias(node *yaml.Node, keys keyOwner, seen visited, visit func(*yaml.Node)) {
	target := node.Alias
	if target == nil || seen[target] {
		return
	}
	seen[target] = true
	defer delete(seen, target)
	walk(target, keys, seen, visit)
}

// visitMapping reports the `uses` values of one mapping's key/value pairs.
// YAML stores a mapping as a flat alternating list, so the step of two is what
// keeps keys and values from swapping places.
func visitMapping(node *yaml.Node, keys keyOwner, seen visited, visit func(*yaml.Node)) {
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := follow(node.Content[i]), node.Content[i+1]
		if keys == schemaKeys && authored[key.Value] {
			// `with:` and `env:` hold keys the AUTHOR chose, so a `uses` there
			// is an input named uses, not an action reference — GitHub never
			// resolves it, and reporting one is a finding nobody can act on.
			continue
		}
		if key.Value == usesKey {
			visit(value)
		}
		walk(value, keysUnder(keys, mappingKey(key.Value)), seen, visit)
	}
}

// authored are the workflow keys whose CHILD keys are named by the author
// rather than by GitHub. Nothing inside them is a schema field.
var authored = map[string]bool{"with": true, "env": true}

// jobsKey introduces the one mapping whose KEYS the author chooses. A job may
// be called `env`, and skipping it as an author-named context silenced every
// step in that job — a whole-job evasion available by renaming a job. The
// exemption is positional, not by name: `with` and `env` mean what [authored]
// says only where GitHub, not the author, put them.
const jobsKey mappingKey = "jobs"

// mappingKey is one key of a YAML mapping, as written.
type mappingKey string

// keysUnder says who names the keys of the mapping a given key introduces.
//
// The answer depends on where the key ITSELF sits, not on how it is spelled.
// Deciding it from the name alone was the same defect twice, in mirror image: a
// job named `env` was first read as an author-named context and silenced every
// step in it, and once that was fixed positionally, a job named `jobs` was read
// as introducing job IDs a second time — so its own body was no longer schema,
// and the `with:` inside it stopped being exempt. A workflow alternates
// strictly: GitHub's keys, then the author's job IDs, then GitHub's keys again.
func keysUnder(keys keyOwner, key mappingKey) keyOwner {
	switch keys {
	case jobIDs:
		// Whatever the job is called, its BODY is GitHub's schema.
		return schemaKeys
	case schemaKeys:
		if key == jobsKey {
			return jobIDs
		}
	}
	return schemaKeys
}

// keyOwner says who chose the keys of the mapping being walked. It is a type
// rather than a bare flag because the whole exemption turns on it: the same two
// words mean GitHub's schema in one position and an author's label in the
// other.
type keyOwner int

const (
	// schemaKeys marks a mapping whose keys GitHub defines.
	schemaKeys keyOwner = iota
	// jobIDs marks the one mapping whose keys the author chooses.
	jobIDs
)
