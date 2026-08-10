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
	// Every node is walked once PER POSITION. A node reached twice from the same
	// position is the same node — the same text, at the same line — so visiting
	// it again reports one written reference as two findings, and doing so per
	// REFERENCE is exponential in the nesting of the anchors that reach it.
	//
	// The position is part of the key because the two rules genuinely differ: an
	// anchor spliced under `jobs` holds job IDs, and the same anchor sitting at
	// the top level holds schema keys where `env` is an author's context and its
	// contents are skipped. Keyed on the node alone, whichever position came
	// FIRST decided — and a merge into `jobs` of an anchor defined above it lost
	// every step in the job. There are two positions, so this bounds the walk at
	// twice the document rather than at an exponential of it.
	if seen[at{node: node, keys: keys}] {
		return
	}
	seen[at{node: node, keys: keys}] = true
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

// visited is the set of nodes already walked in this DOCUMENT.
//
// It is never cleared. Clearing it on the way back out — guarding only cycles on
// the current path — let one anchor be re-expanded once per reference, which is
// exponential in nesting depth: ten anchors each naming the previous one ten
// times is 574 bytes of legal YAML and ten billion nodes. The gate did not fail
// on it, it HUNG, and the size limit cannot help because the blowup is in the
// depth rather than in the bytes. This is the billion-laughs shape, and an
// analyzer whose stated purpose is defeating a hostile author must not be
// wedged by one.
//
// Walking each node once per position is also the RIGHT answer for findings: a
// reference written once is one defect, and expanding it per use reported it
// three times for two uses, every copy at the anchor's line rather than at any
// use site.
type visited map[at]bool

// at is one node considered from one position — the key the walk remembers.
type at struct {
	node *yaml.Node
	keys keyOwner
}

// walkAlias follows an alias to the node it names.
func walkAlias(node *yaml.Node, keys keyOwner, seen visited, visit func(*yaml.Node)) {
	if node.Alias == nil {
		return
	}
	walk(node.Alias, keys, seen, visit)
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
// `secrets` and `matrix` are here for the same reason as `with` and `env`: their
// keys are secret names and matrix dimensions the AUTHOR chose, so a `uses`
// among them is an input named uses that GitHub never resolves — a finding
// nobody can act on.
var authored = map[string]bool{"with": true, "env": true, "secrets": true, "matrix": true}

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
	if key == mergeKey {
		// A merge does not descend a level: `<<: *anchor` splices the anchor's
		// keys into THIS mapping, so they are owned by whoever owns this one.
		// Treating `<<` as an ordinary key made the merged mapping a job BODY
		// when it was really a set of job IDs, and the whole-job evasion the
		// positional rule closed was available again through a merge.
		return keys
	}
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

// mergeKey is YAML's merge directive, which splices one mapping into another
// rather than introducing a level of its own.
const mergeKey mappingKey = "<<"

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
