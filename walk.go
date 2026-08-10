package wfpolicy

// Finding the action references in a document. The KEY is looked for rather
// than the path to it, because a workflow spells `uses` in a step, a
// reusable-workflow job and a composite action's step — and enumerating those
// paths would silently miss whichever shape GitHub adds next. The exception is
// a key the AUTHOR named rather than GitHub, under which nothing is a schema
// field at all.

import "gopkg.in/yaml.v3"

// walk visits the value of every `uses:` key in the document, at any depth. The
// key is looked for rather than the path to it, because a workflow spells
// `uses` in three places — a step, a reusable-workflow job, and a composite
// action's step — and enumerating those paths would silently miss whichever
// shape GitHub adds next.
func walk(node *yaml.Node, visit func(*yaml.Node)) {
	switch node.Kind {
	case yaml.MappingNode:
		// A mapping walks its own children, so that the values of author-named
		// keys can be skipped rather than descended into.
		visitMapping(node, visit)
		return
	case yaml.DocumentNode, yaml.SequenceNode, yaml.ScalarNode, yaml.AliasNode:
		// Only a mapping holds keys, so only a mapping can hold a `uses:` key.
	}
	for _, child := range node.Content {
		walk(child, visit)
	}
}

// visitMapping reports the `uses` values of one mapping's key/value pairs.
// YAML stores a mapping as a flat alternating list, so the step of two is what
// keeps keys and values from swapping places.
func visitMapping(node *yaml.Node, visit func(*yaml.Node)) {
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := follow(node.Content[i]), node.Content[i+1]
		if authored[key.Value] {
			// `with:` and `env:` hold keys the AUTHOR chose, so a `uses` there
			// is an input named uses, not an action reference — GitHub never
			// resolves it, and reporting one is a finding nobody can act on.
			continue
		}
		if key.Value == usesKey {
			visit(value)
		}
		walk(value, visit)
	}
}

// authored are the workflow keys whose CHILD keys are named by the author
// rather than by GitHub. Nothing inside them is a schema field.
var authored = map[string]bool{"with": true, "env": true}
