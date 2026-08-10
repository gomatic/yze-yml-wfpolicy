package wfpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

// TestFollowNeverDereferencesAnAbsentAlias pins the defensive arm of alias
// resolution. The parser never produces an alias whose target is absent, so
// only a hand-built node reaches this path; standing on that assumption would
// trade a finding for a panic on input this package does not control. The
// alias's own value is the ANCHOR'S NAME, so yielding the node unchanged must
// still name no action — reporting "anchor" as a reference would be an
// invented finding.
func TestFollowNeverDereferencesAnAbsentAlias(t *testing.T) {
	t.Parallel()

	orphan := &yaml.Node{Kind: yaml.AliasNode, Value: "anchor"}

	assert.Same(t, orphan, follow(orphan))
	assert.Empty(t, reference(orphan))
}
