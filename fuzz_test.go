package wfpolicy_test

import (
	"errors"
	"strings"
	"testing"

	goyze "github.com/gomatic/go-yze"

	wfpolicy "github.com/gomatic/yze-yml-wfpolicy"
)

// FuzzDiagnostics drives arbitrary text through the YAML parser and the pin
// model. The contract under fuzz, asserted on every input rather than merely
// exercised:
//
//   - Diagnostics never panics, however malformed the document.
//   - It returns either diagnostics or an error wrapping ErrParse, never both.
//   - Every diagnostic carries this rule's identity and a navigable 1-based
//     position.
//   - A finding is reported ONLY for a value naming a denylisted branch, which
//     is the property that keeps the rule free of guesses: if the message names
//     a ref, that ref really is in the denylist and really is in the source.
//
// The seed corpus is the edge matrix: empty and comment-only documents, every
// fixed-ref form, each denylisted branch, non-scalar and missing values,
// anchors and aliases, multi-document files, and text that is not YAML.
func FuzzDiagnostics(f *testing.F) {
	for _, seed := range []string{
		"",
		"\n",
		"# comment\n",
		"jobs:\n  b:\n    steps:\n      - uses: o/a@v1\n",
		"jobs:\n  b:\n    steps:\n      - uses: o/a@main\n",
		"jobs:\n  b:\n    steps:\n      - uses: o/a@master\n",
		"jobs:\n  b:\n    steps:\n      - uses: ./local\n",
		"jobs:\n  b:\n    steps:\n      - uses: docker://alpine:3\n",
		"jobs:\n  b:\n    steps:\n      - uses:\n",
		"jobs:\n  b:\n    steps:\n      - uses: []\n",
		"uses: o/a@main\n",
		"a: &x {uses: o/a@main}\nb: *x\n",
		"---\nuses: o/a@main\n---\nuses: o/a@dev\n",
		"jobs:\n  - [unclosed\n",
		"uses: o/a@main@extra\n",
		"uses: '@main'\n",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, source string) {
		diags, err := wfpolicy.Diagnostics("fuzz.yml", wfpolicy.Source(source))
		if err != nil {
			if !errors.Is(err, wfpolicy.ErrParse) {
				t.Fatalf("a failure must identify itself as a parse failure, got %v", err)
			}
			if diags != nil {
				t.Fatalf("a parse failure reports no diagnostics, got %d", len(diags))
			}
			return
		}

		for _, d := range diags {
			if d.Rule != wfpolicy.Rule || d.Tool != "yze" {
				t.Fatalf("diagnostic must carry this rule's identity, got %q/%q", d.Tool, d.Rule)
			}
			if d.Line < 1 || d.Col < 1 {
				t.Fatalf("diagnostic must be navigable, got line %d col %d", d.Line, d.Col)
			}
			if d.Severity != goyze.SeverityError {
				t.Fatalf("every finding here is an error, got %q", d.Severity)
			}
			ref, ok := reported(d.Message)
			if !ok {
				t.Fatalf("a finding must name the branch it objects to: %s", d.Message)
			}
			if !strings.Contains(source, ref) {
				t.Fatalf("a finding named %q, which is not in the source", ref)
			}
		}
	})
}

// reported is the ref a finding names, read back out of its message.
func reported(message string) (string, bool) {
	_, rest, found := strings.Cut(message, `resolves "`)
	if !found {
		return "", false
	}
	ref, _, found := strings.Cut(rest, `"`)
	return ref, found
}
