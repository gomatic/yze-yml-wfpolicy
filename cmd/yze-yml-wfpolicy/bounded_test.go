package main

// What this command refuses to read, and what it refuses to lose. Both answers
// were wrong here and right in both siblings: there was no size bound at all, so
// a 2 GB file reached 4.3 GB resident by either entry point; and one unreadable
// file or directory aborted the run and returned an empty report, which is the
// one result indistinguishable from a clean pass.

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	goyze "github.com/gomatic/go-yze"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	wfpolicy "github.com/gomatic/yze-yml-wfpolicy"
)

// TestReadFileBoundsEveryPathItReads names readFile and the claim it makes: the
// bound is at the ONE place every path is read, so the walk and a named argument
// cannot disagree about it. Guarding one entry point and not the other is not a
// bound, and this analyzer guarded neither while both its siblings guarded both.
func TestReadFileBoundsEveryPathItReads(t *testing.T) {
	dir := t.TempDir()
	huge := writeWorkflow(t, dir, ".github/workflows/huge.yml", "")
	require.NoError(t, os.Truncate(huge, int64(wfpolicy.SizeLimit)+1))
	small := writeWorkflow(t, dir, ".github/workflows/ci.yml", pinned)

	_, err := readFile(huge)
	assert.ErrorIs(t, err, goyze.ErrTooLarge, "over the limit is refused")

	data, err := readFile(small)
	require.NoError(t, err, "an ordinary workflow is read")
	assert.NotEmpty(t, data)
}

// TestRunRefusesAFileTooLargeToBeAWorkflow pins the bound this analyzer had none
// of while both its siblings did: a 2 GB file reached 4.3 GB resident by BOTH
// entry points. The file is still REPORTED — a workflow too large to read is
// exactly where an unchecked pin hides.
func TestRunRefusesAFileTooLargeToBeAWorkflow(t *testing.T) {
	dir := t.TempDir()
	huge := writeWorkflow(t, dir, ".github/workflows/huge.yml", "")
	require.NoError(t, os.Truncate(huge, int64(wfpolicy.SizeLimit)+1))

	for name, args := range map[string][]string{"walked": {dir}, "named": {huge}} {
		buf := swapStdout(t)
		require.Equal(t, 0, run(args), name)
		assert.Contains(t, buf.String(), "huge.yml", "%s: reported, not dropped", name)
		assert.Contains(t, buf.String(), "too large", name)
	}
}

// TestRunContainsATreeItCannotEnter pins the other half of walk failure, and it
// is the opposite answer from the one this command used to give. An entry the
// walk could not stat aborted the run and emptied the report, so ONE unreadable
// directory cost every other file its findings — while the sibling analyzer
// contained it and reported the tree. A gate that reports nothing is
// indistinguishable from a clean one.
func TestRunContainsATreeItCannotEnter(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, ".github/workflows/ci.yml", pinned)
	locked := filepath.Join(dir, "locked")
	require.NoError(t, os.Mkdir(locked, 0o750))
	original := files.WalkDir
	files.WalkDir = deniedTree(locked)
	t.Cleanup(func() { files.WalkDir = original })
	buf := swapStdout(t)

	require.Equal(t, 0, run([]string{dir}), "one unreadable tree is not the run's failure")
	out := buf.String()
	assert.Contains(t, out, "locked", "the tree is reported rather than passed over")
	assert.Contains(t, out, "a ref that moves", "and every other file keeps its findings")
}

// TestRunContainsAFileItCannotRead pins the same containment one level down. A
// file the gate cannot open used to abort the run; now it is one finding against
// that file, and its neighbours keep theirs.
func TestRunContainsAFileItCannotRead(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, ".github/workflows/ci.yml", pinned)
	locked := writeWorkflow(t, dir, ".github/workflows/locked.yml", pinned)
	original := files.Open
	files.Open = func(path string) (io.ReadCloser, error) {
		if path == locked {
			return nil, os.ErrPermission
		}
		return original(path)
	}
	t.Cleanup(func() { files.Open = original })
	buf := swapStdout(t)

	require.Equal(t, 0, run([]string{dir}))
	out := buf.String()
	assert.Contains(t, out, "cannot read workflow file")
	assert.Contains(t, out, "a ref that moves", "the readable file keeps its findings")
}

// deniedTree walks for real but reports one path as unreadable.
//
// The failure is injected through the SEAM rather than with chmod, because a
// test that removes read permission does not test what it says on a machine
// whose user ignores permissions: the gate's own CI container runs as ROOT,
// where `chmod 000` denies nothing, so such a test passes locally and fails
// there — the premise, not the code. The seam states the condition directly and
// holds for every user.
func deniedTree(at string) func(string, fs.WalkDirFunc) error {
	return func(root string, walk fs.WalkDirFunc) error {
		return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if path == at {
				return walk(path, entry, os.ErrPermission)
			}
			return walk(path, entry, err)
		})
	}
}
