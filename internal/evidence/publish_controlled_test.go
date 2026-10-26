package evidence

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kunchenguid/no-mistakes/internal/factorysandbox"
)

func TestPublish_ControlledScratchPreservesProductIndexAndExistingEvidence(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux capability test")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap not installed")
	}
	remote, work := newRepoWithRemote(t)
	source := writeEvidence(t, t.TempDir(), map[string]string{"old.txt": "earlier evidence\n"})
	ctx := factorysandbox.WithPolicy(context.Background(), source, []string{work, remote})
	first, err := Publish(ctx, baseRequest(remote, work, source))
	if err != nil || first == nil {
		t.Fatalf("initial controlled publication: %v, %v", first, err)
	}

	// Keep distinct staged and unstaged source bytes so replacing the real
	// index with the existing evidence tree cannot masquerade as a clean run.
	product := filepath.Join(work, "README.md")
	if err := os.WriteFile(product, []byte("staged product\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runGit(t, work, "add", "README.md")
	if err := os.WriteFile(product, []byte("unstaged product\n"), 0600); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(work, ".git", "index")
	indexBefore, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	headBefore := runGit(t, work, "rev-parse", "HEAD")
	mainBefore := runGit(t, remote, "rev-parse", "refs/heads/main")
	if err := os.Remove(filepath.Join(source, "old.txt")); err != nil {
		t.Fatal(err)
	}
	writeEvidence(t, source, map[string]string{"new.txt": "fresh evidence\n"})

	result, err := Publish(ctx, baseRequest(remote, work, source))
	if err != nil || result == nil {
		t.Fatalf("publication over existing evidence tree: %v, %v", result, err)
	}
	if result.CommitSHA == first.CommitSHA {
		t.Fatal("new evidence did not produce a new commit")
	}
	if got := runGit(t, remote, "rev-parse", "refs/heads/"+DefaultBranch); got != result.CommitSHA {
		t.Fatalf("remote evidence tip = %s, want %s", got, result.CommitSHA)
	}
	if got := runGit(t, remote, "rev-parse", result.CommitSHA+"^"); got != first.CommitSHA {
		t.Fatalf("evidence parent = %s, want %s", got, first.CommitSHA)
	}
	for file, want := range map[string]string{
		MarkerPath: MarkerContent,
		".no-mistakes/evidence/fm/add-login/old.txt": "earlier evidence\n",
		".no-mistakes/evidence/fm/add-login/new.txt": "fresh evidence\n",
	} {
		if got := runGit(t, remote, "cat-file", "blob", result.CommitSHA+":"+file); got != string(bytes.TrimSpace([]byte(want))) {
			t.Errorf("published %s = %q, want %q", file, got, want)
		}
	}
	indexAfter, err := os.ReadFile(indexPath)
	if err != nil || !bytes.Equal(indexBefore, indexAfter) {
		t.Fatalf("product index changed: %v", err)
	}
	if got := runGit(t, work, "rev-parse", "HEAD"); got != headBefore {
		t.Fatalf("product HEAD changed: %s", got)
	}
	if got := runGit(t, remote, "rev-parse", "refs/heads/main"); got != mainBefore {
		t.Fatalf("remote product branch changed: %s", got)
	}
	if got, err := os.ReadFile(product); err != nil || string(got) != "unstaged product\n" {
		t.Fatalf("product source changed: %q %v", got, err)
	}
	if got := runGit(t, work, "show", ":README.md"); got != "staged product" {
		t.Fatalf("staged source changed: %q", got)
	}
}
