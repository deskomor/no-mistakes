package factorysandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitScratchIndexRejectsUngrantedAndUnsafePaths(t *testing.T) {
	repo := sandboxRepo(t)
	for _, name := range []string{"ungranted", "outside-grant", "protected", "symlink-directory", "symlink-index", "symlink-marker", "hardlink-index", "hardlink-marker"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			index := filepath.Join(dir, "index")
			ctx := WithPolicy(context.Background(), t.TempDir(), []string{repo})
			switch name {
			case "outside-grant":
				index = filepath.Join(t.TempDir(), "index")
			case "protected":
				dir = filepath.Join(repo, ".git")
				index = filepath.Join(dir, "index")
			case "symlink-directory":
				alias := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(dir, alias); err != nil {
					t.Fatal(err)
				}
				dir = alias
				index = filepath.Join(dir, "index")
			case "symlink-index", "symlink-marker", "hardlink-index", "hardlink-marker":
				target := index
				if strings.HasSuffix(name, "marker") {
					target = filepath.Join(dir, "marker")
				}
				var err error
				if strings.HasPrefix(name, "symlink") {
					err = os.Symlink(filepath.Join(repo, "source"), target)
				} else {
					err = os.Link(filepath.Join(repo, "source"), target)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if name != "ungranted" {
				ctx = WithGitScratchIndex(ctx, dir)
			}
			cmd := exec.Command("git", "read-tree", "--empty")
			cmd.Dir = repo
			cmd.Env = []string{"GIT_INDEX_FILE=" + index}
			if cleanup, err := WrapGitCommand(ctx, cmd, []string{"read-tree", "--empty"}); err == nil {
				cleanup()
				t.Fatal("unsafe scratch index accepted")
			} else {
				want := "controlled Git refuses ungranted scratch index"
				switch name {
				case "protected":
					want = "overlaps protected source/Git state"
				case "symlink-directory":
					want = "existing non-symlink path"
				case "symlink-index", "symlink-marker":
					want = "scratch contains symlink"
				case "hardlink-index", "hardlink-marker":
					want = "multiply-linked regular file"
				}
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("scratch refused for unrelated reason: %v; want %q", err, want)
				}
			}
			data, err := os.ReadFile(filepath.Join(repo, "source"))
			if err != nil || string(data) != "original" {
				t.Fatalf("source changed: %q %v", data, err)
			}
		})
	}
}

func TestGitScratchIndexGrantDoesNotChangeLegacyOrAgentCommands(t *testing.T) {
	dir := t.TempDir()
	ctx := WithGitScratchIndex(context.Background(), dir)
	cmd := exec.Command("git", "read-tree", "--empty")
	cmd.Env = []string{"GIT_INDEX_FILE=" + filepath.Join(dir, "index")}
	original := cmd.Path
	cleanup, err := WrapGitCommand(ctx, cmd, []string{"read-tree", "--empty"})
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if cmd.Path != original || len(cmd.Env) != 1 {
		t.Fatal("scratch grant changed an opt-out caller")
	}

	repo := sandboxRepo(t)
	cmd = exec.Command("sh", "-c", `test -z "${GIT_INDEX_FILE-}"; test ! -e "$1"`, "agent", dir)
	cmd.Dir = repo
	cmd.Env = []string{"GIT_INDEX_FILE=" + filepath.Join(dir, "index")}
	cleanup, err = WrapAssessment(cmd, t.TempDir(), []string{repo}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("agent acquired scratch capability: %v %s", err, out)
	}
}
