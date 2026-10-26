package factorysandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeCustodyProofsUseBuiltinsAndConstrainWrites(t *testing.T) {
	repo := sandboxRepo(t)
	evidence := t.TempDir()
	run := func(ctx context.Context, args ...string) (string, error) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = repo
		cleanup, err := WrapGitCommand(ctx, cmd, args)
		if err != nil {
			return "", err
		}
		defer cleanup()
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	must := func(ctx context.Context, args ...string) string {
		t.Helper()
		out, err := run(ctx, args...)
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return out
	}
	plain := context.Background()
	must(plain, "config", "user.name", "Custody Test")
	must(plain, "config", "user.email", "custody@example.invalid")
	must(plain, "add", "source")
	must(plain, "commit", "-m", "base")
	base := must(plain, "rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(repo, "left"), []byte("left\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	must(plain, "add", "left")
	must(plain, "commit", "-m", "left")
	left := must(plain, "rev-parse", "HEAD")
	must(plain, "checkout", "--detach", base)
	if err := os.WriteFile(filepath.Join(repo, "right"), []byte("right\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	must(plain, "add", "right")
	must(plain, "commit", "-m", "right")
	right := must(plain, "rev-parse", "HEAD")
	controlled := WithPolicy(plain, evidence, []string{repo})
	if got := must(controlled, "rev-list", "--count", left); got != "2" {
		t.Fatalf("native rev-list = %q, want 2", got)
	}
	// --write-tree creates a new combined tree. Admission must allow Git's
	// own object writes, not treat every custody proof as read-only.
	tree := must(controlled, "merge-tree", "--write-tree", left, right)
	if got := must(controlled, "ls-tree", "--name-only", tree); got != "left\nright\nsource" {
		t.Fatalf("native merge-tree result = %q", got)
	}
	if got := must(controlled, "rev-parse", "HEAD"); got != right {
		t.Fatalf("proof changed HEAD: %s", got)
	}
	host := filepath.Join(t.TempDir(), "host-sentinel")
	must(plain, "config", "alias.custody-proof", "!printf escaped > '"+host+"'")
	if out, err := run(controlled, "custody-proof"); err == nil || !strings.Contains(err.Error(), "unsupported native command") {
		t.Fatalf("configured alias was admitted: %v %s", err, out)
	}
	if _, err := os.Stat(host); !os.IsNotExist(err) {
		t.Fatalf("Git alias executed on host: %v", err)
	}
	baseline := filepath.Join(t.TempDir(), "native-output")
	must(plain, "rev-list", "--output="+baseline, left)
	if _, err := os.Stat(baseline); err != nil {
		t.Fatalf("native rev-list did not exercise its output writer: %v", err)
	}
	output := filepath.Join(repo, "readonly-output")
	if out, err := run(controlled, "rev-list", "--output="+output, left); err == nil {
		t.Fatalf("read-only rev-list wrote source: %s", out)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("read-only rev-list created source file: %v", err)
	}
}
