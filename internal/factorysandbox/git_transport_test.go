package factorysandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestControlledLocalTransportSuppressesReceiverHooks(t *testing.T) {
	source := sandboxRepo(t)
	receiver := t.TempDir()
	destination := sandboxRepo(t)
	run := func(ctx context.Context, dir string, args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = dir
		cleanup, err := WrapGitCommand(ctx, cmd, args)
		if err != nil {
			t.Fatal(err)
		}
		defer cleanup()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	plain := context.Background()
	run(plain, receiver, "init", "--bare")
	run(plain, source, "config", "user.name", "Transport Test")
	run(plain, source, "config", "user.email", "transport@example.invalid")
	run(plain, source, "add", "source")
	run(plain, source, "commit", "-m", "baseline")
	head := run(plain, source, "rev-parse", "HEAD")
	run(plain, source, "remote", "add", "private", receiver)
	marker := filepath.Join(source, "unreserved-server-mutation")
	hook := "#!/bin/sh\nprintf escaped > '" + strings.ReplaceAll(marker, "'", "'\\''") + "'\n"
	if err := os.WriteFile(filepath.Join(receiver, "hooks", "post-receive"), []byte(hook), 0700); err != nil {
		t.Fatal(err)
	}
	controlled := WithPolicy(plain, t.TempDir(), []string{source, receiver, destination})
	run(controlled, source, "push", "private", "HEAD:refs/heads/controlled")
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("controlled receiver hook mutated product: %v", err)
	}
	run(controlled, destination, "fetch", "file://"+receiver, "refs/heads/controlled:refs/heads/fetched")
	if got := run(plain, destination, "rev-parse", "refs/heads/fetched"); got != head {
		t.Fatalf("native transport lost candidate: got %s want %s", got, head)
	}
	for _, remote := range []string{"ssh://example.invalid/repo.git", "https://example.invalid/repo.git"} {
		args := []string{"push", remote, "HEAD"}
		cmd := exec.Command("git", args...)
		cmd.Dir = source
		if cleanup, err := WrapGitCommand(controlled, cmd, args); err == nil {
			cleanup()
			t.Fatalf("non-local controlled transport admitted: %s", remote)
		}
	}
	// A real opt-out push proves the installed receiver hook is executable.
	run(plain, source, "push", "private", "HEAD:refs/heads/legacy")
	if got, err := os.ReadFile(marker); err != nil || string(got) != "escaped" {
		t.Fatalf("legacy receiver hook did not execute: %q %v", got, err)
	}
	refuseConfigured := func() {
		t.Helper()
		args := []string{"push", "private", "HEAD"}
		cmd := exec.Command("git", args...)
		cmd.Dir = source
		if cleanup, err := WrapGitCommand(controlled, cmd, args); err == nil {
			cleanup()
			t.Fatal("unsafe configured local transport admitted")
		}
	}
	run(plain, source, "config", "--add", "remote.private.url", destination)
	refuseConfigured()
	run(plain, source, "config", "--unset-all", "remote.private.url")
	run(plain, source, "config", "remote.private.url", "")
	refuseConfigured()
	run(plain, source, "config", "remote.private.url", receiver)
	run(plain, source, "config", "url.https://example.invalid/.insteadOf", receiver)
	refuseConfigured()
}
