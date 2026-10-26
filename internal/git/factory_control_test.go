package git

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kunchenguid/no-mistakes/internal/factorysandbox"
)

func TestFactoryParentGitDisablesExecutableConfig(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("controlled execution requires Linux bubblewrap")
	}
	if err := factorysandbox.Supported(); err != nil {
		t.Skip(err)
	}
	ctx := context.Background()
	repo, evidence, host := t.TempDir(), t.TempDir(), t.TempDir()
	run := func(ctx context.Context, args ...string) string {
		t.Helper()
		out, err := Run(ctx, repo, args...)
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return out
	}
	run(ctx, "init")
	run(ctx, "config", "user.name", "Factory Test")
	run(ctx, "config", "user.email", "factory@example.invalid")
	file := filepath.Join(repo, "product.txt")
	if err := os.WriteFile(file, []byte("original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	run(ctx, "add", ".")
	run(ctx, "commit", "-m", "initial")
	hostSentinel := filepath.Join(host, "host-write")
	sourceSentinel := filepath.Join(repo, "unreserved-write")
	helper := filepath.Join(repo, "helper.sh")
	// One helper attacks both the outer host and the managed writable source.
	// Disabling executable extensions matters even inside a mutation sandbox.
	script := "#!/bin/sh\nprintf attacked > '" + hostSentinel + "'\nprintf attacked > '" + sourceSentinel + "'\ncat\n"
	if err := os.WriteFile(helper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	run(ctx, "config", "core.fsmonitor", helper)
	run(ctx, "config", "filter.attack.clean", helper)
	run(ctx, "config", "filter.attack.required", "true")
	if err := os.WriteFile(filepath.Join(repo, ".gitattributes"), []byte("product.txt filter=attack\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("updated\n"), 0600); err != nil {
		t.Fatal(err)
	}
	controlled := factorysandbox.WithPolicy(ctx, evidence, []string{repo})
	index := filepath.Join(repo, ".git", "index")
	before, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	run(controlled, "status", "--porcelain")
	after, err := os.ReadFile(index)
	if err != nil || string(before) != string(after) {
		t.Fatalf("read-only status changed index: %v", err)
	}
	run(controlled, "add", "product.txt", ".gitattributes")
	run(controlled, "commit", "-m", "native integration")
	if got := run(controlled, "show", "HEAD:product.txt"); got != "updated" {
		t.Fatalf("clean native Git stored %q", got)
	}
	for _, path := range []string{hostSentinel, sourceSentinel} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("configured helper escaped through parent Git: %s (%v)", path, err)
		}
	}
	// Legacy Git remains deliberately untouched, including local fsmonitor.
	run(ctx, "status", "--porcelain")
	for _, path := range []string{hostSentinel, sourceSentinel} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("opt-out Git no longer executes configured helper: %v", err)
		}
	}
}

func TestFactoryParentGitReadOnlyBoundaryDeniesDiffOutput(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("controlled execution requires Linux bubblewrap")
	}
	if err := factorysandbox.Supported(); err != nil {
		t.Skip(err)
	}
	repo := t.TempDir()
	ctx := context.Background()
	if _, err := Run(ctx, repo, "init"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "file"), []byte("content"), 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(repo, "unreserved-diff")
	ctx = factorysandbox.WithPolicy(ctx, t.TempDir(), []string{repo})
	if _, err := Run(ctx, repo, "diff", "--no-index", "--output="+target, "/dev/null", filepath.Join(repo, "file")); err == nil {
		t.Fatal("read-only Git unexpectedly wrote its output into source")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("read-only Git created source file: %v", err)
	}
}
