//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kunchenguid/no-mistakes/internal/types"
)

func TestForkRouting(t *testing.T) {
	h := NewHarness(t, SetupOpts{Agent: "claude"})
	ctx := context.Background()

	parentURL := "https://github.com/parent-owner/no-mistakes.git"
	forkURL := "https://github.com/fork-owner/no-mistakes.git"
	branch := "feature/fork-routing-e2e"

	forkDir := filepath.Join(filepath.Dir(h.UpstreamDir), "fork.git")
	if err := os.MkdirAll(forkDir, 0o755); err != nil {
		t.Fatalf("mkdir fork: %v", err)
	}
	if out, err := h.runGit(ctx, forkDir, "init", "--bare", "--initial-branch=main"); err != nil {
		t.Fatalf("init fork: %v\n%s", err, out)
	}
	if out, err := h.runGit(ctx, h.WorkDir, "push", forkDir, "main"); err != nil {
		t.Fatalf("seed fork main: %v\n%s", err, out)
	}

	configureGitURLRewrite(t, h, parentURL, h.UpstreamDir)
	configureGitURLRewrite(t, h, forkURL, forkDir)
	if out, err := h.runGit(ctx, h.WorkDir, "remote", "set-url", "origin", parentURL); err != nil {
		t.Fatalf("set parent origin: %v\n%s", err, out)
	}

	ghLog := filepath.Join(filepath.Dir(h.AgentLog), "gh-fork-routing.log")
	t.Setenv("FAKEAGENT_GH_MODE", "fork-pr")
	t.Setenv("FAKEAGENT_GH_LOG", ghLog)
	t.Setenv("FAKEAGENT_GH_PARENT", "parent-owner/no-mistakes")

	out, err := h.Run("init", "--fork-url", forkURL)
	if err != nil {
		t.Fatalf("init with fork URL: %v\n%s", err, out)
	}

	h.CommitChange(branch, "fork.txt", "fork route\n", "add fork route")
	h.PushToGate(branch)

	run := h.WaitForRun(branch, 90*time.Second)
	if run.Status != types.RunCompleted {
		t.Fatalf("run did not complete: status=%s error=%v", run.Status, deref(run.Error))
	}
	if run.PRURL == nil || !strings.HasPrefix(*run.PRURL, "https://github.com/parent-owner/no-mistakes/pull/") {
		t.Fatalf("PR URL = %v, want parent repository PR URL", run.PRURL)
	}

	forkSHA, err := h.runGit(ctx, forkDir, "rev-parse", "refs/heads/"+branch)
	if err != nil {
		t.Fatalf("fork branch missing: %v\n%s", err, forkSHA)
	}
	if got := string(bytes.TrimSpace(forkSHA)); got != run.HeadSHA {
		t.Fatalf("fork branch SHA = %s, want run head %s", got, run.HeadSHA)
	}
	if out, err := h.runGit(ctx, h.UpstreamDir, "rev-parse", "--verify", "refs/heads/"+branch); err == nil {
		t.Fatalf("parent unexpectedly received feature branch at %s", bytes.TrimSpace(out))
	}

	invocations := readGHStubInvocations(t, ghLog)
	var sawParentCreate bool
	for _, inv := range invocations {
		if len(inv.Args) >= 2 && inv.Args[0] == "pr" && inv.Args[1] == "list" && strings.Contains(inv.Head, ":") {
			t.Fatalf("gh pr list used unsupported owner-qualified head: %+v", inv)
		}
		if len(inv.Args) >= 2 && inv.Args[0] == "pr" && inv.Args[1] == "create" {
			if inv.Repo == "fork-owner/no-mistakes" {
				t.Fatalf("created silent self-PR against fork: %+v", inv)
			}
			if inv.Repo == "parent-owner/no-mistakes" && inv.Head == "fork-owner:"+branch && inv.Base == "main" {
				sawParentCreate = true
			}
		}
	}
	if !sawParentCreate {
		t.Fatalf("did not see parent PR create with fork owner head in gh log: %+v", invocations)
	}
}

// A shared XDG git/config must never receive rewrites or let an earlier
// fixture capture the next fixture's identical forge URL. Changing XDG for
// provider discovery must also leave the fixture's Git config reachable.
func TestHarnessGitURLRewriteIsolation(t *testing.T) {
	ambient := t.TempDir()
	ambientXDG := filepath.Join(ambient, "xdg")
	if err := os.MkdirAll(filepath.Join(ambientXDG, "git"), 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := []byte("[user]\n\tname = ambient sentinel\n")
	ambientConfig := filepath.Join(ambientXDG, "git", "config")
	if err := os.WriteFile(ambientConfig, sentinel, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", ambientXDG)
	t.Setenv("GIT_CONFIG_GLOBAL", ambientConfig)
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "url.file:///missing-ambient-repo.insteadOf")
	t.Setenv("GIT_CONFIG_VALUE_0", "https://github.com/parent-owner/no-mistakes.git")
	t.Setenv("GIT_CONFIG_PARAMETERS", "'protocol.file.allow'='never'")
	t.Setenv("GIT_ALLOW_PROTOCOL", "file")

	for _, name := range []string{"first", "second"} {
		t.Run(name, func(t *testing.T) {
			h := NewHarness(t, SetupOpts{Agent: "claude"})
			ctx := context.Background()
			mainSHA, err := h.runGit(ctx, h.WorkDir, "rev-parse", "refs/heads/main")
			if err != nil {
				t.Fatalf("resolve fixture main: %v\n%s", err, mainSHA)
			}
			upstreamSHA, err := h.runGit(ctx, h.WorkDir, "ls-remote", h.UpstreamDir, "refs/heads/main")
			if err != nil || !strings.HasPrefix(string(upstreamSHA), strings.TrimSpace(string(mainSHA))+"\t") {
				t.Fatalf("fixture upstream main: %v\n%s", err, upstreamSHA)
			}
			const remoteURL = "https://github.com/parent-owner/no-mistakes.git"
			configureGitURLRewrite(t, h, remoteURL, h.UpstreamDir)
			// Gitea selects its provider config after setting up the rewrite.
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(h.HomeDir, "provider-config"))
			remoteSHA, err := h.runGit(ctx, h.WorkDir, "ls-remote", remoteURL, "refs/heads/main")
			if err != nil || string(remoteSHA) != string(upstreamSHA) {
				t.Fatalf("rewritten main: %v\n%s; want %s", err, remoteSHA, upstreamSHA)
			}
		})
	}
	data, err := os.ReadFile(ambientConfig)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, sentinel) {
		t.Fatalf("harness changed ambient Git config:\n%s", data)
	}
}

func configureGitURLRewrite(t *testing.T, h *Harness, rawURL, repoDir string) {
	t.Helper()
	rewrite := pathFileURL(t, repoDir)
	key := fmt.Sprintf("url.%s.insteadOf", rewrite)
	if out, err := h.runGit(context.Background(), h.WorkDir, "config", "--global", key, rawURL); err != nil {
		t.Fatalf("configure git URL rewrite %s to %s: %v\n%s", rawURL, rewrite, err, out)
	}
}

func pathFileURL(t *testing.T, path string) string {
	t.Helper()
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("abs %s: %v", path, err)
	}
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}).String()
}

type ghStubInvocation struct {
	Args []string `json:"args"`
	Repo string   `json:"repo"`
	Head string   `json:"head"`
	Base string   `json:"base"`
	Body string   `json:"body"`
}

func readGHStubInvocations(t *testing.T, path string) []ghStubInvocation {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read gh log: %v", err)
	}
	var invocations []ghStubInvocation
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var inv ghStubInvocation
		if err := json.Unmarshal(line, &inv); err != nil {
			t.Fatalf("parse gh log line: %v\n%s", err, line)
		}
		invocations = append(invocations, inv)
	}
	return invocations
}
