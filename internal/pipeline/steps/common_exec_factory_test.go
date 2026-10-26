package steps

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kunchenguid/no-mistakes/internal/factorysandbox"
	"github.com/kunchenguid/no-mistakes/internal/pipeline"
	"github.com/kunchenguid/no-mistakes/internal/testgit"
)

func TestStepGitRunRawControlsExecutableExtensions(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("controlled execution requires Linux bubblewrap")
	}
	realGit, err := testgit.RealGit()
	if err != nil {
		t.Skip("git not available")
	}
	for _, extension := range []string{"hook", "fsmonitor", "filter"} {
		for _, controlled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/controlled=%t", extension, controlled), func(t *testing.T) {
				if controlled {
					if _, err := exec.LookPath("bwrap"); err != nil {
						t.Skip("bubblewrap not installed")
					}
				}
				repo := t.TempDir()
				host := filepath.Join(t.TempDir(), "host-config")
				source := filepath.Join(repo, "source")
				for _, path := range []string{host, source} {
					if err := os.WriteFile(path, []byte("original\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				env := []string{
					"PATH=" + filepath.Dir(realGit) + string(os.PathListSeparator) + "/bin",
					"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
					"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
					"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
				}
				setupGit := func(args ...string) {
					t.Helper()
					cmd := exec.Command(realGit, args...)
					cmd.Dir, cmd.Env = repo, mergeEnv(env)
					if out, err := cmd.CombinedOutput(); err != nil {
						t.Fatalf("fixture git %v: %v\n%s", args, err, out)
					}
				}
				setupGit("init", "-q")
				setupGit("config", "commit.gpgSign", "false")
				setupGit("add", "source")
				setupGit("commit", "-qm", "initial")
				helper := filepath.Join(repo, "malicious-helper")
				script := fmt.Sprintf("#!/bin/sh\nprintf 'altered\\n' > %q\nprintf 'altered\\n' > %q\n", source, host)
				args := []string{"status", "--porcelain", "-z"}
				switch extension {
				case "hook":
					helper = filepath.Join(repo, ".git", "hooks", "post-commit")
					args = []string{"commit", "--allow-empty", "-m", "native commit"}
				case "fsmonitor":
					setupGit("config", "core.fsmonitor", helper)
					script += "printf 'token\\000/\\000'\n"
				case "filter":
					setupGit("config", "filter.host.clean", helper)
					setupGit("config", "filter.host.required", "true")
					if err := os.WriteFile(filepath.Join(repo, ".gitattributes"), []byte("payload filter=host\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(repo, "payload"), []byte("payload\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					script += "cat\n"
					args = []string{"add", "payload"}
				}
				if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
					t.Fatal(err)
				}
				ctx := context.Background()
				if controlled {
					ctx = factorysandbox.WithPolicy(ctx, t.TempDir(), []string{repo})
				}
				sctx := &pipeline.StepContext{Ctx: ctx, WorkDir: repo, Env: env}
				if _, err := stepGitRunRaw(sctx, args...); err != nil {
					t.Fatalf("step Git %v: %v", args, err)
				}
				want := "altered\n"
				if controlled {
					want = "original\n"
				}
				for _, path := range []string{source, host} {
					got, err := os.ReadFile(path)
					if err != nil || string(got) != want {
						t.Fatalf("helper mutation at %s: got %q, err %v; want %q", path, got, err, want)
					}
				}
			})
		}
	}
}
