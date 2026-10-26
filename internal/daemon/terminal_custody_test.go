package daemon

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kunchenguid/no-mistakes/internal/config"
	"github.com/kunchenguid/no-mistakes/internal/custody"
	"github.com/kunchenguid/no-mistakes/internal/db"
	"github.com/kunchenguid/no-mistakes/internal/factorysandbox"
	gitpkg "github.com/kunchenguid/no-mistakes/internal/git"
	"github.com/kunchenguid/no-mistakes/internal/paths"
)

func TestPreserveRunHeadUsesDurableCustodyBeforeGit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("reference-transaction helper uses a POSIX shell")
	}
	for _, controlled := range []bool{false, true} {
		name := "legacy"
		if controlled {
			name = "controlled"
		}
		t.Run(name, func(t *testing.T) {
			if controlled {
				if err := factorysandbox.Supported(); err != nil {
					t.Skip(err)
				}
			}
			p := paths.WithRoot(t.TempDir())
			if err := p.EnsureDirs(); err != nil {
				t.Fatal(err)
			}
			d, err := db.Open(p.DB())
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			source := t.TempDir()
			gitCmd(t, source, "init")
			gitCmd(t, source, "config", "user.email", "test@test.com")
			gitCmd(t, source, "config", "user.name", "Test")
			gitCmd(t, source, "commit", "--allow-empty", "-m", "submitted")
			submitted := gitOutput(t, source, "rev-parse", "HEAD")
			repo, err := d.InsertRepo(source, "https://example.com/terminal.git", "main")
			if err != nil {
				t.Fatal(err)
			}
			run, err := d.InsertRunWithIntentAndLaunchNonce(repo.ID, "feature/terminal", submitted, submitted, nil, "nonce", "generation", "digest", "", false, nil)
			if err != nil {
				t.Fatal(err)
			}
			if controlled {
				if err := d.EnsureFactoryBudget(run); err != nil {
					t.Fatal(err)
				}
			}
			gate := p.RepoDir(repo.ID)
			gitCmd(t, "", "init", "--bare", gate)
			gitCmd(t, source, "push", gate, "HEAD:refs/heads/feature/terminal")
			work := p.WorktreeDir(repo.ID, run.ID)
			if err := gitpkg.WorktreeAdd(context.Background(), gate, work, submitted); err != nil {
				t.Fatal(err)
			}
			gitCmd(t, work, "config", "user.email", "test@test.com")
			gitCmd(t, work, "config", "user.name", "Test")
			gitCmd(t, work, "commit", "--allow-empty", "-m", "unpublished repair")
			repair := gitOutput(t, work, "rev-parse", "HEAD")
			hooks := t.TempDir()
			hostMarker := filepath.Join(t.TempDir(), "host-hook")
			workMarker := filepath.Join(work, "work-hook")
			script := "#!/bin/sh\nprintf attacked > '" + hostMarker + "'\nprintf attacked > '" + workMarker + "'\nexit 0\n"
			if err := os.WriteFile(filepath.Join(hooks, "reference-transaction"), []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			gitCmd(t, work, "config", "core.hooksPath", hooks)
			// The switch is off: enrollment, not current config, owns custody.
			head, verified := preserveRunHead(d, p, &config.Config{ControlledExecution: false}, work, run)
			if !verified || head != repair {
				t.Fatalf("preserved head=%q verified=%v, want %s", head, verified, repair)
			}
			stored, err := d.GetRun(run.ID)
			if err != nil || stored.HeadSHA != repair || stored.TerminalHeadVerifiedAt == nil {
				t.Fatalf("terminal evidence=%+v error=%v", stored, err)
			}
			if got := gitOutput(t, gate, "rev-parse", custody.RecoveryRef(run.ID)); got != repair {
				t.Fatalf("anchor=%s, want %s", got, repair)
			}
			if got := gitOutput(t, gate, "rev-parse", "refs/heads/feature/terminal"); got != submitted {
				t.Fatalf("preservation moved gate branch to %s", got)
			}
			for _, marker := range []string{hostMarker, workMarker} {
				_, err := os.Stat(marker)
				if controlled && !os.IsNotExist(err) || !controlled && err != nil {
					t.Fatalf("controlled=%v hook side effect %s: %v", controlled, marker, err)
				}
			}
		})
	}
}
