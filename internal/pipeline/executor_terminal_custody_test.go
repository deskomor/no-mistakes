package pipeline

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kunchenguid/no-mistakes/internal/config"
	"github.com/kunchenguid/no-mistakes/internal/custody"
	"github.com/kunchenguid/no-mistakes/internal/factorysandbox"
	"github.com/kunchenguid/no-mistakes/internal/git"
	"github.com/kunchenguid/no-mistakes/internal/types"
)

func TestTerminalRunHeadPreservesCustodyAcrossFreshContext(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("reference-transaction helper uses a POSIX shell")
	}
	for _, controlled := range []bool{false, true} {
		for _, terminal := range []string{"abort", "complete"} {
			name := "legacy/" + terminal
			if controlled {
				name = "controlled/" + terminal
			}
			t.Run(name, func(t *testing.T) {
				if controlled {
					if err := factorysandbox.Supported(); err != nil {
						t.Skip(err)
					}
				}
				database, p, _, _ := setupTest(t)
				source := t.TempDir()
				initGitRepo(t, source)
				submitted, err := git.HeadSHA(context.Background(), source)
				if err != nil {
					t.Fatal(err)
				}
				repo, err := database.InsertRepo(source, "https://example.com/terminal.git", "main")
				if err != nil {
					t.Fatal(err)
				}
				run, err := database.InsertRunWithIntentAndLaunchNonce(repo.ID, "terminal", submitted, submitted, nil, "nonce", "generation", "digest", "", false, nil)
				if err != nil {
					t.Fatal(err)
				}
				if controlled {
					if err := database.EnsureFactoryBudget(run); err != nil {
						t.Fatal(err)
					}
				}
				gate := p.RepoDir(repo.ID)
				execGit(t, source, "init", "--bare", gate)
				execGit(t, source, "push", gate, "HEAD:refs/heads/terminal")
				work := p.WorktreeDir(repo.ID, run.ID)
				if err := git.WorktreeAdd(context.Background(), gate, work, submitted); err != nil {
					t.Fatal(err)
				}
				execGit(t, work, "config", "user.email", "test@test.com")
				execGit(t, work, "config", "user.name", "Test")
				execGit(t, work, "commit", "--allow-empty", "-m", "unpublished repair")
				repair, err := git.HeadSHA(context.Background(), work)
				if err != nil {
					t.Fatal(err)
				}
				hostMarker := filepath.Join(t.TempDir(), "host-hook")
				workMarker := filepath.Join(work, "work-hook")
				hooks := t.TempDir()
				script := "#!/bin/sh\nprintf attacked > '" + hostMarker + "'\nprintf attacked > '" + workMarker + "'\nexit 0\n"
				if err := os.WriteFile(filepath.Join(hooks, "reference-transaction"), []byte(script), 0o700); err != nil {
					t.Fatal(err)
				}
				execGit(t, work, "config", "core.hooksPath", hooks)
				// Neither the live toggle nor an executor binding supplies custody here.
				e := NewExecutor(database, p, &config.Config{ControlledExecution: false}, nil, nil, nil)
				e.workDir = work
				wantStatus := types.RunCompleted
				if terminal == "abort" {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					_ = e.failRun(run, repo, errors.New(types.RunCancelReasonAbortedByUser), ctx)
					wantStatus = types.RunCancelled
				} else if err := e.completeRun(run, repo); err != nil {
					t.Fatal(err)
				}
				stored, err := database.GetRun(run.ID)
				if err != nil || stored.Status != wantStatus || stored.HeadSHA != repair || stored.TerminalHeadVerifiedAt == nil {
					t.Fatalf("terminal head not preserved: run=%+v error=%v", stored, err)
				}
				anchor, err := git.Run(context.Background(), work, "rev-parse", custody.RecoveryRef(run.ID))
				if err != nil || anchor != repair {
					t.Fatalf("recovery anchor=%q error=%v, want %s", anchor, err, repair)
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
}
