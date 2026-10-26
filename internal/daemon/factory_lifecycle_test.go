package daemon

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kunchenguid/no-mistakes/internal/db"
	"github.com/kunchenguid/no-mistakes/internal/factorysandbox"
	"github.com/kunchenguid/no-mistakes/internal/git"
	"github.com/kunchenguid/no-mistakes/internal/pipeline"
)

func TestLifecycleStartupSuppressesPlantedCheckoutHook(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("executable hook uses POSIX shell")
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
			t.Setenv("NM_DEMO", "1")
			p, d := newRefreshRunFixture(t)
			repo, head := setupTestGitRepo(t, p, d, "native-startup")
			if controlled {
				if err := os.WriteFile(p.ConfigFile(), []byte("controlled_execution: true\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			gate := p.RepoDir(repo.ID)
			hooks := filepath.Join(gate, "hooks")
			hostMarker := filepath.Join(t.TempDir(), "host-hook")
			gateMarker := filepath.Join(gate, "gate-hook")
			script := "#!/bin/sh\nprintf attacked > '" + hostMarker + "'\nprintf attacked > '" + gateMarker + "'\n"
			if err := os.WriteFile(filepath.Join(hooks, "post-checkout"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			gitCmd(t, gate, "config", "core.hooksPath", hooks)
			m := NewRunManager(d, p, func() []pipeline.Step { return nil })
			t.Cleanup(m.Shutdown)
			runID, err := m.startRunWithIntentSourceLocked(context.Background(), repo, "main", head, head, "test", nil, "native startup boundary", db.RunIntentSourceAgent, "native-nonce", "native-generation", "digest", "", false, "", "")
			if err != nil {
				t.Fatalf("native startup failed before pipeline launch: %v", err)
			}
			waitForRunTerminalState(t, d, runID)
			for _, marker := range []string{hostMarker, gateMarker} {
				_, err := os.Stat(marker)
				if controlled && !os.IsNotExist(err) || !controlled && err != nil {
					t.Fatalf("controlled=%v checkout hook marker %s: %v", controlled, marker, err)
				}
			}
		})
	}
}

func TestLifecycleRejectsUnboundLaunchBeforeNativeCheckout(t *testing.T) {
	if err := factorysandbox.Supported(); err != nil {
		t.Skip(err)
	}
	p, d := newRefreshRunFixture(t)
	repo, head := setupTestGitRepo(t, p, d, "native-unbound")
	if err := os.WriteFile(p.ConfigFile(), []byte("controlled_execution: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m := NewRunManager(d, p, nil)
	_, err := m.startRun(context.Background(), repo, "main", head, head, "test", nil, "unbound", "", false, "")
	if err == nil || !strings.Contains(err.Error(), "strict launch") {
		t.Fatalf("unbound launch error: %v", err)
	}
	runs, err := d.GetRunsByRepo(repo.ID)
	if err != nil || len(runs) != 0 {
		t.Fatalf("unbound launch created rows: %v, %v", runs, err)
	}
	if entries, err := os.ReadDir(p.WorktreeDir(repo.ID, "")); err == nil && len(entries) != 0 {
		t.Fatalf("unbound launch created checkout entries: %v", entries)
	}
}

func TestLifecycleCleanupRetainsUnknownAndRejectsExecutableConfig(t *testing.T) {
	if err := factorysandbox.Supported(); err != nil {
		t.Skip(err)
	}
	p, d := newRefreshRunFixture(t)
	repo, head := setupTestGitRepo(t, p, d, "native-cleanup")
	run, err := d.InsertRunWithIntentAndLaunchNonce(repo.ID, "main", head, head, nil, "nonce", "generation", "digest", "", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureFactoryBudget(run); err != nil {
		t.Fatal(err)
	}
	gate := p.RepoDir(repo.ID)
	work := p.WorktreeDir(repo.ID, run.ID)
	if err := git.WorktreeAdd(context.Background(), gate, work, head); err != nil {
		t.Fatal(err)
	}
	if err := d.SetRunWorktreeDir(run.ID, work); err != nil {
		t.Fatal(err)
	}
	m := NewRunManager(d, p, nil)
	// Global mode is off; durable enrollment still protects native cleanup.
	unknown := filepath.Join(t.TempDir(), "unowned")
	if err := os.Mkdir(unknown, 0700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(unknown, "keep")
	if err := os.WriteFile(keep, []byte("unowned"), 0600); err != nil {
		t.Fatal(err)
	}
	m.removeRunWorktree(repo.ID, run.ID, gate, unknown, "test-unowned")
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("cleanup removed unowned path: %v", err)
	}
	marker := filepath.Join(t.TempDir(), "transport-ran")
	helper := filepath.Join(t.TempDir(), "upload-pack")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf attacked > '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, gate, "config", "remote.origin.uploadpack", helper)
	m.removeRunWorktree(repo.ID, run.ID, gate, work, "test-executable-config")
	if _, err := os.Stat(filepath.Join(work, "test.txt")); err != nil {
		t.Fatalf("cleanup did not fail closed for executable transport config: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("planted executable ran: %v", err)
	}
	gitCmd(t, gate, "config", "--unset", "remote.origin.uploadpack")
	m.removeRunWorktree(repo.ID, run.ID, gate, work, "test-cleanup")
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Fatalf("owned worktree was not removed: %v", err)
	}
}

func TestLifecycleRecoveryUsesDurablePolicyForTrustedFetch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("transport helper uses POSIX shell")
	}
	for _, controlled := range []bool{false, true} {
		name := "legacy"
		if controlled {
			name = "enrolled-switch-off"
		}
		t.Run(name, func(t *testing.T) {
			if controlled {
				if err := factorysandbox.Supported(); err != nil {
					t.Skip(err)
				}
			}
			p, d := newRefreshRunFixture(t)
			repo, head := setupTestGitRepo(t, p, d, "native-recovery")
			gate := p.RepoDir(repo.ID)
			mirror := filepath.Join(t.TempDir(), "private.git")
			gitCmd(t, "", "clone", "--bare", gate, mirror)
			var err error
			repo, err = d.ReplaceRepoURLs(repo.ID, mirror, "")
			if err != nil {
				t.Fatal(err)
			}
			gitCmd(t, gate, "remote", "set-url", "origin", mirror)
			run, err := d.InsertRunWithIntentAndLaunchNonce(repo.ID, "main", head, head, nil, "nonce", "generation", "digest", "", false, nil)
			if err != nil {
				t.Fatal(err)
			}
			if controlled {
				if err := d.EnsureFactoryBudget(run); err != nil {
					t.Fatal(err)
				}
			}
			work := p.WorktreeDir(repo.ID, run.ID)
			if err := git.WorktreeAdd(context.Background(), gate, work, head); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(t.TempDir(), "transport-ran")
			helper := filepath.Join(t.TempDir(), "upload-pack")
			script := "#!/bin/sh\nprintf attacked > '" + marker + "'\nexec git upload-pack \"$@\"\n"
			if err := os.WriteFile(helper, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			gitCmd(t, gate, "config", "remote.origin.uploadpack", helper)
			m := NewRunManager(d, p, nil)
			_, err = m.loadRecoveredConfig(context.Background(), run, repo, work)
			if controlled && err == nil || !controlled && err != nil {
				t.Fatalf("controlled=%v trusted recovery fetch error: %v", controlled, err)
			}
			_, markerErr := os.Stat(marker)
			if controlled && !os.IsNotExist(markerErr) || !controlled && markerErr != nil {
				t.Fatalf("controlled=%v transport side effect: %v", controlled, markerErr)
			}
			// Once the planted executable setting is removed, the exact
			// registered private origin remains available in the boundary.
			gitCmd(t, gate, "config", "--unset", "remote.origin.uploadpack")
			if _, err := m.loadRecoveredConfig(context.Background(), run, repo, work); err != nil {
				t.Fatalf("safe private-origin recovery fetch: %v", err)
			}
		})
	}
}
