package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kunchenguid/no-mistakes/internal/config"
	"github.com/kunchenguid/no-mistakes/internal/db"
	"github.com/kunchenguid/no-mistakes/internal/factorysandbox"
	"github.com/kunchenguid/no-mistakes/internal/git"
	"github.com/kunchenguid/no-mistakes/internal/paths"
	"github.com/kunchenguid/no-mistakes/internal/worktrees"
)

func validateLifecycleLaunch(branch, nonce, generation string) error {
	if branch == "" || nonce == "" || generation == "" {
		return fmt.Errorf("controlled execution requires a strict launch nonce and validation generation")
	}
	if err := validateLaunchNonce(nonce); err != nil {
		return err
	}
	return validateValidationGeneration(generation)
}

func createLifecycleWorktreeDestination(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return fmt.Errorf("controlled worktree destination must be absolute and clean")
	}
	// Resolve the existing ancestor before creating anything; MkdirAll must
	// not follow a planted parent symlink outside the recorded placement.
	for parent := filepath.Dir(dir); ; parent = filepath.Dir(parent) {
		real, err := filepath.EvalSymlinks(parent)
		if err == nil {
			if real != parent {
				return fmt.Errorf("controlled worktree destination has a symlink-routed parent")
			}
			break
		}
		if !os.IsNotExist(err) || filepath.Dir(parent) == parent {
			return fmt.Errorf("resolve controlled worktree destination: %w", err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return fmt.Errorf("create owned worktree destination: %w", err)
	}
	return nil
}

// Enrollment protects repository metadata even after the global switch is off.
func lifecycleGitContext(ctx context.Context, d *db.DB, p *paths.Paths, enabled bool, evidenceRoot *string, repo *db.Repo, runID string, workDir string) (context.Context, bool, error) {
	if repo == nil {
		return ctx, false, fmt.Errorf("controlled lifecycle repository is missing")
	}
	enrolled, err := d.FactoryControlledRepoRunID(repo.ID)
	if err != nil {
		return ctx, false, err
	}
	controlled := enrolled != "" || enabled
	if !controlled {
		return ctx, false, nil
	}
	if err := factorysandbox.Supported(); err != nil {
		return ctx, true, err
	}
	roots := []string{p.RepoDir(repo.ID), repo.WorkingPath}
	if workDir != "" {
		roots = append(roots, workDir)
	}
	roots, err = factorysandbox.IncludeLocalMirrors(roots, repo.UpstreamURL, repo.ForkURL)
	if err != nil {
		return ctx, true, err
	}
	evidence := ""
	if runID != "" {
		configured := ""
		if evidenceRoot != nil {
			configured = *evidenceRoot
		}
		evidence = p.RunEvidenceDir(configured, runID)
	}
	// Before enrollment there is no shared writable lifecycle directory.
	// WrapGitCommand supplies exclusively owned per-command scratch itself.
	return factorysandbox.WithPolicy(ctx, evidence, roots), true, nil
}

// Gate migration has two host-side atomic file writers in addition to Git.
// Their directory parents must not have been redirected by an admitted repair.
func validateLifecycleGateHostWrites(gate string) error {
	real, err := filepath.EvalSymlinks(gate)
	if err != nil || real != filepath.Clean(gate) {
		return fmt.Errorf("controlled gate path is missing or symlink-routed")
	}
	hooks := filepath.Join(gate, "hooks")
	info, err := os.Lstat(hooks)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("controlled gate hooks directory is not owned")
	}
	return nil
}

// Validate both sides of the linked-worktree registration without running Git.
// A recorded path alone is not authority to recursively delete arbitrary files.
func validateLifecycleWorktree(p *paths.Paths, repo *db.Repo, run *db.Run, dir string) error {
	if repo == nil || run == nil || run.RepoID != repo.ID || !samePath(dir, worktrees.RecordedDir(p, run.WorktreePath(), repo.ID, run.ID)) {
		return fmt.Errorf("worktree has no matching durable owner")
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil || real != filepath.Clean(dir) {
		return fmt.Errorf("worktree path is missing or symlink-routed")
	}
	marker := filepath.Join(dir, ".git")
	info, err := os.Lstat(marker)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("worktree has no regular Git pointer")
	}
	data, err := os.ReadFile(marker)
	if err != nil || !strings.HasPrefix(string(data), "gitdir: ") {
		return fmt.Errorf("worktree Git pointer is unreadable")
	}
	metadata := resolveGitPath(dir, strings.TrimPrefix(strings.TrimSpace(string(data)), "gitdir: "))
	gate, err := filepath.EvalSymlinks(p.RepoDir(repo.ID))
	if err != nil {
		return err
	}
	realMetadata, err := filepath.EvalSymlinks(metadata)
	if err != nil || realMetadata != metadata || filepath.Dir(metadata) != filepath.Join(gate, "worktrees") {
		return fmt.Errorf("worktree metadata is outside its gate")
	}
	common, err := os.ReadFile(filepath.Join(metadata, "commondir"))
	if err != nil || !samePath(resolveGitPath(metadata, string(common)), gate) {
		return fmt.Errorf("worktree common directory does not match its gate")
	}
	back, err := os.ReadFile(filepath.Join(metadata, "gitdir"))
	if err != nil || filepath.Clean(strings.TrimSpace(string(back))) != marker {
		return fmt.Errorf("worktree registration does not point back to its owner")
	}
	return nil
}

func removeLifecycleWorktree(ctx context.Context, d *db.DB, p *paths.Paths, repoID, runID, gateDir, dir string) error {
	repo, err := d.GetRepo(repoID)
	if err != nil {
		return err
	}
	cfg, err := config.LoadGlobal(p.ConfigFile())
	if err != nil {
		return err
	}
	ctx, controlled, err := lifecycleGitContext(ctx, d, p, cfg.ControlledExecution, cfg.Test.Evidence.LocalRoot, repo, runID, "")
	if err != nil {
		return err
	}
	if !controlled {
		return git.WorktreeRemove(ctx, gateDir, dir)
	}
	run, err := d.GetRun(runID)
	if err != nil {
		return err
	}
	if err := validateLifecycleWorktree(p, repo, run, dir); err != nil {
		return err
	}
	if !samePath(gateDir, p.RepoDir(repo.ID)) {
		return fmt.Errorf("cleanup gate does not match repository registration")
	}
	// Do not mount the checkout: Git can unregister its absent path, but cannot
	// recursively remove a bind mount. Delete only the proven owned tree on the
	// host after native metadata cleanup succeeds. RemoveAll does not follow
	// symlink entries. The caller exclusively owns this tree after process reap.
	if err := git.WorktreeRemove(ctx, gateDir, dir); err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

// Ownership precedes even process sweeping: an unknown directory is not a
// capability to kill its processes merely because it resembles a run path.
func validateLifecycleCleanupOwner(d *db.DB, p *paths.Paths, repoID, runID, dir string) error {
	cfg, err := config.LoadGlobal(p.ConfigFile())
	if err != nil {
		return err
	}
	enrolled, err := d.FactoryControlledRepoRunID(repoID)
	if err != nil {
		return err
	}
	if !cfg.ControlledExecution && enrolled == "" {
		return nil
	}
	repo, err := d.GetRepo(repoID)
	if err != nil {
		return err
	}
	run, err := d.GetRun(runID)
	if err != nil {
		return err
	}
	return validateLifecycleWorktree(p, repo, run, dir)
}
