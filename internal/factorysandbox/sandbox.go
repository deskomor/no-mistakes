// Package factorysandbox owns the opt-in Linux filesystem capability boundary.
// It is not a general network or abstract-IPC sandbox: outbound TCP remains
// available for the controlled ACP gateway. Trusted callers must exclusively own
// isolated runtime/evidence trees, without concurrent host writers, from scope
// validation through child exit. Mount validation cannot prevent host-side races.
package factorysandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Supported fails closed before dispatch if the machine cannot enforce policy.
func Supported() error {
	if runtime.GOOS != "linux" {
		return errors.New("controlled execution requires Linux bubblewrap")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		return fmt.Errorf("controlled execution requires bubblewrap: %w", err)
	}
	return nil
}

func canonical(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(path)
}

// Resolve a not-yet-created evidence path through its real existing ancestor.
func canonicalDestination(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err == nil {
		return resolved, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	parent := filepath.Dir(absolute)
	if parent == absolute {
		return "", err
	}
	parent, err = canonicalDestination(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(absolute)), nil
}

func within(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// ProtectRoots resolves linked-worktree/common metadata without executing Git
// (which could itself execute host config helpers before the boundary exists).
func ProtectRoots(workdirs []string) ([]string, error) {
	var roots []string
	for _, dir := range workdirs {
		if dir == "" {
			continue
		}
		real, err := canonical(dir)
		if err != nil {
			return nil, err
		}
		roots = append(roots, real)
		gitdir := ""
		for candidate := real; ; candidate = filepath.Dir(candidate) {
			marker := filepath.Join(candidate, ".git")
			info, statErr := os.Stat(marker)
			if statErr == nil {
				if info.IsDir() {
					gitdir = marker
				} else {
					data, readErr := os.ReadFile(marker)
					if readErr != nil {
						return nil, readErr
					}
					value := strings.TrimSpace(string(data))
					if !strings.HasPrefix(value, "gitdir: ") {
						return nil, fmt.Errorf("invalid Git directory pointer: %s", marker)
					}
					gitdir = strings.TrimPrefix(value, "gitdir: ")
					if !filepath.IsAbs(gitdir) {
						gitdir = filepath.Join(candidate, gitdir)
					}
				}
				break
			}
			if !os.IsNotExist(statErr) {
				return nil, statErr
			}
			// Bare repositories have no .git marker.
			if info, err := os.Stat(filepath.Join(candidate, "objects")); err == nil && info.IsDir() {
				if _, err := os.Stat(filepath.Join(candidate, "HEAD")); err == nil {
					gitdir = candidate
					break
				}
			}
			if filepath.Dir(candidate) == candidate {
				return nil, fmt.Errorf("resolve controlled Git boundary: no repository at %s", real)
			}
		}
		gitdir, err = canonical(gitdir)
		if err != nil {
			return nil, err
		}
		roots = append(roots, gitdir)
		common, err := os.ReadFile(filepath.Join(gitdir, "commondir"))
		if err == nil {
			path := strings.TrimSpace(string(common))
			if !filepath.IsAbs(path) {
				path = filepath.Join(gitdir, path)
			}
			path, err = canonical(path)
			if err != nil {
				return nil, err
			}
			roots = append(roots, path)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	return roots, nil
}

// WrapAssessment wraps the command and all descendants with a minimal read-only
// system view. Only explicit evidence/runtime and disposable HOME/TMP are writable.
// trustedRuntimePaths is a caller-validated executable/package dependency closure,
// never a user home/configuration tree. Cleanup runs after Wait or start failure.
func WrapAssessment(cmd *exec.Cmd, evidence string, protected []string, agentRuntime bool, trustedRuntimePaths ...string) (func(), error) {
	return WrapCommand(cmd, evidence, protected, agentRuntime, false, trustedRuntimePaths...)
}

// WrapCommand grants protected product/Git writes only for an admitted repair.
// Runtime/evidence trees must remain exclusively owned by the trusted caller.
func WrapCommand(cmd *exec.Cmd, evidence string, protected []string, agentRuntime, mutation bool, trustedRuntimePaths ...string) (func(), error) {
	return wrapCommand(cmd, evidence, protected, agentRuntime, mutation, gitScratch{}, trustedRuntimePaths...)
}

// gitScratch is private so only the trusted parent Git context can grant it;
// neither agent callers nor ambient environment can add writable mounts.
type gitScratch struct {
	dir         string
	index       string
	destination string
}

func wrapCommand(cmd *exec.Cmd, evidence string, protected []string, agentRuntime, mutation bool, scratchIndex gitScratch, trustedRuntimePaths ...string) (func(), error) {
	if err := Supported(); err != nil {
		return nil, err
	}
	roots, err := ProtectRoots(protected)
	if err != nil {
		return nil, err
	}
	if len(roots) == 0 {
		return nil, errors.New("controlled execution requires a protected repository working directory")
	}
	if scratchIndex.destination != "" {
		dir := scratchIndex.destination
		real, err := canonical(dir)
		if err != nil || !filepath.IsAbs(dir) || real != dir {
			return nil, fmt.Errorf("controlled worktree destination must be an existing non-symlink directory")
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			return nil, fmt.Errorf("controlled worktree destination must be empty")
		}
		for _, root := range roots {
			if within(dir, root) || within(root, dir) {
				return nil, fmt.Errorf("controlled worktree destination overlaps existing Git roots")
			}
		}
		roots = append(roots, dir)
	}
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	var filtered []string
	runtimeDir := ""
	for _, entry := range env {
		key, value, _ := strings.Cut(entry, "=")
		if key == "PI_CODING_AGENT_DIR" {
			runtimeDir = value
		}
		// No ambient auth tokens, service sockets, display endpoints or user
		// config selectors. Gateway credentials belong to the isolated PI tree.
		if key == "PATH" || key == "LANG" || key == "LANGUAGE" || strings.HasPrefix(key, "LC_") || key == "TERM" || key == "TZ" || key == "GIT_AUTHOR_NAME" || key == "GIT_AUTHOR_EMAIL" || key == "GIT_AUTHOR_DATE" || key == "GIT_COMMITTER_NAME" || key == "GIT_COMMITTER_EMAIL" || key == "GIT_COMMITTER_DATE" {
			filtered = append(filtered, entry)
		}
	}
	filtered = append(filtered, "GIT_CONFIG_NOSYSTEM=1", "NO_MISTAKES_GATE=1", "COMPACT_ADVISER_DISABLE=1")
	var writable []string
	if evidence != "" {
		writable = append(writable, evidence)
	}
	if agentRuntime {
		if runtimeDir == "" {
			return nil, errors.New("controlled acp:omp requires an explicit isolated PI_CODING_AGENT_DIR (no user credentials or config are copied)")
		}
		writable = append(writable, runtimeDir)
	}
	if scratchIndex.dir != "" {
		// Unlike evidence destinations, scratch must already exist with no
		// symlink routing in either its directory or any contained entry.
		resolved, err := canonical(scratchIndex.dir)
		if err != nil || resolved != scratchIndex.dir {
			return nil, fmt.Errorf("controlled Git scratch directory must be an existing non-symlink path: %s", scratchIndex.dir)
		}
		if err := filepath.WalkDir(scratchIndex.dir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("controlled Git scratch contains symlink: %s", path)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		if info, err := os.Lstat(scratchIndex.index); err == nil {
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("controlled Git scratch index is not a regular file: %s", scratchIndex.index)
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		writable = append(writable, scratchIndex.dir)
		filtered = append(filtered, "GIT_INDEX_FILE="+scratchIndex.index)
	}
	// Validate every scope before creating even the evidence directory.
	for i, path := range writable {
		path, err = canonicalDestination(path)
		if err != nil {
			return nil, fmt.Errorf("controlled writable directory: %w", err)
		}
		for _, root := range roots {
			if within(path, root) || within(root, path) {
				return nil, fmt.Errorf("controlled writable directory overlaps protected source/Git state: %s", path)
			}
		}
		writable[i] = path
	}
	for i, path := range writable {
		if i == 0 && evidence != "" {
			if err = os.MkdirAll(path, 0700); err != nil {
				return nil, err
			}
		}
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("controlled writable path is not a directory: %s", path)
		}
		if err := rejectHardlinks(path); err != nil {
			return nil, err
		}
	}
	if agentRuntime {
		runtimeDir, err = canonical(runtimeDir)
		if err != nil {
			return nil, err
		}
		filtered = append(filtered, "PI_CODING_AGENT_DIR="+runtimeDir)
	}
	// Resolve explicit package roots and the exact entry executable, never its
	// containing temp/home directory. Dependencies outside /usr need admission.
	entry, err := canonical(cmd.Path)
	if err != nil {
		return nil, fmt.Errorf("controlled executable: %w", err)
	}
	type runtimeMount struct{ source, destination string }
	trusted := []runtimeMount{{entry, entry}}
	for _, path := range trustedRuntimePaths {
		destination, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		source, err := canonical(path)
		if err != nil {
			return nil, fmt.Errorf("controlled runtime dependency: %w", err)
		}
		if source == "/" || destination == "/" {
			return nil, errors.New("controlled runtime dependency cannot expose host root")
		}
		trusted = append(trusted, runtimeMount{source, destination})
		if source != destination {
			trusted = append(trusted, runtimeMount{source, source})
		}
	}
	scratch, err := os.MkdirTemp("", "no-mistakes-assessment-")
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = os.RemoveAll(scratch) }
	scratch, err = canonical(scratch)
	if err != nil {
		cleanup()
		return nil, err
	}
	bin, err := exec.LookPath("bwrap")
	if err != nil {
		cleanup()
		return nil, err
	}
	args := []string{bin, "--die-with-parent", "--unshare-user", "--unshare-pid", "--new-session", "--cap-drop", "ALL", "--tmpfs", "/"}
	for _, path := range []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"} {
		if _, err := os.Stat(path); err == nil {
			args = append(args, "--ro-bind", path, path)
		}
	}
	for _, path := range []string{"/etc/nsswitch.conf", "/etc/hosts", "/etc/host.conf", "/etc/gai.conf", "/etc/services", "/etc/protocols", "/etc/ssl/certs", "/etc/pki/tls/certs", "/etc/pki/ca-trust"} {
		if _, err := os.Stat(path); err == nil {
			args = append(args, "--ro-bind", path, path)
		}
	}
	// /etc/resolv.conf often points into /run. Copy only the resolved public
	// regular resolver file, not the host runtime directory or its service bus.
	resolver, resolveErr := canonical("/etc/resolv.conf")
	if resolveErr == nil {
		info, statErr := os.Stat(resolver)
		if statErr != nil || !info.Mode().IsRegular() {
			cleanup()
			return nil, errors.New("controlled DNS resolver is not a regular file")
		}
		data, readErr := os.ReadFile(resolver)
		if readErr != nil {
			cleanup()
			return nil, readErr
		}
		copyPath := filepath.Join(scratch, "resolv.conf")
		if err := os.WriteFile(copyPath, data, 0600); err != nil {
			cleanup()
			return nil, err
		}
		args = append(args, "--ro-bind", copyPath, "/etc/resolv.conf")
	} else if !os.IsNotExist(resolveErr) {
		cleanup()
		return nil, resolveErr
	}
	args = append(args, "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/run", "--tmpfs", "/tmp", "--tmpfs", "/var/tmp", "--dir", "/run/user", "--dir", "/run/user/private", "--dir", "/tmp/home", "--bind", scratch, scratch)
	for _, mount := range trusted {
		args = append(args, "--ro-bind", mount.source, mount.destination)
	}
	for _, path := range roots {
		mode := "--ro-bind"
		if mutation {
			mode = "--bind"
		}
		args = append(args, mode, path, path)
	}
	for _, path := range writable {
		args = append(args, "--bind", path, path)
	}
	args = append(args, "--setenv", "HOME", "/tmp/home", "--setenv", "TMPDIR", "/tmp", "--setenv", "XDG_RUNTIME_DIR", "/run/user/private", "--setenv", "XDG_CACHE_HOME", "/tmp/home/.cache", "--setenv", "XDG_STATE_HOME", "/tmp/home/.local/state", "--setenv", "XDG_CONFIG_HOME", "/tmp/home/.config", "--setenv", "XDG_DATA_HOME", "/tmp/home/.local/share")
	if cmd.Dir != "" {
		dir, err := canonical(cmd.Dir)
		if err != nil {
			cleanup()
			return nil, err
		}
		args = append(args, "--chdir", dir)
	}
	args = append(args, "--", entry)
	args = append(args, cmd.Args[1:]...)
	cmd.Env = filtered
	cmd.Path = bin
	cmd.Args = args
	return cleanup, nil
}
