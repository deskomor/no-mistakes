//go:build linux

package factoryauth

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func supportedHost() error { return nil }
func ownRuntime(dir string) (func(), error) {
	if e := os.Mkdir(dir, 0700); e != nil && !os.IsExist(e) {
		return nil, errors.New("runtime directory unavailable")
	}
	s, e := os.Lstat(dir)
	if e != nil || !s.IsDir() || s.Mode().Perm() != 0700 {
		return nil, errors.New("runtime must be a private mode0700 directory")
	}
	if st, ok := s.Sys().(*syscall.Stat_t); !ok || st.Uid != uint32(os.Getuid()) {
		return nil, errors.New("runtime owner mismatch")
	}
	lock := filepath.Join(dir, ".factory-auth.lock")
	fd, e := syscall.Open(lock, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return nil, errors.New("runtime lock unavailable")
	}
	f := os.NewFile(uintptr(fd), lock)
	s, e = f.Stat()
	if e != nil {
		_ = f.Close()
		return nil, errors.New("runtime lock unavailable")
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || !s.Mode().IsRegular() || st.Nlink != 1 || st.Uid != uint32(os.Getuid()) || s.Mode().Perm() != 0600 {
		_ = f.Close()
		return nil, errors.New("unsafe runtime lock")
	}
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		_ = f.Close()
		return nil, errors.New("runtime already owned")
	}
	release := func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = f.Close() }
	entries, e := os.ReadDir(dir)
	if e != nil {
		release()
		return nil, e
	}
	for _, entry := range entries {
		if entry.Name() != ".factory-auth.lock" {
			release()
			return nil, errors.New("runtime must be empty; existing agent state is not adopted")
		}
	}
	return release, nil
}
func hostCommand(ctx context.Context, o Options, scratch, overlay string) (*exec.Cmd, error) {
	bwrap, e := exec.LookPath("bwrap")
	if e != nil {
		return nil, errors.New("Linux bubblewrap required")
	}
	st, e := os.Stat(o.OMP)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
		return nil, errors.New("omp must be an executable regular file")
	}
	if info, ok := st.Sys().(*syscall.Stat_t); !ok || info.Nlink != 1 {
		return nil, errors.New("hardlinked omp executable unsupported")
	}
	// Build an allowlisted filesystem, not a read-only view of the host: a
	// read-only Unix socket still grants access to the service behind it.
	args := []string{"--die-with-parent", "--new-session", "--unshare-user", "--unshare-pid", "--cap-drop", "ALL", "--tmpfs", "/"}
	for _, path := range []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"} {
		if _, err := os.Stat(path); err == nil {
			args = append(args, "--ro-bind", path, path)
		} else if !os.IsNotExist(err) {
			return nil, errors.New("system runtime unavailable")
		}
	}
	for _, path := range []string{"/etc/nsswitch.conf", "/etc/hosts", "/etc/host.conf", "/etc/gai.conf", "/etc/services", "/etc/protocols", "/etc/ssl/certs", "/etc/pki/tls/certs", "/etc/pki/ca-trust"} {
		if _, err := os.Stat(path); err == nil {
			args = append(args, "--ro-bind", path, path)
		} else if !os.IsNotExist(err) {
			return nil, errors.New("public network configuration unavailable")
		}
	}
	// The resolver is commonly a symlink into /run. Copy only this public
	// regular file into owned scratch; never expose its runtime ancestors.
	resolver, err := filepath.EvalSymlinks("/etc/resolv.conf")
	if err == nil {
		info, statErr := os.Stat(resolver)
		if statErr != nil || !info.Mode().IsRegular() {
			return nil, errors.New("DNS resolver is not a regular file")
		}
		data, readErr := os.ReadFile(resolver)
		if readErr != nil {
			return nil, errors.New("DNS resolver unavailable")
		}
		resolverCopy := filepath.Join(scratch, "resolv.conf")
		if writeErr := os.WriteFile(resolverCopy, data, 0600); writeErr != nil {
			return nil, errors.New("private DNS resolver unavailable")
		}
		args = append(args, "--ro-bind", resolverCopy, "/etc/resolv.conf")
	} else if !os.IsNotExist(err) {
		return nil, errors.New("DNS resolver unavailable")
	}
	args = append(args, "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/run", "--tmpfs", "/tmp", "--tmpfs", "/var/tmp")
	// SourceHome intentionally includes its normal data/runtime descendants,
	// but none of those paths are writable. Extra runtimes outside the system
	// mounts and these explicit sources are unsupported, not PATH-derived grants.
	args = append(args, "--ro-bind", o.SourceHome, o.SourceHome, "--ro-bind", o.SourceAgentDir, o.SourceAgentDir, "--ro-bind", o.OMP, o.OMP, "--bind", scratch, "/factory", "--ro-bind", overlay, "/factory/overlay.yml", "--chdir", "/factory/neutral", "--setenv", "HOME", o.SourceHome, "--setenv", "PI_CODING_AGENT_DIR", o.SourceAgentDir, "--setenv", "PI_CONFIG_FILES", "/factory/overlay.yml", "--setenv", "XDG_CACHE_HOME", "/factory/cache", "--setenv", "TMPDIR", "/tmp", "--", o.OMP, "auth-gateway", "stdio")
	cmd := exec.CommandContext(ctx, bwrap, args...)
	// Never inherit ambient model selectors, project paths, API keys, overlay
	// controls or broker overrides. Auth comes only from the chosen RO sources.
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + o.SourceHome, "LANG=C.UTF-8", "XDG_CONFIG_HOME=" + filepath.Join(o.SourceHome, ".config"), "NO_MISTAKES_TELEMETRY=off", "NO_MISTAKES_NO_UPDATE_CHECK=1"}
	cmd.Dir = scratch
	return cmd, nil
}
