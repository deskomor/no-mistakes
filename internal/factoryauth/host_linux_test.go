//go:build linux

package factoryauth

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kunchenguid/no-mistakes/internal/shellenv"
)

func TestRuntimeOwnershipAndUnsafeEntries(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "agent")
	release, e := ownRuntime(dir)
	if e != nil {
		t.Fatal(e)
	}
	if second, e := ownRuntime(dir); e == nil {
		second()
		t.Fatal("second credential host acquired same runtime")
	}
	release()
	release, e = ownRuntime(dir)
	if e != nil {
		t.Fatal(e)
	}
	release()
	sentinel := filepath.Join(root, "user-models")
	if e = os.WriteFile(sentinel, []byte("preserve"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Link(sentinel, filepath.Join(dir, "models.yml")); e != nil {
		t.Fatal(e)
	}
	if r, e := ownRuntime(dir); e == nil {
		r()
		t.Fatal("adopted existing hardlinked configuration")
	}
	b, e := os.ReadFile(sentinel)
	if e != nil || string(b) != "preserve" {
		t.Fatal("source changed")
	}
	linked := filepath.Join(root, "linked")
	if e = os.Symlink(dir, linked); e != nil {
		t.Fatal(e)
	}
	if e = safePath(linked, true); e == nil {
		t.Fatal("accepted symlink runtime")
	}
}
func TestHardlinkedLockIsRejected(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "agent")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	original := filepath.Join(root, "lock")
	if e := os.WriteFile(original, nil, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Link(original, filepath.Join(dir, ".factory-auth.lock")); e != nil {
		t.Fatal(e)
	}
	if r, e := ownRuntime(dir); e == nil {
		r()
		t.Fatal("hardlinked lock accepted")
	}
}
func TestHomeNestedRuntimeAllowedButCredentialOverlapRefused(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	agent := filepath.Join(home, ".omp", "agent")
	if e := os.MkdirAll(agent, 0700); e != nil {
		t.Fatal(e)
	}
	exe := filepath.Join(root, "omp")
	if e := os.WriteFile(exe, []byte("binary"), 0700); e != nil {
		t.Fatal(e)
	}
	data := filepath.Join(home, "data")
	if e := os.Mkdir(data, 0700); e != nil {
		t.Fatal(e)
	}
	o := Options{OMP: exe, SourceHome: home, SourceAgentDir: agent, RuntimeDir: filepath.Join(data, "runtime"), Model: "provider/id"}
	if e := validate(o); e != nil {
		t.Fatalf("private runtime under HOME refused: %v", e)
	}
	for _, dir := range []string{home, agent, filepath.Join(agent, "runtime"), filepath.Join(home, ".omp", "runtime"), root} {
		o.RuntimeDir = dir
		if e := validate(o); e == nil {
			t.Fatalf("overlap allowed: %s", dir)
		}
	}
}
func TestHostCommandClearsAmbientAuthorityAndUsesNeutralCWD(t *testing.T) {
	bwrap, e := exec.LookPath("bwrap")
	if e != nil {
		t.Skip("bubblewrap not installed; credential filesystem boundary untested")
	}
	// Probe the actual kernel boundary before deciding this CI host cannot run
	// the test. Once this succeeds, any production-command failure is a failure.
	probeArgs := []string{"--unshare-user", "--unshare-pid", "--cap-drop", "ALL", "--tmpfs", "/"}
	for _, path := range []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"} {
		if _, err := os.Stat(path); err == nil {
			probeArgs = append(probeArgs, "--ro-bind", path, path)
		}
	}
	probeArgs = append(probeArgs, "--proc", "/proc", "--dev", "/dev", "--", "/bin/sh", "-c", "exit 0")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	probe := exec.CommandContext(ctx, bwrap, probeArgs...)
	probe.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	if output, err := probe.CombinedOutput(); err != nil {
		reason := strings.ToLower(string(output))
		if ctx.Err() == nil && strings.Contains(reason, "namespace") && (strings.Contains(reason, "not permitted") || strings.Contains(reason, "permission denied") || strings.Contains(reason, "no permissions") || strings.Contains(reason, "not supported") || strings.Contains(reason, "disabled")) {
			t.Skipf("actual bubblewrap namespace probe unavailable; boundary untested: %s", output)
		}
		t.Fatalf("bubblewrap probe failed: %v: %s", err, output)
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	agent := filepath.Join(home, ".omp", "agent")
	// The supported source HOME may be an ancestor of private runtime data.
	scratch := filepath.Join(home, "data", "scratch")
	for _, dir := range []string{agent, filepath.Join(home, ".config"), filepath.Join(scratch, "neutral")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	credential := filepath.Join(home, ".config", "dummy-credential")
	settings := filepath.Join(agent, "settings.yml")
	overlay := filepath.Join(scratch, "overlay.yml")
	for _, path := range []string{credential, settings, overlay} {
		if err := os.WriteFile(path, []byte("public-dummy-source\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Keep the real Unix socket outside every approved source. A read-only
	// host-root mount would still expose this socket and the adjacent marker.
	hidden, err := os.MkdirTemp("", "factory-hidden-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(hidden) })
	marker := filepath.Join(hidden, "marker")
	if err = os.WriteFile(marker, []byte("unrelated-public-marker"), 0600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(hidden, "service.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	quote := func(path string) string { return "'" + strings.ReplaceAll(path, "'", "'\\''") + "'" }
	script := strings.NewReplacer("@HOME@", quote(home), "@AGENT@", quote(agent), "@CREDENTIAL@", quote(credential), "@SETTINGS@", quote(settings), "@HIDDEN@", quote(hidden), "@MARKER@", quote(marker), "@SOCKET@", quote(socket)).Replace(`#!/bin/sh
set -eux
test "$1" = auth-gateway
test "$2" = stdio
test "$PWD" = /factory/neutral
test "$(pwd -P)" = /factory/neutral
test "$HOME" = @HOME@
test "$PI_CODING_AGENT_DIR" = @AGENT@
test "$XDG_CONFIG_HOME" = "$HOME/.config"
test "$PI_CONFIG_FILES" = /factory/overlay.yml
test "$XDG_CACHE_HOME" = /factory/cache
test "$TMPDIR" = /tmp
test "${OPENAI_API_KEY+x}" = ""
test "${ANTHROPIC_API_KEY+x}" = ""
test "${PI_PROJECT_DIR+x}" = ""
test "${PI_MODEL+x}" = ""
test "${SSH_AUTH_SOCK+x}" = ""
test "${DBUS_SESSION_BUS_ADDRESS+x}" = ""
test "${XDG_RUNTIME_DIR+x}" = ""
test "${NODE_OPTIONS+x}" = ""
test "${LD_LIBRARY_PATH+x}" = ""
test "$(cat @CREDENTIAL@)" = public-dummy-source
test "$(cat @SETTINGS@)" = public-dummy-source
test "$(cat /factory/overlay.yml)" = public-dummy-source
if (printf changed > @CREDENTIAL@) 2>/dev/null; then exit 41; fi
if (printf changed > @SETTINGS@) 2>/dev/null; then exit 42; fi
if (printf changed > "$HOME/new-source-file") 2>/dev/null; then exit 43; fi
if (printf changed > "$0") 2>/dev/null; then exit 44; fi
if (printf changed > /factory/overlay.yml) 2>/dev/null; then exit 45; fi
if (printf changed > "$HOME/data/scratch/source-alias-write") 2>/dev/null; then exit 46; fi
test ! -e @MARKER@
test ! -e @SOCKET@
test ! -e @HIDDEN@
test -z "$(ls -A /run)"
test -z "$(ls -A /var/tmp)"
while read key value rest; do
  case "$key" in CapEff:|CapPrm:|CapBnd:) test "$value" = 0000000000000000;; esac
done < /proc/self/status
printf private-write > /factory/proof
mkdir -p /factory/cache
printf cache-write > /factory/cache/proof
printf temporary-write > /tmp/proof
printf boundary-observed
`)
	exe := filepath.Join(root, "omp")
	if err = os.WriteFile(exe, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{
		"OPENAI_API_KEY": "ambient-dummy-secret", "ANTHROPIC_API_KEY": "ambient-dummy-secret",
		"PI_CONFIG_FILES": "/card/evil.yml", "PI_PROJECT_DIR": "/card", "PI_MODEL": "other/model",
		"XDG_CONFIG_HOME": hidden, "XDG_RUNTIME_DIR": hidden, "SSH_AUTH_SOCK": socket,
		"DBUS_SESSION_BUS_ADDRESS": "unix:path=" + socket, "NODE_OPTIONS": "--require=/card/evil.js",
		"LD_LIBRARY_PATH": hidden,
	} {
		t.Setenv(key, value)
	}
	cmd, err := hostCommand(ctx, Options{OMP: exe, SourceHome: home, SourceAgentDir: agent}, scratch, overlay)
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("credential filesystem boundary failed: %v: %s", err, output)
	}
	if !strings.Contains(string(output), "boundary-observed") {
		t.Fatal("fake credential host did not finish its boundary observations")
	}
	for _, path := range []string{credential, settings, overlay} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "public-dummy-source\n" {
			t.Fatalf("source changed: %s: %v", path, err)
		}
	}
	for path, want := range map[string]string{"proof": "private-write", "cache/proof": "cache-write"} {
		data, err := os.ReadFile(filepath.Join(scratch, path))
		if err != nil || string(data) != want {
			t.Fatalf("private scratch write missing: %s: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(home, "new-source-file")); !os.IsNotExist(err) {
		t.Fatalf("source HOME was writable: %v", err)
	}
}

func TestCancellationReapsCredentialPeerDescendants(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "sleep 300 & echo $!; wait")
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + cmd.Dir}
	shellenv.ConfigureShellCommand(cmd)
	out, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = shellenv.StartShellCommand(cmd); e != nil {
		t.Fatal(e)
	}
	defer shellenv.TerminateShellCommandGroup(cmd)
	line, e := bufio.NewReader(out).ReadString('\n')
	if e != nil {
		cancel()
		_ = cmd.Wait()
		t.Fatal(e)
	}
	pid, e := strconv.Atoi(strings.TrimSpace(line))
	if e != nil {
		cancel()
		_ = cmd.Wait()
		t.Fatal(e)
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	cancel()
	select {
	case <-waited:
	case <-time.After(8 * time.Second):
		t.Fatal("peer parent survived cancellation")
	}
	shellenv.TerminateShellCommandGroup(cmd)
	deadline := time.Now().Add(5 * time.Second)
	for {
		b, e := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if os.IsNotExist(e) {
			break
		}
		// A zombie is already dead; init owns its final bookkeeping, not this host.
		if e == nil {
			tail := string(b)
			if end := strings.LastIndex(tail, ") "); end >= 0 && strings.HasPrefix(tail[end+2:], "Z ") {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("credential descendant %d survived group cleanup", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
