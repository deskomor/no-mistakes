package factorysandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func sandboxRepo(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux capability test")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap not installed")
	}
	dir := t.TempDir()
	cmd := exec.Command("git", "init", dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(dir, "source"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAssessmentDeniesSourceGitAndDescendantsAllowsEvidence(t *testing.T) {
	repo := sandboxRepo(t)
	evidence := t.TempDir()
	outside := t.TempDir()
	gitdir := filepath.Join(outside, "metadata")
	cmd := exec.Command("git", "-C", repo, "rev-parse", "--absolute-git-dir")
	original, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	// A real external Git directory covers worktree pointer and alternate path access.
	if err = os.Rename(strings.TrimSpace(string(original)), gitdir); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(repo, ".git"), []byte("gitdir: "+gitdir+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	script := `set -eu
test "$(cat "$1/source")" = original
test -s "$2/HEAD"
if printf altered > "$1/source"; then exit 31; fi
if sh -c 'printf altered > "$1/source"' child "$1"; then exit 32; fi
if printf altered > "$2/HEAD"; then exit 33; fi
if git -C "$1" update-ref refs/heads/assessment 0000000000000000000000000000000000000001; then exit 34; fi
printf evidence > "$3/result"
printf scratch > "$TMPDIR/check"
printf home > "$HOME/check"
`
	cmd = exec.Command("sh", "-c", script, "assessment", repo, gitdir, evidence)
	cmd.Dir = repo
	cleanup, err := WrapAssessment(cmd, evidence, []string{repo}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("enforced assessment: %v\n%s", err, out)
	}
	bytes, err := os.ReadFile(filepath.Join(repo, "source"))
	if err != nil || string(bytes) != "original" {
		t.Fatalf("source changed: %q %v", bytes, err)
	}
	if _, err = os.Stat(filepath.Join(evidence, "result")); err != nil {
		t.Fatal("allowed evidence missing:", err)
	}
}

func TestSandboxRejectsWritableAliasesIntoSourceAndGit(t *testing.T) {
	repo := sandboxRepo(t)
	for _, evidence := range []string{repo, filepath.Dir(repo), filepath.Join(repo, ".git")} {
		cmd := exec.Command("sh", "-c", "exit 99")
		cmd.Dir = repo
		if cleanup, err := WrapAssessment(cmd, evidence, []string{repo}, false); err == nil {
			cleanup()
			t.Fatalf("writable protected overlap accepted: %s", evidence)
		}
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(repo, alias); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", "exit 99")
	cmd.Dir = repo
	if cleanup, err := WrapAssessment(cmd, alias, []string{repo}, false); err == nil {
		cleanup()
		t.Fatal("symlink alias accepted")
	}
}

func TestSandboxRepairAllowsOnlyProductAndExplicitRuntime(t *testing.T) {
	repo := sandboxRepo(t)
	evidence := t.TempDir()
	runtimeDir := t.TempDir()
	unrelated := filepath.Join(t.TempDir(), "host-config")
	if err := os.WriteFile(unrelated, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", `set -eu; printf fixed > "$1/source"; git -C "$1" symbolic-ref HEAD refs/heads/repair; printf state > "$2/session"; test ! -r "$3"; if printf bad > "$3"; then exit 30; fi`, "repair", repo, runtimeDir, unrelated)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "PI_CODING_AGENT_DIR="+runtimeDir)
	cleanup, err := WrapCommand(cmd, evidence, []string{repo}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("repair boundary: %v %s", err, out)
	}
	data, err := os.ReadFile(filepath.Join(repo, "source"))
	if err != nil || string(data) != "fixed" {
		t.Fatalf("repair failed: %q %v", data, err)
	}
	data, err = os.ReadFile(filepath.Join(repo, ".git", "HEAD"))
	if err != nil || string(data) != "ref: refs/heads/repair\n" {
		t.Fatalf("Git repair failed: %q %v", data, err)
	}
	data, err = os.ReadFile(unrelated)
	if err != nil || string(data) != "original" {
		t.Fatalf("host config changed: %q %v", data, err)
	}
}

func TestAgentRuntimeIsExplicitAndOutsideProtectedState(t *testing.T) {
	repo := sandboxRepo(t)
	for _, runtimeDir := range []string{"", repo, filepath.Join(repo, ".git")} {
		cmd := exec.Command("sh", "-c", "exit 99")
		cmd.Dir = repo
		cmd.Env = []string{fmt.Sprintf("PI_CODING_AGENT_DIR=%s", runtimeDir)}
		if cleanup, err := WrapAssessment(cmd, t.TempDir(), []string{repo}, true); err == nil {
			cleanup()
			t.Fatalf("invalid runtime accepted %q", runtimeDir)
		}
	}
}

func TestSandboxHidesHostSiblingsSecretsAndServiceSockets(t *testing.T) {
	repo := sandboxRepo(t)
	if _, err := exec.LookPath("systemd-run"); err != nil {
		t.Skip("service escape regression requires real systemd-run")
	}
	evidence := t.TempDir()
	runtimeDir := t.TempDir()
	hostHome := t.TempDir()
	secret := filepath.Join(hostHome, "credentials")
	if err := os.WriteFile(secret, []byte("host secret"), 0600); err != nil {
		t.Fatal(err)
	}
	escape := filepath.Join(repo, "systemd-escape")
	cmd := exec.Command("sh", "-c", `set -eu
test ! -r "$1"
test ! -e "$2"
test -z "${DBUS_SESSION_BUS_ADDRESS-}"
test -z "${SSH_AUTH_SOCK-}"
test -z "${DISPLAY-}"
test -z "${WAYLAND_DISPLAY-}"
test -z "${OPENAI_API_KEY-}"
test -z "${GIT_CONFIG_COUNT-}"
test "$XDG_RUNTIME_DIR" = /run/user/private
printf runtime > "$PI_CODING_AGENT_DIR/session"
printf private > "$XDG_RUNTIME_DIR/check"
# An explicit original bus address must also fail, not just a sanitized env.
if DBUS_SESSION_BUS_ADDRESS="$3" systemd-run --user --wait --pipe /bin/sh -c 'printf escaped > "$1"' escape "$4"; then exit 41; fi
printf blocked > "$5/result"
`, "boundary", secret, filepath.Join("/run/user", fmt.Sprint(os.Getuid()), "bus"), "unix:path="+filepath.Join("/run/user", fmt.Sprint(os.Getuid()), "bus"), escape, evidence)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "PI_CODING_AGENT_DIR="+runtimeDir, "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/host-bus", "SSH_AUTH_SOCK=/tmp/host-agent", "DISPLAY=:0", "WAYLAND_DISPLAY=wayland-0", "OPENAI_API_KEY=host-secret", "GIT_CONFIG_COUNT=7")
	cleanup, err := WrapAssessment(cmd, evidence, []string{repo}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("host boundary: %v\n%s", err, out)
	}
	if _, err := os.Stat(escape); !os.IsNotExist(err) {
		t.Fatalf("service escape output exists: %v", err)
	}
	for _, path := range []string{filepath.Join(runtimeDir, "session"), filepath.Join(evidence, "result")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSandboxRejectsWritableHardlinkAliases(t *testing.T) {
	repo := sandboxRepo(t)
	for _, tree := range []string{"evidence", "runtime"} {
		t.Run(tree, func(t *testing.T) {
			evidence := t.TempDir()
			runtimeDir := t.TempDir()
			target := evidence
			if tree == "runtime" {
				target = runtimeDir
			}
			nested := filepath.Join(target, "nested")
			if err := os.Mkdir(nested, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(filepath.Join(repo, "source"), filepath.Join(nested, "alias")); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("sh", "-c", `printf altered > "$PI_CODING_AGENT_DIR/nested/alias"`)
			cmd.Dir = repo
			cmd.Env = append(os.Environ(), "PI_CODING_AGENT_DIR="+runtimeDir)
			if cleanup, err := WrapAssessment(cmd, evidence, []string{repo}, true); err == nil {
				cleanup()
				t.Fatal("multiply-linked writable regular file accepted")
			}
			data, err := os.ReadFile(filepath.Join(repo, "source"))
			if err != nil || string(data) != "original" {
				t.Fatalf("source changed: %q %v", data, err)
			}
		})
	}
}

func TestSandboxValidatesAllScopesBeforeCreatingEvidence(t *testing.T) {
	repo := sandboxRepo(t)
	evidence := filepath.Join(t.TempDir(), "must-not-exist")
	cmd := exec.Command("sh", "-c", "exit 99")
	cmd.Env = append(os.Environ(), "PI_CODING_AGENT_DIR="+filepath.Join(repo, "new-runtime"))
	if cleanup, err := WrapAssessment(cmd, evidence, []string{repo}, true); err == nil {
		cleanup()
		t.Fatal("protected runtime accepted")
	}
	if _, err := os.Stat(evidence); !os.IsNotExist(err) {
		t.Fatalf("evidence created before scope validation: %v", err)
	}
}

func TestSandboxRestoresExactTemporaryExecutableAndPublicResolver(t *testing.T) {
	repo := sandboxRepo(t)
	evidence := t.TempDir()
	dir := t.TempDir()
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(shell)
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "private-sh")
	if err := os.WriteFile(bin, data, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(dir, "host-secret")
	if err := os.WriteFile(sentinel, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	// The public resolver setup is a DNS prerequisite smoke, not a claim that
	// every host resolver or outbound model endpoint is universally reachable.
	cmd := exec.Command(bin, "-c", `set -eu; test ! -r "$1"; cat /etc/resolv.conf > "$2/resolver"; cat "$3/source" > "$2/source"`, "temporary-executable", sentinel, evidence, repo)
	cmd.Dir = repo
	cleanup, err := WrapAssessment(cmd, evidence, []string{repo}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("temporary executable/resolver: %v\n%s", err, out)
	}
	want, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(evidence, "resolver"))
	if err != nil || string(got) != string(want) {
		t.Fatalf("public resolver changed: %q %v", got, err)
	}
}

func TestSandboxRestoresTrustedExecutableAliasWithoutParent(t *testing.T) {
	repo := sandboxRepo(t)
	evidence := t.TempDir()
	install := t.TempDir()
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(shell)
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(install, "installed-shell")
	if err := os.WriteFile(real, data, 0700); err != nil {
		t.Fatal(err)
	}
	aliasDir := t.TempDir()
	alias := filepath.Join(aliasDir, "selected-shell")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(aliasDir, "host-secret")
	if err := os.WriteFile(secret, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", `set -eu; test ! -r "$1"; "$2" -c 'printf dependency > "$1/result"' dependency "$3"`, "trusted-runtime", secret, alias, evidence)
	cmd.Dir = repo
	cleanup, err := WrapAssessment(cmd, evidence, []string{repo}, false, alias)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("explicit executable alias: %v\n%s", err, out)
	}
	if data, err := os.ReadFile(filepath.Join(evidence, "result")); err != nil || string(data) != "dependency" {
		t.Fatalf("trusted child missing: %q %v", data, err)
	}
}
