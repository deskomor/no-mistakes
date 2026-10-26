package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFactoryACPUnknownMutationFailureNeverRetries(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux enforcement")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap unavailable")
	}
	repo := t.TempDir()
	cmd := exec.Command("git", "init", repo)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	evidence := t.TempDir()
	runtimeDir := t.TempDir()
	bin := t.TempDir()
	stub := filepath.Join(bin, "acpx")
	if err := os.WriteFile(filepath.Join(bin, "package.json"), []byte(`{"name":"acpx"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"node", "omp"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	script := `#!/bin/sh
cat > /dev/null
printf dispatched >> "$PI_CODING_AGENT_DIR/dispatch"
printf 'rate limit exceeded; overloaded; retry after 0s\n' >&2
exit 1
`
	if err := os.WriteFile(stub, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	a, err := New("acp:omp", stub, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	_, err = a.Run(context.Background(), RunOpts{Prompt: "repair", CWD: repo, FactoryControlled: true, FactoryMutation: true, FactoryEvidenceDir: evidence, Env: []string{"PI_CODING_AGENT_DIR=" + runtimeDir, "PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH")}})
	if err == nil {
		t.Fatal("failed mutation unexpectedly succeeded")
	}
	dispatched, err := os.ReadFile(filepath.Join(runtimeDir, "dispatch"))
	if err != nil {
		t.Fatal(err)
	}
	if string(dispatched) != "dispatched" {
		t.Fatalf("mutation replayed: %q", dispatched)
	}
}

func TestFactoryRejectsUnsupportedAdaptersAndACPOverrideBeforeLaunch(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux enforcement")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap unavailable")
	}
	for _, target := range []string{"gemini", "codex", "omp"} {
		a := &acpxAgent{bin: "must-not-launch", target: target}
		if target == "omp" {
			a.rawCommand = "omp acp --custom"
		}
		_, err := a.Run(context.Background(), RunOpts{FactoryControlled: true})
		if err == nil || !strings.Contains(err.Error(), "unsupported adapter") {
			t.Fatalf("target %s was not refused before launch: %v", target, err)
		}
	}
}
