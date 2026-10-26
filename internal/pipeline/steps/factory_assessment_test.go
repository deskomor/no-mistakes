package steps

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kunchenguid/no-mistakes/internal/agent"
	"github.com/kunchenguid/no-mistakes/internal/config"
	"github.com/kunchenguid/no-mistakes/internal/pipeline"
	"github.com/kunchenguid/no-mistakes/internal/types"
)

func TestFactoryInitialHousekeepingAssessesWithoutUnreservedEdits(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux enforcement")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap unavailable")
	}
	for _, step := range []pipeline.Step{&DocumentStep{}, &LintStep{}} {
		t.Run(string(step.Name()), func(t *testing.T) {
			dir, base, head := setupGitRepo(t)
			source := filepath.Join(dir, "controlled-sentinel")
			if err := os.WriteFile(source, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
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
			runtimeDir := t.TempDir()
			script := "#!/bin/sh\nsource='" + strings.ReplaceAll(source, "'", "'\\''") + "'\n" + `
cat > /dev/null
if printf forbidden > "$source"; then exit 91; fi
if sh -c 'printf forbidden > "$1"' child "$source"; then exit 92; fi
printf evidence > "$PI_CODING_AGENT_DIR/proof"
printf '%s\n' '{"method":"session/update","params":{"update":{"sessionUpdate":"agent_message_chunk","text":"{\"findings\":[{\"id\":\"required\",\"severity\":\"warning\",\"description\":\"required correction\",\"action\":\"auto-fix\"}],\"summary\":\"needs correction\"}"}}}'
`
			if err := os.WriteFile(stub, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			ag, err := agent.New("acp:omp", stub, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer ag.Close()
			sctx := newTestContextWithDBRecords(t, ag, dir, base, head, config.Commands{})
			run, err := sctx.DB.InsertRunWithIntentAndLaunchNonce(sctx.Repo.ID, sctx.Run.Branch, head, base, nil, "nonce", "card-generation", "digest", "", false, nil)
			if err != nil {
				t.Fatal(err)
			}
			sctx.Run = run
			if err = sctx.DB.EnsureFactoryBudget(run); err != nil {
				t.Fatal(err)
			}
			sctx.Config.ControlledExecution = true
			t.Setenv("PI_CODING_AGENT_DIR", runtimeDir)
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			outcome, err := step.Execute(sctx)
			if err != nil {
				t.Fatal(err)
			}
			if !outcome.NeedsApproval || !strings.Contains(outcome.Findings, "required correction") {
				t.Fatalf("missing required-change gate: %#v", outcome)
			}
			content, err := os.ReadFile(source)
			if err != nil || string(content) != "original" {
				t.Fatalf("initial %s changed source: %q %v", step.Name(), content, err)
			}
			used, err := sctx.DB.GetFactoryBudget(run.ID)
			if err != nil || used != 0 {
				t.Fatalf("assessment consumed budget: %d %v", used, err)
			}
			if _, err = os.Stat(filepath.Join(runtimeDir, "proof")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFactoryConfiguredCommandAndPrepareAreReadOnly(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux enforcement")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap unavailable")
	}
	dir, base, head := setupGitRepo(t)
	sctx := newTestContextWithDBRecords(t, agent.NewNoop(), dir, base, head, config.Commands{})
	sctx.Config.ControlledExecution = true
	sctx.Config.Commands.Prepare = "printf forbidden > forbidden-setup"
	if err := ensurePrepared(sctx, types.StepTest); err == nil {
		t.Fatal("mutating prepare unexpectedly succeeded")
	}
	if _, err := os.Stat(filepath.Join(dir, "forbidden-setup")); !os.IsNotExist(err) {
		t.Fatalf("setup wrote source: %v", err)
	}
	output, code, err := runStepShellCommand(sctx, "sh -c 'printf forbidden > forbidden-test'")
	if err != nil || code == 0 {
		t.Fatalf("mutating configured command: code=%d err=%v output=%s", code, err, output)
	}
	if _, err = os.Stat(filepath.Join(dir, "forbidden-test")); !os.IsNotExist(err) {
		t.Fatalf("configured command wrote source: %v", err)
	}
	// The legacy path retains upstream command capability when opt-out.
	sctx.Config.ControlledExecution = false
	_, code, err = runStepShellCommand(sctx, "printf legacy > legacy-marker")
	if err != nil || code != 0 {
		t.Fatalf("legacy command changed: %d %v", code, err)
	}
	if _, err = os.Stat(filepath.Join(dir, "legacy-marker")); err != nil {
		t.Fatal(err)
	}
}
