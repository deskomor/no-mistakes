package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kunchenguid/no-mistakes/internal/factorysandbox"
)

func TestFactoryRuntimeExposesDeclaredPackagesNotSiblings(t *testing.T) {
	if err := factorysandbox.Supported(); err != nil {
		t.Skip(err)
	}
	root := t.TempDir()
	write := func(path, body string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	module := filepath.Join(root, "node_modules", "acpx")
	needed := filepath.Join(root, "node_modules", "context0")
	unrelated := filepath.Join(root, "node_modules", "unrelated")
	entry := filepath.Join(module, "bin", "acpx")
	write(filepath.Join(module, "package.json"), `{"name":"acpx","dependencies":{"context0":"1"}}`, 0600)
	write(filepath.Join(needed, "package.json"), `{"name":"context0"}`, 0600)
	write(filepath.Join(needed, "value"), "declared-package\n", 0600)
	write(filepath.Join(unrelated, "secret"), "unrelated-package-secret\n", 0600)
	write(entry, "#!/bin/sh\ncat \"$1\"\nif cat \"$2\" 2>/dev/null; then exit 42; fi\n", 0700)
	bin := filepath.Join(root, "bin")
	for _, name := range []string{"node", "omp"} {
		write(filepath.Join(bin, name), "#!/bin/sh\nexit 0\n", 0700)
	}
	source := filepath.Join(root, "source")
	if err := os.MkdirAll(source, 0700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "init", source).CombinedOutput(); err != nil {
		t.Fatalf("git fixture: %v %s", err, out)
	}
	runtimeDir, evidence := t.TempDir(), t.TempDir()
	env := append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "PI_CODING_AGENT_DIR="+runtimeDir)
	adapter := &acpxAgent{bin: entry, target: "omp"}
	grants, err := adapter.factoryRuntimePaths(env)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(entry, filepath.Join(needed, "value"), filepath.Join(unrelated, "secret"))
	cmd.Dir, cmd.Env = source, env
	cleanup, err := factorysandbox.WrapAssessment(cmd, evidence, []string{source}, true, grants...)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("package closure execution: %v", err)
	}
	if string(out) != "declared-package\n" {
		t.Fatalf("runtime exposed incorrect package data: %q", out)
	}
}

func TestFactoryRuntimeRefusesUnknownWrapperBeforeExecution(t *testing.T) {
	if err := factorysandbox.Supported(); err != nil {
		t.Skip(err)
	}
	for _, nested := range []bool{false, true} {
		name := "standalone"
		if nested {
			name = "nested-unsupported-package"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			wrapperDir := filepath.Join(root, "wrapper")
			if err := os.MkdirAll(wrapperDir, 0700); err != nil {
				t.Fatal(err)
			}
			expected := "not inside a validated acpx package"
			if nested {
				// An acpx ancestor must not override the nearest package's
				// identity: nested third-party wrappers remain unsupported.
				if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"acpx"}`), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(wrapperDir, "package.json"), []byte(`{"name":"unknown-wrapper"}`), 0600); err != nil {
					t.Fatal(err)
				}
				expected = `unsupported package "unknown-wrapper"`
			}
			marker := filepath.Join(root, "wrapper-executed")
			executable := filepath.Join(wrapperDir, "acpx")
			if err := os.WriteFile(executable, []byte("#!/bin/sh\nprintf executed > \""+marker+"\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			adapter := &acpxAgent{bin: executable, target: "omp"}
			result, err := adapter.Run(context.Background(), RunOpts{
				CWD:                root,
				FactoryControlled:  true,
				FactoryEvidenceDir: t.TempDir(),
			})
			if err == nil || !strings.Contains(err.Error(), expected) || result != nil {
				t.Fatalf("unknown wrapper was not refused at package admission: result=%+v err=%v", result, err)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("unknown wrapper executed before refusal: %v", err)
			}
		})
	}
}
