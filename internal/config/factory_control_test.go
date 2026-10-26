package config

import (
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"testing"
)

func TestFactoryControlledExecutionIsMachineOnlyAndOptIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("controlled_execution: true\nagent: acp:omp\n"), 0600); err != nil {
		t.Fatal(err)
	}
	global, err := LoadGlobal(path)
	if err != nil {
		t.Fatal(err)
	}
	var repo RepoConfig
	if err = yaml.Unmarshal([]byte("controlled_execution: false\nauto_fix:\n  review: 100\n  document: 100\n"), &repo); err != nil {
		t.Fatal(err)
	}
	if !Merge(global, &repo).ControlledExecution {
		t.Fatal("repository disabled machine control")
	}
	if err = yaml.Unmarshal([]byte("controlled_execution: true\n"), &repo); err != nil {
		t.Fatal(err)
	}
	if Merge(DefaultGlobalConfig(), &repo).ControlledExecution {
		t.Fatal("repository enabled machine control without operator opt-in")
	}
}
