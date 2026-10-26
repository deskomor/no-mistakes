package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kunchenguid/no-mistakes/internal/db"
	"github.com/kunchenguid/no-mistakes/internal/types"
)

func TestAxiFactoryGateDetailsReadOnlyFullFindings(t *testing.T) {
	home := t.TempDir()
	t.Setenv("NM_HOME", home)
	database, err := db.Open(filepath.Join(home, "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	repo, err := database.InsertRepo(t.TempDir(), "https://example.invalid/details.git", "main")
	if err != nil {
		t.Fatal(err)
	}
	run, err := database.InsertRun(repo.ID, "details", "exact-head", "base")
	if err != nil {
		t.Fatal(err)
	}
	if err = database.UpdateRunStatus(run.ID, types.RunRunning); err != nil {
		t.Fatal(err)
	}
	step, err := database.InsertStepResult(run.ID, types.StepReview)
	if err != nil {
		t.Fatal(err)
	}
	finding := types.Finding{ID: "original-finding", Severity: "warning", Action: "ask-user", Description: strings.Repeat("complete finding text ", 300) + "end marker"}
	raw, err := json.Marshal(types.Findings{Items: []types.Finding{finding}})
	if err != nil {
		t.Fatal(err)
	}
	findings := string(raw)
	if err = database.ParkStepForApproval(run.ID, step.ID, types.StepStatusAwaitingApproval, 0, 0, &findings); err != nil {
		t.Fatal(err)
	}
	gate, err := database.ParkFactoryGate(run.ID, step.ID, 1, "exact-head")
	if err != nil {
		t.Fatal(err)
	}
	invoke := func(args ...string) ([]byte, error) {
		t.Helper()
		var out bytes.Buffer
		cmd := newAxiFactoryLookupCmd(false)
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(args)
		err := cmd.Execute()
		return out.Bytes(), err
	}
	plain, err := invoke("--run", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	var original db.FactoryGate
	if err = json.Unmarshal(plain, &original); err != nil || original != *gate || bytes.Contains(plain, []byte("findings")) {
		t.Fatalf("default protocol changed: %s %v", plain, err)
	}
	full, err := invoke("--details", "--run", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	var details db.FactoryGateDetails
	if err = json.Unmarshal(full, &details); err != nil || details.Gate != original || !reflect.DeepEqual(details.Findings, []types.Finding{finding}) {
		t.Fatalf("full CLI snapshot lost data: %#v %v", details, err)
	}
	if err = database.FenceFactoryRun(run.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = invoke("--details", "--run", run.ID); err == nil {
		t.Fatal("stopping gate details accepted")
	}
	if _, err = invoke("--run", run.ID); err != nil {
		t.Fatalf("default identity lookup no longer reads fenced gates: %v", err)
	}
}
