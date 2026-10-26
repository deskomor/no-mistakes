package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kunchenguid/no-mistakes/internal/agent"
	"github.com/kunchenguid/no-mistakes/internal/db"
	"github.com/kunchenguid/no-mistakes/internal/types"
)

type factoryFileRepair struct{ path string }

func (a *factoryFileRepair) Name() string { return "repair-write-probe" }
func (a *factoryFileRepair) Close() error { return nil }
func (a *factoryFileRepair) Run(context.Context, agent.RunOpts) (*agent.Result, error) {
	file, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	_, err = file.WriteString("repair\n")
	return &agent.Result{}, err
}

func TestFactoryMutationRequiresOneUsePrivateDispatch(t *testing.T) {
	root := t.TempDir()
	database, err := db.Open(filepath.Join(root, "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repo, err := database.InsertRepoWithID("factory-token", root, "https://example.invalid/repo", "main")
	if err != nil {
		t.Fatal(err)
	}
	run, err := database.InsertRunWithIntentAndLaunchNonce(repo.ID, "card", "head", "base", nil, "nonce", "generation", "digest", "", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = database.EnsureFactoryBudget(run); err != nil {
		t.Fatal(err)
	}
	step, err := database.InsertStepResult(run.ID, types.StepReview)
	if err != nil {
		t.Fatal(err)
	}
	repair, err := database.ReserveFactoryRepair(run.ID, step.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = database.ClaimFactoryRepairDispatch(repair.ID, run.ID, step.ID); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "written-repairs")
	sctx := &StepContext{DB: database, Run: run, Repo: repo, WorkDir: root, StepResultID: step.ID, FactoryRepairID: repair.ID}
	guarded := &factoryBoundaryAgent{inner: &factoryFileRepair{path: path}, step: sctx}
	opts := agent.RunOpts{FactoryControlled: true, FactoryMutation: true}
	if _, err = guarded.Run(context.Background(), opts); err == nil {
		t.Fatal("exported invocation flags authorized a source repair")
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("unadmitted source side effect: %v", err)
	}
	token := &factoryMutationToken{runID: run.ID, stepID: step.ID, repairID: repair.ID}
	ctx := context.WithValue(context.Background(), factoryMutationContextKey{}, token)
	if _, err = guarded.Run(ctx, opts); err != nil {
		t.Fatal(err)
	}
	if _, err = guarded.Run(ctx, opts); err == nil {
		t.Fatal("reused token dispatched a duplicate repair")
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != "repair\n" {
		t.Fatalf("unexpected source modifications: %q", actual)
	}
}
