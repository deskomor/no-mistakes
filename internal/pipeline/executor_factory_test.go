package pipeline

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kunchenguid/no-mistakes/internal/agent"
	"github.com/kunchenguid/no-mistakes/internal/db"
	"github.com/kunchenguid/no-mistakes/internal/factorysandbox"
	"github.com/kunchenguid/no-mistakes/internal/git"
	"github.com/kunchenguid/no-mistakes/internal/ipc"
	"github.com/kunchenguid/no-mistakes/internal/types"
)

func controlledResponseExecutor(t *testing.T) (*Executor, db.FactoryResponseRequest) {
	t.Helper()
	database, p, _, _ := setupTest(t)
	dir := t.TempDir()
	initGitRepo(t, dir)
	head, err := git.HeadSHA(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := database.InsertRepo(dir, "https://example.com/controlled.git", "main")
	if err != nil {
		t.Fatal(err)
	}
	run, err := database.InsertRunWithIntentAndLaunchNonce(repo.ID, "controlled", head, "base", nil, "nonce", "generation", "digest", "", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = database.EnsureFactoryBudget(run); err != nil {
		t.Fatal(err)
	}
	if err = database.UpdateRunStatus(run.ID, types.RunRunning); err != nil {
		t.Fatal(err)
	}
	sr, err := database.InsertStepResult(run.ID, types.StepReview)
	if err != nil {
		t.Fatal(err)
	}
	findings := `{"findings":[{"id":"required-change","severity":"error","action":"ask-user","description":"Required correction"}]}`
	if err = database.ParkStepForApproval(run.ID, sr.ID, types.StepStatusAwaitingApproval, 0, 0, &findings); err != nil {
		t.Fatal(err)
	}
	gate, err := database.ParkFactoryGate(run.ID, sr.ID, 1, head)
	if err != nil {
		t.Fatal(err)
	}
	e := NewExecutor(database, p, nil, nil, nil, nil)
	if err = e.bindFactoryRun(run.ID); err != nil {
		t.Fatal(err)
	}
	e.workDir = dir
	e.waiting = true
	e.waitingStep = types.StepReview
	payload := db.FactoryResponsePayload{Step: types.StepReview, Action: types.ActionApprove}
	digest, err := db.FactoryPayloadDigest(payload)
	if err != nil {
		t.Fatal(err)
	}
	return e, db.FactoryResponseRequest{RunID: run.ID, ExpectedGate: *gate, OperationID: "operation", PayloadDigest: digest, Payload: payload}
}

func TestFactoryResponseConcurrentReplayQueuesOnce(t *testing.T) {
	e, q := controlledResponseExecutor(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := e.RespondFactory(q)
			if err != nil {
				t.Error(err)
				return
			}
			if r.OperationID != q.OperationID {
				t.Errorf("receipt=%#v", r)
			}
		}()
	}
	wg.Wait()
	if got := len(e.approvalCh); got != 1 {
		t.Fatalf("dispatch count=%d", got)
	}
	response := <-e.approvalCh
	if response.action != types.ActionApprove {
		t.Fatalf("action=%q", response.action)
	}
	e.completeFactoryOperation()
	if _, err := e.db.ParkFactoryGate(q.RunID, q.ExpectedGate.StepResultID, 2, q.ExpectedGate.HeadSHA); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RespondFactory(q); err != nil {
		t.Fatal(err)
	}
	if len(e.approvalCh) != 0 {
		t.Fatal("lost acknowledgement replay queued another action")
	}
}

func TestFactoryResponseControlledLegacyAndReconciliationCannotBypass(t *testing.T) {
	e, q := controlledResponseExecutor(t)
	if err := e.Respond(types.StepReview, types.ActionApprove, nil); err == nil {
		t.Fatal("legacy response released controlled gate")
	}
	if !e.waiting || len(e.approvalCh) != 0 {
		t.Fatal("legacy response changed gate")
	}
	if action, resume, err := e.resumeApprovalGate(context.Background(), nil, nil, ""); err != nil || resume || action != "" {
		t.Fatalf("resumer bypass: %q %v %v", action, resume, err)
	}
	if resolved, err := e.reconcileApprovalGate(context.Background(), nil, nil, ""); err != nil || resolved {
		t.Fatalf("reconcile bypass: %v %v", resolved, err)
	}
	if err := e.db.FenceFactoryRun(q.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RespondFactory(q); err == nil {
		t.Fatal("response dispatched after stop fence")
	}
	if !e.waiting || len(e.approvalCh) != 0 {
		t.Fatal("stop-first response changed gate")
	}
}

func TestFactoryResponseRefusesMovedWorktreeHead(t *testing.T) {
	e, q := controlledResponseExecutor(t)
	execGit(t, e.workDir, "commit", "--allow-empty", "-m", "move head")
	if _, err := e.RespondFactory(q); err == nil {
		t.Fatal("stale worktree head accepted")
	}
	if !e.waiting || len(e.approvalCh) != 0 {
		t.Fatal("stale response changed gate")
	}
}

func TestFactoryResponseInvalidPayloadDoesNotConsumeGate(t *testing.T) {
	e, q := controlledResponseExecutor(t)
	invalid := q
	invalid.Payload.Action = types.ActionFix
	invalid.Payload.FindingIDs = []string{"missing"}
	invalid.PayloadDigest, _ = db.FactoryPayloadDigest(invalid.Payload)
	if _, err := e.RespondFactory(invalid); err == nil {
		t.Fatal("unknown selected finding accepted")
	}
	receipt, err := e.db.GetFactoryResponseReceipt(q.RunID, q.OperationID)
	if err != nil || receipt != nil {
		t.Fatalf("invalid payload consumed operation: %#v %v", receipt, err)
	}
	gate, err := e.db.GetFactoryGate(q.RunID)
	if err != nil || gate.State != "parked" {
		t.Fatalf("invalid payload consumed gate: %#v %v", gate, err)
	}
	if _, err = e.RespondFactory(q); err != nil {
		t.Fatal(err)
	}
}

func TestFactoryResponseDirtyWorktreeDoesNotConsumeGate(t *testing.T) {
	e, q := controlledResponseExecutor(t)
	writeTestFile(t, e.workDir, "unexpected.txt", "untracked modification")
	if _, err := e.RespondFactory(q); err == nil {
		t.Fatal("dirty worktree response accepted")
	}
	receipt, err := e.db.GetFactoryResponseReceipt(q.RunID, q.OperationID)
	if err != nil || receipt != nil {
		t.Fatalf("dirty response consumed operation: %#v %v", receipt, err)
	}
	if !e.waiting || len(e.approvalCh) != 0 {
		t.Fatal("dirty response changed gate")
	}
}

func TestFactoryResumeRestoresRepairBudgetApprovalRefusal(t *testing.T) {
	if err := factorysandbox.Supported(); err != nil {
		t.Skip(err)
	}
	database, p, _, _ := setupTest(t)
	source := t.TempDir()
	initGitRepo(t, source)
	head, err := git.HeadSHA(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := database.InsertRepo(source, "https://example.com/recovered-budget.git", "main")
	if err != nil {
		t.Fatal(err)
	}
	run, err := database.InsertRunWithIntentAndLaunchNonce(repo.ID, "controlled", head, "base", nil, "resume-nonce", "resume-generation", "digest", "", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	gateDir := p.RepoDir(repo.ID)
	execGit(t, source, "init", "--bare", gateDir)
	execGit(t, source, "push", gateDir, "HEAD:refs/heads/controlled")
	workDir := p.WorktreeDir(repo.ID, run.ID)
	if err := git.WorktreeAdd(context.Background(), gateDir, workDir, head); err != nil {
		t.Fatal(err)
	}
	if err := database.EnsureFactoryBudget(run); err != nil {
		t.Fatal(err)
	}
	if err := database.UpdateRunStatus(run.ID, types.RunRunning); err != nil {
		t.Fatal(err)
	}
	step, err := database.InsertStepResult(run.ID, types.StepReview)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.StartStep(step.ID); err != nil {
		t.Fatal(err)
	}
	// Exhaust the real durable allowance, then persist the same outcome that
	// the executor parks when its next repair admission is refused.
	for round := 1; round <= 3; round++ {
		repair, err := database.ReserveFactoryRepair(run.ID, step.ID, round)
		if err != nil {
			t.Fatal(err)
		}
		if err := database.ClaimFactoryRepairDispatch(repair.ID, run.ID, step.ID); err != nil {
			t.Fatal(err)
		}
	}
	_, budgetErr := database.ReserveFactoryRepair(run.ID, step.ID, 4)
	if !errors.Is(budgetErr, db.ErrFactoryBudgetExhausted) {
		t.Fatalf("fourth repair admission = %v, want exhausted budget", budgetErr)
	}
	outcome := factoryBudgetOutcome(budgetErr)
	if _, err := database.InsertStepRound(step.ID, 4, "fix", &outcome.Findings, nil, 25); err != nil {
		t.Fatal(err)
	}
	if err := database.ParkStepForApproval(run.ID, step.ID, types.StepStatusAwaitingApproval, outcome.ExitCode, 25, &outcome.Findings); err != nil {
		t.Fatal(err)
	}
	gate, err := database.ParkFactoryGate(run.ID, step.ID, 4, head)
	if err != nil {
		t.Fatal(err)
	}
	downstream, err := database.InsertStepResult(run.ID, types.StepTest)
	if err != nil {
		t.Fatal(err)
	}
	run, err = database.GetRun(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Recovery never invokes the adapter: a missing executable makes an
	// accidental assessment/repair dispatch fail rather than launch a real agent.
	adapter, err := agent.New(types.AgentName("acp:omp"), filepath.Join(t.TempDir(), "must-not-run-acpx"), nil)
	if err != nil {
		t.Fatal(err)
	}
	parkedStep := newPassStep(types.StepReview)
	nextStep := newPassStep(types.StepTest)
	parked := make(chan struct{}, 1)
	executor := NewExecutor(database, p, nil, adapter, []Step{parkedStep, nextStep}, func(event ipc.Event) {
		if event.Type == ipc.EventStepCompleted && event.Status != nil && *event.Status == string(types.StepStatusAwaitingApproval) {
			parked <- struct{}{}
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("resumed executor did not stop after cancellation")
		}
	})
	if err := executor.Respond(types.StepReview, types.ActionApprove, nil); err == nil {
		t.Fatal("legacy response accepted before recovery bound its run")
	}
	go func() { done <- executor.Resume(ctx, run, repo, workDir) }()
	select {
	case <-parked:
	case err := <-done:
		done <- err
		t.Fatalf("Resume returned before restoring its gate: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Resume did not restore its gate")
	}
	if err := executor.Respond(types.StepReview, types.ActionApprove, nil); err == nil {
		t.Fatal("legacy response released the restored controlled gate")
	}
	payload := db.FactoryResponsePayload{Step: types.StepReview, Action: types.ActionApprove}
	digest, err := db.FactoryPayloadDigest(payload)
	if err != nil {
		t.Fatal(err)
	}
	request := db.FactoryResponseRequest{RunID: run.ID, ExpectedGate: *gate, OperationID: "approve-exhausted-recovery", PayloadDigest: digest, Payload: payload}
	if receipt, err := executor.RespondFactory(request); err == nil || !strings.Contains(err.Error(), db.ErrFactoryBudgetExhausted.Error()) || !strings.Contains(err.Error(), "stop and reconcile") || receipt != nil {
		t.Fatalf("strict approve must refuse the recovered budget gate before admission: receipt=%+v err=%v", receipt, err)
	}
	if receipt, err := database.GetFactoryResponseReceipt(run.ID, request.OperationID); err != nil || receipt != nil {
		t.Fatalf("refusal created an operation receipt: receipt=%+v err=%v", receipt, err)
	}
	if storedGate, err := database.GetFactoryGate(run.ID); err != nil || storedGate == nil || *storedGate != *gate {
		t.Fatalf("refusal changed the parked exact gate: gate=%+v err=%v", storedGate, err)
	}
	executor.mu.Lock()
	waiting, waitingStep, queued := executor.waiting, executor.waitingStep, len(executor.approvalCh)
	executor.mu.Unlock()
	if !waiting || waitingStep != types.StepReview || queued != 0 {
		t.Fatalf("refusal released or enqueued the gate: waiting=%v step=%s queued=%d", waiting, waitingStep, queued)
	}
	if storedRun, err := database.GetRun(run.ID); err != nil || storedRun.Status != types.RunRunning || storedRun.AwaitingAgentSince == nil {
		t.Fatalf("run no longer parked: run=%+v err=%v", storedRun, err)
	}
	if storedStep, err := database.GetStepResult(step.ID); err != nil || storedStep.Status != types.StepStatusAwaitingApproval {
		t.Fatalf("recovered step no longer parked: step=%+v err=%v", storedStep, err)
	}
	if storedStep, err := database.GetStepResult(downstream.ID); err != nil || storedStep.Status != types.StepStatusPending {
		t.Fatalf("downstream step advanced: step=%+v err=%v", storedStep, err)
	}
	if parkedStep.callCount() != 0 || nextStep.callCount() != 0 {
		t.Fatal("recovery or refused approval executed a pipeline step")
	}
	if used, err := database.GetFactoryBudget(run.ID); err != nil || used != 3 {
		t.Fatalf("recovery changed exhausted budget: used=%d err=%v", used, err)
	}
}

func TestFactoryFixRequiresExplicitExistingFindingSelection(t *testing.T) {
	e, request := controlledResponseExecutor(t)
	request.Payload.Action = types.ActionFix
	request.PayloadDigest, _ = db.FactoryPayloadDigest(request.Payload)
	if _, err := e.RespondFactory(request); err == nil {
		t.Fatal("ambiguous whole-gate fix consumed the selected-finding decision")
	}
	if receipt, err := e.db.GetFactoryResponseReceipt(request.RunID, request.OperationID); err != nil || receipt != nil {
		t.Fatalf("ambiguous fix consumed its operation: %#v %v", receipt, err)
	}
	if gate, err := e.db.GetFactoryGate(request.RunID); err != nil || gate == nil || *gate != request.ExpectedGate {
		t.Fatalf("ambiguous fix changed its gate: %#v %v", gate, err)
	}
	request.Payload.FindingIDs = []string{"required-change"}
	request.PayloadDigest, _ = db.FactoryPayloadDigest(request.Payload)
	if _, err := e.RespondFactory(request); err != nil {
		t.Fatal(err)
	}
	if e.waiting || len(e.approvalCh) != 1 {
		t.Fatal("explicit selected repair did not consume exactly one parked decision")
	}
}
