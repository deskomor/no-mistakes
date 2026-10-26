package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/kunchenguid/no-mistakes/internal/db"
	"github.com/kunchenguid/no-mistakes/internal/factorysandbox"
	"github.com/kunchenguid/no-mistakes/internal/git"
	"github.com/kunchenguid/no-mistakes/internal/types"
)

// Execute/Resume bind a fresh executor before publishing any waiting gate.
// Response eligibility and binding share mu, so a pre-bind legacy response can
// see only "not waiting", never a restored gate with an unresolved mode.
func (e *Executor) bindFactoryRun(runID string) error {
	controlled, err := e.db.IsFactoryControlledRun(runID)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.factoryRunID = runID
	e.factoryControlled = controlled
	e.mu.Unlock()
	return nil
}

func (e *Executor) completeFactoryOperation() {
	e.mu.Lock()
	op := e.factoryOperation
	runID := e.factoryRunID
	e.factoryOperation = ""
	e.mu.Unlock()
	if op != "" {
		if err := e.db.CompleteFactoryResponse(runID, op); err != nil {
			slog.Error("complete controlled response receipt", "run", runID, "operation", op, "error", err)
		}
	}
}

// RespondFactory admits an immutable request and queues it at most once. A
// receipt marks dispatch completion, not exactly-once external side effects.
func (e *Executor) RespondFactory(q db.FactoryResponseRequest) (*db.FactoryResponseReceipt, error) {
	// Durable replay precedes in-memory gate validation, including terminal runs.
	existing, err := e.db.GetFactoryResponseReceipt(q.RunID, q.OperationID)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		r, _, err := e.db.ClaimFactoryResponse(q)
		return r, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	existing, err = e.db.GetFactoryResponseReceipt(q.RunID, q.OperationID)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		r, _, claimErr := e.db.ClaimFactoryResponse(q)
		return r, claimErr
	}
	if !e.factoryControlled || q.RunID != e.factoryRunID {
		return nil, fmt.Errorf("run is not this controlled executor")
	}
	p := q.Payload
	if !e.waiting || p.Step != e.waitingStep {
		return nil, fmt.Errorf("no matching gate awaiting response")
	}
	switch p.Action {
	case types.ActionApprove, types.ActionFix, types.ActionSkip, types.ActionAbort:
	default:
		return nil, fmt.Errorf("unsupported strict response action %q", p.Action)
	}
	if p.ApprovalReason != "" && (p.Step != types.StepTest || p.Action != types.ActionApprove) {
		return nil, fmt.Errorf("approval reason applies only to Test approval")
	}
	if p.Action == types.ActionApprove && e.waitingApprovalRefusal != "" {
		return nil, fmt.Errorf("%s", e.waitingApprovalRefusal)
	}
	if p.Action != types.ActionFix && (len(p.FindingIDs) > 0 || len(p.Instructions) > 0 || len(p.AddedFindings) > 0) {
		return nil, fmt.Errorf("finding selection and overrides apply only to fix")
	}
	sr, err := e.db.GetStepResult(q.ExpectedGate.StepResultID)
	if err != nil {
		return nil, err
	}
	if sr == nil || sr.RunID != q.RunID {
		return nil, fmt.Errorf("step result does not belong to run")
	}
	known := map[string]bool{}
	if sr.FindingsJSON != nil && *sr.FindingsJSON != "" {
		findings, parseErr := types.ParseFindingsJSON(*sr.FindingsJSON)
		if parseErr != nil {
			return nil, parseErr
		}
		for _, f := range findings.Items {
			known[f.ID] = true
		}
	}
	if p.Action == types.ActionFix && len(known) > 0 && len(p.FindingIDs) == 0 {
		return nil, fmt.Errorf("controlled fixes require explicit finding_ids for existing findings")
	}
	selected := map[string]bool{}
	for _, id := range p.FindingIDs {
		if !known[id] || selected[id] {
			return nil, fmt.Errorf("unknown or duplicate finding id %q", id)
		}
		selected[id] = true
	}
	for id := range p.Instructions {
		if !known[id] {
			return nil, fmt.Errorf("instruction targets unknown finding %q", id)
		}
	}
	for _, f := range p.AddedFindings {
		if f.Description == "" || (f.Severity != "" && !types.IsKnownFindingSeverity(f.Severity)) {
			return nil, fmt.Errorf("invalid user finding")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = factorysandbox.WithPolicy(ctx, e.runEvidenceDir(q.RunID), []string{e.workDir})
	head, err := git.HeadSHA(ctx, e.workDir)
	if err != nil {
		return nil, err
	}
	if head != q.ExpectedGate.HeadSHA {
		return nil, fmt.Errorf("worktree head changed since gate parked")
	}
	dirty, err := git.Run(ctx, e.workDir, "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return nil, err
	}
	if dirty != "" {
		return nil, fmt.Errorf("controlled response requires a clean worktree; inspect unexpected modifications before replacing the run")
	}
	r, admitted, err := e.db.ClaimFactoryResponse(q)
	if err != nil || !admitted {
		return r, err
	}
	// Persist started BEFORE enqueue; a crash in this gap is deliberately uncertain.
	if err = e.db.StartFactoryResponse(q.RunID, q.OperationID); err != nil {
		return nil, err
	}
	e.factoryOperation = q.OperationID
	e.waiting = false
	e.approvalCh <- approvalResponse{action: p.Action, findingIDs: p.FindingIDs, instructions: p.Instructions, addedFindings: p.AddedFindings, approvalReason: p.ApprovalReason}
	r.State = "started"
	return r, nil
}
