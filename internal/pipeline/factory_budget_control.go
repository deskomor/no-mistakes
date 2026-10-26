package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/kunchenguid/no-mistakes/internal/agent"
	"github.com/kunchenguid/no-mistakes/internal/config"
	"github.com/kunchenguid/no-mistakes/internal/db"
	"github.com/kunchenguid/no-mistakes/internal/factorysandbox"
	"github.com/kunchenguid/no-mistakes/internal/types"
)

// Enrollment is durable: changing the live global switch cannot restore legacy
// write capability to a run that already belongs to a controlled generation.
func (e *Executor) enrollFactoryRun(run *db.Run) error {
	enrolled, err := e.db.IsFactoryControlledRun(run.ID)
	if err != nil {
		return err
	}
	requested := e.config != nil && e.config.ControlledExecution
	if !enrolled && !requested {
		return nil
	}
	if e.config == nil {
		e.config = &config.Config{}
	}
	effective := *e.config
	effective.ControlledExecution = true
	if effective.Review.Conversation {
		return errors.New("controlled execution requires review.conversation: false; use ask-user findings and exact-gate responses instead of unbound review answers")
	}
	if err := agent.EnsureFactoryControlled(e.agent); err != nil {
		return err
	}
	if err := e.db.EnsureFactoryBudget(run); err != nil {
		return err
	}
	e.config = &effective
	return nil
}

func (e *Executor) factoryGitContext(ctx context.Context, runID string, repo *db.Repo, workDir string) (context.Context, error) {
	roots, err := factorysandbox.IncludeLocalMirrors([]string{workDir, e.paths.RepoDir(repo.ID), repo.WorkingPath}, repo.UpstreamURL, repo.ForkURL)
	if err != nil {
		return nil, err
	}
	return factorysandbox.WithPolicy(ctx, e.runEvidenceDir(runID), roots), nil
}

type factoryMutationContextKey struct{}

type factoryMutationToken struct {
	runID    string
	stepID   string
	repairID string
	consumed atomic.Bool
}

// A direct Step.Agent.Run call is assessment by default too. Only the shared
// StepContext invocation seam may mark an explicitly admitted repair invocation.
// The adapter still enforces the filesystem capability below every shell child.
type factoryBoundaryAgent struct {
	inner agent.Agent
	step  *StepContext
}

func (a *factoryBoundaryAgent) Name() string { return a.inner.Name() }
func (a *factoryBoundaryAgent) Close() error { return a.inner.Close() }
func (a *factoryBoundaryAgent) Run(ctx context.Context, opts agent.RunOpts) (*agent.Result, error) {
	if opts.FactoryMutation {
		token, _ := ctx.Value(factoryMutationContextKey{}).(*factoryMutationToken)
		if !opts.FactoryControlled || token == nil || token.runID != a.step.Run.ID || token.stepID != a.step.StepResultID || token.repairID != a.step.FactoryRepairID || !token.consumed.CompareAndSwap(false, true) {
			return nil, errors.New("mutation invocation requires an unused private dispatch authorization")
		}
		if err := a.step.DB.ValidateFactoryRepair(a.step.FactoryRepairID, a.step.Run.ID, a.step.StepResultID); err != nil {
			return nil, err
		}
	}
	opts.FactoryControlled = true
	opts.FactoryEvidenceDir = a.step.EvidenceDir
	opts.FactoryProtectedPaths = []string{a.step.WorkDir, a.step.GateDir, a.step.Repo.WorkingPath}
	return a.inner.Run(ctx, opts)
}

const factoryBudgetFindingID = "factory-repair-budget-exhausted"

func factoryBudgetOutcome(err error) *StepOutcome {
	findings := struct {
		Findings []types.Finding `json:"findings"`
		Summary  string          `json:"summary"`
	}{
		Findings: []types.Finding{{ID: factoryBudgetFindingID, Severity: types.FindingSeverityError, Action: types.ActionAskUser, Description: err.Error()}},
		Summary:  "Repair not dispatched: controlled repair budget unavailable",
	}
	encoded, _ := json.Marshal(findings)
	return &StepOutcome{NeedsApproval: true, Findings: string(encoded)}
}

func factoryBudgetApprovalRefusal(findings string) string {
	var parsed struct {
		Findings []types.Finding `json:"findings"`
	}
	if json.Unmarshal([]byte(findings), &parsed) != nil {
		return ""
	}
	for _, finding := range parsed.Findings {
		if finding.ID == factoryBudgetFindingID {
			return fmt.Sprintf("%s; no validation or repair was dispatched: stop and reconcile this controlled execution", finding.Description)
		}
	}
	return ""
}
