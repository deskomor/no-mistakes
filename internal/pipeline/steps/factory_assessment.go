package steps

import (
	"encoding/json"
	"fmt"

	"github.com/kunchenguid/no-mistakes/internal/agent"
	"github.com/kunchenguid/no-mistakes/internal/pipeline"
	"github.com/kunchenguid/no-mistakes/internal/types"
)

func controlledAssessment(sctx *pipeline.StepContext) bool {
	return sctx.Config != nil && sctx.Config.ControlledExecution && (!sctx.Fixing || sctx.SkipFixExecution)
}

// Initial housekeeping is assessment, never an unmetered repair. Do not reuse
// the legacy edit-and-commit pass or silently skip its findings obligation.
func factoryAssessHousekeeping(sctx *pipeline.StepContext, step types.StepName) (*pipeline.StepOutcome, error) {
	if err := assertPipelineHeadContinuity(sctx, step); err != nil {
		return nil, err
	}
	duty := "Inspect documentation affected by the current change. Report required corrections to factually incorrect documentation, comments, and examples. Do not perform an exhaustive documentation sweep."
	if step == types.StepLint {
		duty = "Discover the project's linters and formatters and run relevant read-only checks on changed files. Report all required format, lint, or static-analysis changes. Never apply fixes and do not run tests."
	}
	prompt := fmt.Sprintf("Assess the %s duty for branch %s, base %s, target %s. %s Source, tests, setup and Git are read-only. Put any runtime output in the allowed scratch/evidence directories. Return required changes as structured findings with honest severity and action; unresolved uncertainty requires ask-user, routine corrections may be auto-fix. Return an empty findings list only when the duty is satisfied.%s", step, sctx.Run.Branch, sctx.Run.BaseSHA, sctx.Run.HeadSHA, duty, roundHistoryPromptSection(sctx)+userIntentPromptSection(sctx))
	if step == types.StepDocument && sctx.Config.Document.Instructions != "" {
		prompt += "\nRepository documentation instructions:\n" + sctx.Config.Document.Instructions
	}
	result, err := sctx.RunAgent(agent.RunOpts{Prompt: prompt, CWD: sctx.WorkDir, JSONSchema: findingsSchema, OnChunk: sctx.LogChunk, Purpose: string(step) + "-assessment"})
	if err != nil {
		return nil, err
	}
	if result == nil || result.Output == nil {
		return nil, fmt.Errorf("%s assessment returned no findings", step)
	}
	var findings Findings
	if err = unmarshalRequiredFindings(result.Output, &findings, true); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(findings)
	if err != nil {
		return nil, err
	}
	return &pipeline.StepOutcome{NeedsApproval: hasBlockingFindings(findings.Items), AutoFixable: false, Findings: string(encoded)}, nil
}
