package db

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/kunchenguid/no-mistakes/internal/types"
)

func TestFactoryGateDetailsPreservesFullFindingsAndReplacementIdentity(t *testing.T) {
	d := openTestDB(t)
	run, sr, q := factoryResponseFixture(t, d, "details")
	finding := types.Finding{ID: "exact-id", Severity: "warning", File: "src/main.go", Line: 42, Description: strings.Repeat("Full original description — ", 200) + "unique ending", Action: "ask-user", UserInstructions: "retain original instruction"}
	raw, err := json.Marshal(types.Findings{Items: []types.Finding{finding}, Summary: "original summary", RiskLevel: "high", RiskRationale: "original rationale", RiskScope: "source-or-external"})
	if err != nil {
		t.Fatal(err)
	}
	if err = d.SetStepFindings(sr.ID, string(raw)); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetFactoryGateDetails(run.ID)
	if err != nil || got == nil {
		t.Fatalf("details: %#v %v", got, err)
	}
	if got.Gate != q.ExpectedGate || !reflect.DeepEqual(got.Findings, []types.Finding{finding}) || got.Summary != "original summary" || got.Risk != "high" || got.RiskRationale != "original rationale" || got.RiskScope != "source-or-external" {
		t.Fatalf("identity/full findings changed: %#v", got)
	}
	// Replacing the park must not combine the old gate identity with new rows.
	next, err := d.InsertStepResult(run.ID, types.StepLint)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.ParkStepForApproval(run.ID, next.ID, types.StepStatusAwaitingApproval, 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err = d.SetStepFindings(next.ID, `{"findings":[{"id":"new-id","severity":"error","description":"next full finding","action":"auto-fix"}]}`); err != nil {
		t.Fatal(err)
	}
	gate, err := d.ParkFactoryGate(run.ID, next.ID, 2, "full-head")
	if err != nil {
		t.Fatal(err)
	}
	got, err = d.GetFactoryGateDetails(run.ID)
	if err != nil || got == nil || got.Gate != *gate || got.Gate == q.ExpectedGate || len(got.Findings) != 1 || got.Findings[0].ID != "new-id" || got.Findings[0].Action != "auto-fix" {
		t.Fatalf("replacement snapshot: %#v %v", got, err)
	}
	if _, _, err = d.ClaimFactoryResponse(q); err == nil {
		t.Fatal("details lookup made stale gate actionable")
	}
}

func TestFactoryGateDetailsFailsClosedForStaleAndMalformedState(t *testing.T) {
	for _, change := range []struct{ name, statement string }{
		{"moved-head", `UPDATE runs SET head_sha='different' WHERE id=?`},
		{"completed-run", `UPDATE runs SET status='completed' WHERE id=?`},
		{"claimed-gate", `UPDATE factory_gates SET state='claimed' WHERE run_id=?`},
		{"stopping", `UPDATE factory_response_fences SET stopping=1 WHERE run_id=?`},
		{"resumed-step", `UPDATE step_results SET status='running' WHERE run_id=?`},
		{"malformed-findings", `UPDATE step_results SET findings_json='not json' WHERE run_id=?`},
	} {
		t.Run(change.name, func(t *testing.T) {
			d := openTestDB(t)
			run, _, _ := factoryResponseFixture(t, d, change.name)
			if _, err := d.sql.Exec(change.statement, run.ID); err != nil {
				t.Fatal(err)
			}
			if got, err := d.GetFactoryGateDetails(run.ID); err == nil || got != nil {
				t.Fatalf("unsafe details returned: %#v %v", got, err)
			}
		})
	}
	d := openTestDB(t)
	if got, err := d.GetFactoryGateDetails("missing"); err != nil || got != nil {
		t.Fatalf("missing gate: %#v %v", got, err)
	}
}
