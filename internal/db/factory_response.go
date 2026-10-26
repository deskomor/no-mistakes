package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/kunchenguid/no-mistakes/internal/types"
)

const factoryResponseSchema = `
CREATE TABLE IF NOT EXISTS factory_response_fences (run_id TEXT PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE, stopping INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS factory_gates (
 run_id TEXT PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE, gate_id TEXT NOT NULL, step_result_id TEXT NOT NULL REFERENCES step_results(id) ON DELETE CASCADE,
 round INTEGER NOT NULL, generation INTEGER NOT NULL, head_sha TEXT NOT NULL, state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS factory_responses (
 run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE, operation_id TEXT NOT NULL, digest TEXT NOT NULL, gate_json TEXT NOT NULL,
 state TEXT NOT NULL, accepted_at INTEGER NOT NULL, PRIMARY KEY(run_id,operation_id));
`

// FactoryGate identifies one material park, not merely a step name.
type FactoryGate struct {
	RunID        string `json:"run_id"`
	GateID       string `json:"gate_id"`
	StepResultID string `json:"step_result_id"`
	Round        int    `json:"round"`
	Generation   int    `json:"generation"`
	HeadSHA      string `json:"head_sha"`
	State        string `json:"state"`
}

type FactoryResponsePayload struct {
	Step           types.StepName       `json:"step"`
	Action         types.ApprovalAction `json:"action"`
	FindingIDs     []string             `json:"finding_ids,omitempty"`
	Instructions   map[string]string    `json:"instructions,omitempty"`
	AddedFindings  []types.Finding      `json:"added_findings,omitempty"`
	ApprovalReason string               `json:"approval_reason,omitempty"`
}

type FactoryResponseRequest struct {
	RunID         string                 `json:"run_id"`
	ExpectedGate  FactoryGate            `json:"expected_gate"`
	OperationID   string                 `json:"operation_id"`
	PayloadDigest string                 `json:"payload_digest"`
	Payload       FactoryResponsePayload `json:"payload"`
}

type FactoryResponseReceipt struct {
	RunID         string      `json:"run_id"`
	OperationID   string      `json:"operation_id"`
	PayloadDigest string      `json:"payload_digest"`
	Gate          FactoryGate `json:"gate"`
	State         string      `json:"state"`
	AcceptedAt    int64       `json:"accepted_at"`
}

func FactoryPayloadDigest(p FactoryResponsePayload) (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func scanFactoryGate(row interface{ Scan(...any) error }) (*FactoryGate, error) {
	g := &FactoryGate{}
	err := row.Scan(&g.RunID, &g.GateID, &g.StepResultID, &g.Round, &g.Generation, &g.HeadSHA, &g.State)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return g, err
}

func (d *DB) GetFactoryGate(runID string) (*FactoryGate, error) {
	return scanFactoryGate(d.sql.QueryRow(`SELECT run_id,gate_id,step_result_id,round,generation,head_sha,state FROM factory_gates WHERE run_id=?`, runID))
}

// FactoryGateDetails is one SQLite snapshot of the strict gate and its original
// structured findings. The compact AXI display is not an authorization source.
type FactoryGateDetails struct {
	Gate          FactoryGate     `json:"gate"`
	Findings      []types.Finding `json:"findings"`
	Summary       string          `json:"summary,omitempty"`
	Risk          string          `json:"risk,omitempty"`
	RiskRationale string          `json:"risk_rationale,omitempty"`
	RiskScope     string          `json:"risk_scope,omitempty"`
}

func (d *DB) GetFactoryGateDetails(runID string) (*FactoryGateDetails, error) {
	v := &FactoryGateDetails{Findings: []types.Finding{}}
	var raw sql.NullString
	var head, runStatus, stepStatus string
	var stopping int
	// One joined statement binds all fields to the same read snapshot, including
	// when another connection replaces the park or advances the run concurrently.
	err := d.sql.QueryRow(`SELECT g.run_id,g.gate_id,g.step_result_id,g.round,g.generation,g.head_sha,g.state,
		s.findings_json,COALESCE(r.head_sha,''),COALESCE(r.status,''),COALESCE(s.status,''),COALESCE(f.stopping,1)
		FROM factory_gates g
		LEFT JOIN runs r ON r.id=g.run_id
		LEFT JOIN step_results s ON s.id=g.step_result_id AND s.run_id=g.run_id
		LEFT JOIN factory_response_fences f ON f.run_id=g.run_id
		WHERE g.run_id=?`, runID).Scan(&v.Gate.RunID, &v.Gate.GateID, &v.Gate.StepResultID,
		&v.Gate.Round, &v.Gate.Generation, &v.Gate.HeadSHA, &v.Gate.State, &raw,
		&head, &runStatus, &stepStatus, &stopping)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if v.Gate.State != "parked" || head != v.Gate.HeadSHA || runStatus != "running" ||
		stepStatus != string(types.StepStatusAwaitingApproval) || stopping != 0 {
		return nil, fmt.Errorf("stale or unavailable gate details")
	}
	if raw.Valid && raw.String != "" {
		findings, err := types.ParseFindingsJSON(raw.String)
		if err != nil {
			return nil, fmt.Errorf("invalid gate findings: %w", err)
		}
		if findings.Items != nil {
			v.Findings = findings.Items
		}
		v.Summary = findings.Summary
		v.Risk = findings.RiskLevel
		v.RiskRationale = findings.RiskRationale
		v.RiskScope = findings.RiskScope
	}
	return v, nil
}

// ParkFactoryGate always increments the durable generation. Recovery reads the
// existing park instead; it must never manufacture a fresh authorization.
func (d *DB) ParkFactoryGate(runID, stepID string, round int, head string) (*FactoryGate, error) {
	if head == "" {
		return nil, fmt.Errorf("controlled gate requires full head")
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`INSERT INTO factory_response_fences(run_id) VALUES(?) ON CONFLICT DO NOTHING`, runID); err != nil {
		return nil, err
	}
	var stopping int
	if err = tx.QueryRow(`SELECT stopping FROM factory_response_fences WHERE run_id=?`, runID).Scan(&stopping); err != nil {
		return nil, err
	}
	if stopping != 0 {
		return nil, fmt.Errorf("run is stopping")
	}
	g := &FactoryGate{RunID: runID, GateID: newID(), StepResultID: stepID, Round: round, HeadSHA: head, State: "parked"}
	_, err = tx.Exec(`INSERT INTO factory_gates(run_id,gate_id,step_result_id,round,generation,head_sha,state) VALUES(?,?,?,?,1,?,'parked') ON CONFLICT(run_id) DO UPDATE SET gate_id=excluded.gate_id,step_result_id=excluded.step_result_id,round=excluded.round,generation=generation+1,head_sha=excluded.head_sha,state='parked'`, runID, g.GateID, stepID, round, head)
	if err != nil {
		return nil, err
	}
	if err = tx.QueryRow(`SELECT generation FROM factory_gates WHERE run_id=?`, runID).Scan(&g.Generation); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return g, nil
}

func scanFactoryReceipt(row interface{ Scan(...any) error }) (*FactoryResponseReceipt, error) {
	r := &FactoryResponseReceipt{}
	var gate string
	err := row.Scan(&r.RunID, &r.OperationID, &r.PayloadDigest, &gate, &r.State, &r.AcceptedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(gate), &r.Gate)
	return r, err
}
func (d *DB) GetFactoryResponseReceipt(runID, operationID string) (*FactoryResponseReceipt, error) {
	return scanFactoryReceipt(d.sql.QueryRow(`SELECT run_id,operation_id,digest,gate_json,state,accepted_at FROM factory_responses WHERE run_id=? AND operation_id=?`, runID, operationID))
}

// ClaimFactoryResponse durably admits once. A retry is checked BEFORE current
// gate/liveness: a lost acknowledgement remains recoverable after gate movement.
func (d *DB) ClaimFactoryResponse(q FactoryResponseRequest) (*FactoryResponseReceipt, bool, error) {
	controlled, controlErr := d.IsFactoryControlledRun(q.RunID)
	if controlErr != nil {
		return nil, false, controlErr
	}
	if !controlled {
		return nil, false, fmt.Errorf("strict response requires controlled run")
	}
	digest, err := FactoryPayloadDigest(q.Payload)
	if err != nil {
		return nil, false, err
	}
	if q.OperationID == "" || q.RunID == "" || q.ExpectedGate.RunID != q.RunID || digest != q.PayloadDigest {
		return nil, false, fmt.Errorf("invalid response identity or payload digest")
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	r, err := scanFactoryReceipt(tx.QueryRow(`SELECT run_id,operation_id,digest,gate_json,state,accepted_at FROM factory_responses WHERE run_id=? AND operation_id=?`, q.RunID, q.OperationID))
	if err != nil {
		return nil, false, err
	}
	if r != nil {
		if r.PayloadDigest != digest || r.Gate != q.ExpectedGate {
			return nil, false, fmt.Errorf("operation id already bound to a different response")
		}
		return r, false, nil
	}
	var status string
	var stopping int
	if err = tx.QueryRow(`SELECT r.status,f.stopping FROM runs r JOIN factory_response_fences f ON f.run_id=r.id WHERE r.id=?`, q.RunID).Scan(&status, &stopping); err != nil {
		return nil, false, err
	}
	if status != "running" || stopping != 0 {
		return nil, false, fmt.Errorf("run is not active or is stopping")
	}
	g, err := scanFactoryGate(tx.QueryRow(`SELECT run_id,gate_id,step_result_id,round,generation,head_sha,state FROM factory_gates WHERE run_id=?`, q.RunID))
	if err != nil {
		return nil, false, err
	}
	if g == nil || *g != q.ExpectedGate || g.State != "parked" {
		return nil, false, fmt.Errorf("stale or unavailable gate")
	}
	var head, step string
	if err = tx.QueryRow(`SELECT r.head_sha,s.step_name FROM runs r JOIN step_results s ON s.run_id=r.id WHERE r.id=? AND s.id=?`, q.RunID, g.StepResultID).Scan(&head, &step); err != nil {
		return nil, false, err
	}
	if head != g.HeadSHA || step != string(q.Payload.Step) {
		return nil, false, fmt.Errorf("gate head or step changed")
	}
	b, err := json.Marshal(g)
	if err != nil {
		return nil, false, err
	}
	r = &FactoryResponseReceipt{RunID: q.RunID, OperationID: q.OperationID, PayloadDigest: digest, Gate: *g, State: "accepted", AcceptedAt: now()}
	if _, err = tx.Exec(`INSERT INTO factory_responses VALUES(?,?,?,?,?,?)`, r.RunID, r.OperationID, digest, string(b), r.State, r.AcceptedAt); err != nil {
		return nil, false, err
	}
	if _, err = tx.Exec(`UPDATE factory_gates SET state='claimed' WHERE run_id=?`, q.RunID); err != nil {
		return nil, false, err
	}
	if err = tx.Commit(); err != nil {
		return nil, false, err
	}
	return r, true, nil
}

// Start is a conditional transition, never a replay permission. Stop shares the
// same transaction ordering; stop-first cannot launch admitted but unstarted work.
func (d *DB) StartFactoryResponse(runID, operationID string) error {
	result, err := d.sql.Exec(`UPDATE factory_responses SET state='started' WHERE run_id=? AND operation_id=? AND state='accepted' AND EXISTS(SELECT 1 FROM factory_response_fences f JOIN runs r ON r.id=f.run_id WHERE f.run_id=? AND f.stopping=0 AND r.status='running')`, runID, operationID, runID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("response cannot start (stopped or already dispatched)")
	}
	return nil
}
func (d *DB) CompleteFactoryResponse(runID, operationID string) error {
	_, err := d.sql.Exec(`UPDATE factory_responses SET state='completed' WHERE run_id=? AND operation_id=? AND state='started'`, runID, operationID)
	return err
}
func (d *DB) FenceFactoryRun(runID string) error {
	_, err := d.sql.Exec(`INSERT INTO factory_response_fences(run_id,stopping) VALUES(?,1) ON CONFLICT(run_id) DO UPDATE SET stopping=1`, runID)
	return err
}

// Recovery does not re-enqueue either accepted or started requests: a process
// death can hide dispatch. The old receipt survives as explicit uncertainty.
func (d *DB) RecoverFactoryResponses() error {
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE factory_gates SET state='uncertain' WHERE run_id IN (SELECT run_id FROM factory_responses WHERE state IN ('accepted','started'))`); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE factory_responses SET state='uncertain' WHERE state IN ('accepted','started')`); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE runs SET awaiting_agent_since=COALESCE(awaiting_agent_since,?),updated_at=? WHERE status='running' AND id IN (SELECT run_id FROM factory_responses WHERE state='uncertain')`, now(), now()); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE step_results SET status='awaiting_approval' WHERE id IN (SELECT g.step_result_id FROM factory_gates g JOIN runs r ON r.id=g.run_id WHERE g.state='uncertain' AND r.status='running')`); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) FactoryUncertainRunIDs() ([]string, error) {
	rows, err := d.sql.Query(`SELECT DISTINCT r.id FROM runs r JOIN factory_responses f ON f.run_id=r.id WHERE r.status='running' AND f.state='uncertain'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
