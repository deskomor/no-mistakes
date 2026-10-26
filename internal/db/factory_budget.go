package db

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// factoryBudgetSchema is installed by Open together with the ordinary schema.
const factoryBudgetSchema = `
CREATE TABLE IF NOT EXISTS factory_budget_generations (
 repo TEXT NOT NULL, branch TEXT NOT NULL, generation TEXT NOT NULL,
 used INTEGER NOT NULL DEFAULT 0 CHECK(used BETWEEN 0 AND 3),
 PRIMARY KEY(repo,branch,generation)
);
CREATE TABLE IF NOT EXISTS factory_budget_runs (
 run_id TEXT PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE, repo TEXT NOT NULL,
 branch TEXT NOT NULL, generation TEXT NOT NULL,
 FOREIGN KEY(repo,branch,generation) REFERENCES factory_budget_generations(repo,branch,generation)
);
CREATE TABLE IF NOT EXISTS factory_repairs (
 id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES factory_budget_runs(run_id) ON DELETE CASCADE,
 step_result_id TEXT NOT NULL, round INTEGER NOT NULL, ordinal INTEGER NOT NULL,
 dispatched INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
 UNIQUE(run_id,step_result_id,round)
);`

var ErrFactoryBudgetExhausted = errors.New("controlled repair budget exhausted (maximum three passes per validation generation)")
var ErrFactoryRepairDispatched = errors.New("controlled repair already admitted; interrupted or uncertain work must not be replayed")

type FactoryRepair struct {
	ID      string
	Ordinal int
}

func validFactoryIdentity(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range []byte(value) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~') {
			return false
		}
	}
	return true
}

// EnsureFactoryBudget enrolls a strict launch. Canonical checkout identity, not
// a replaceable run ID, owns the allowance. There is intentionally no refund API.
func (d *DB) EnsureFactoryBudget(run *Run) error {
	if run == nil || run.LaunchValidationGeneration == nil || strings.TrimSpace(*run.LaunchValidationGeneration) == "" || run.LaunchNonce == nil || strings.TrimSpace(*run.LaunchNonce) == "" || run.Branch == "" {
		return errors.New("controlled execution requires a strict launch nonce and validation generation")
	}
	if !validFactoryIdentity(*run.LaunchValidationGeneration) || !validFactoryIdentity(*run.LaunchNonce) {
		return errors.New("controlled launch identities must be 1..128 ASCII identifier characters")
	}
	stored, err := d.GetRun(run.ID)
	if err != nil {
		return err
	}
	if stored.RepoID != run.RepoID || stored.Branch != run.Branch || stored.LaunchNonce == nil || stored.LaunchValidationGeneration == nil || *stored.LaunchNonce != *run.LaunchNonce || *stored.LaunchValidationGeneration != *run.LaunchValidationGeneration {
		return errors.New("controlled launch identity does not match its durable run")
	}
	var path string
	if err := d.sql.QueryRow(`SELECT working_path FROM repos WHERE id=?`, run.RepoID).Scan(&path); err != nil {
		return err
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("canonical controlled repository: %w", err)
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return err
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`INSERT INTO factory_budget_generations(repo,branch,generation) VALUES(?,?,?) ON CONFLICT DO NOTHING`, canonical, run.Branch, *run.LaunchValidationGeneration); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO factory_budget_runs(run_id,repo,branch,generation) VALUES(?,?,?,?) ON CONFLICT DO NOTHING`, run.ID, canonical, run.Branch, *run.LaunchValidationGeneration); err != nil {
		return err
	}
	var actualRepo, actualBranch, actualGeneration string
	if err = tx.QueryRow(`SELECT repo,branch,generation FROM factory_budget_runs WHERE run_id=?`, run.ID).Scan(&actualRepo, &actualBranch, &actualGeneration); err != nil {
		return err
	}
	if actualRepo != canonical || actualBranch != run.Branch || actualGeneration != *run.LaunchValidationGeneration {
		return errors.New("controlled run enrollment identity changed")
	}
	return tx.Commit()
}

func (d *DB) IsFactoryControlledRun(runID string) (bool, error) {
	var exists bool
	err := d.sql.QueryRow(`SELECT EXISTS(SELECT 1 FROM factory_budget_runs WHERE run_id=?)`, runID).Scan(&exists)
	return exists, err
}

// FactoryControlledRepoRunID finds durable enrollment before a caller can
// safely inspect Git metadata. Enrollment protects the whole checkout, even
// after its run terminates or the current opt-in setting is disabled.
func (d *DB) FactoryControlledRepoRunID(repoID string) (string, error) {
	var runID string
	err := d.sql.QueryRow(`SELECT COALESCE(MIN(f.run_id), '') FROM factory_budget_runs f JOIN runs r ON r.id=f.run_id WHERE r.repo_id=?`, repoID).Scan(&runID)
	return runID, err
}

// ReserveFactoryRepair atomically consumes one pass. Re-entering the same
// round is uncertain execution, never a new invitation to dispatch it again.
func (d *DB) ReserveFactoryRepair(runID, stepResultID string, round int) (*FactoryRepair, error) {
	if stepResultID == "" || round < 0 {
		return nil, errors.New("repair requires a step result and round")
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// The first statement is a write: competing SQLite connections serialize
	// before inspecting the counter (no deferred read-to-write upgrade race).
	result, err := tx.Exec(`UPDATE factory_budget_generations SET used=used+1 WHERE used<3 AND (repo,branch,generation)=(SELECT repo,branch,generation FROM factory_budget_runs WHERE run_id=?)`, runID)
	if err != nil {
		return nil, err
	}
	var old string
	err = tx.QueryRow(`SELECT id FROM factory_repairs WHERE run_id=? AND step_result_id=? AND round=?`, runID, stepResultID, round).Scan(&old)
	if err == nil {
		return nil, ErrFactoryRepairDispatched
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n != 1 {
		var enrolled bool
		if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM factory_budget_runs WHERE run_id=?)`, runID).Scan(&enrolled); err != nil {
			return nil, err
		}
		if !enrolled {
			return nil, errors.New("controlled run is not enrolled")
		}
		return nil, ErrFactoryBudgetExhausted
	}
	repair := &FactoryRepair{ID: newID()}
	if err = tx.QueryRow(`SELECT used FROM factory_budget_generations WHERE (repo,branch,generation)=(SELECT repo,branch,generation FROM factory_budget_runs WHERE run_id=?)`, runID).Scan(&repair.Ordinal); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`INSERT INTO factory_repairs(id,run_id,step_result_id,round,ordinal,created_at) VALUES(?,?,?,?,?,?)`, repair.ID, runID, stepResultID, round, repair.Ordinal, now()); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return repair, nil
}

// ClaimFactoryRepairDispatch fences the mutation-capable agent turn. Any
// failure after this durable write is uncertain and may not be auto-retried.
func (d *DB) ClaimFactoryRepairDispatch(id, runID, stepResultID string) error {
	result, err := d.sql.Exec(`UPDATE factory_repairs SET dispatched=1 WHERE id=? AND run_id=? AND step_result_id=? AND dispatched=0`, id, runID, stepResultID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrFactoryRepairDispatched
	}
	return nil
}

func (d *DB) ValidateFactoryRepair(id, runID, stepResultID string) error {
	var exists bool
	err := d.sql.QueryRow(`SELECT EXISTS(SELECT 1 FROM factory_repairs WHERE id=? AND run_id=? AND step_result_id=?)`, id, runID, stepResultID).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("invalid controlled repair identity")
	}
	return nil
}

// GetFactoryBudget returns the shared generation's durable spent count.
// An unenrolled run returns sql.ErrNoRows rather than a misleading fresh zero.
func (d *DB) GetFactoryBudget(runID string) (used int, err error) {
	err = d.sql.QueryRow(`SELECT g.used FROM factory_budget_generations g JOIN factory_budget_runs r USING(repo,branch,generation) WHERE r.run_id=?`, runID).Scan(&used)
	return used, err
}
