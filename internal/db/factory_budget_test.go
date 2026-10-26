package db

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

func factoryBudgetRun(t *testing.T, d *DB, repo *Repo, nonce, generation string) *Run {
	t.Helper()
	run, err := d.InsertRunWithIntentAndLaunchNonce(repo.ID, "feature", "head", "base", nil, nonce, generation, "digest", "", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.EnsureFactoryBudget(run); err != nil {
		t.Fatal(err)
	}
	return run
}

func TestFactoryControlledRepoEnrollmentSurvivesReopenAndStaysScoped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite")
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := d.InsertRepo(t.TempDir(), "https://example.test/controlled", "main")
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := d.InsertRepo(t.TempDir(), "https://example.test/ordinary", "main")
	if err != nil {
		t.Fatal(err)
	}
	run := factoryBudgetRun(t, d, repo, "durable-nonce", "durable-generation")
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if got, err := d.FactoryControlledRepoRunID(repo.ID); err != nil || got != run.ID {
		t.Fatalf("durable repository enrollment = %q, %v", got, err)
	}
	if got, err := d.FactoryControlledRepoRunID(ordinary.ID); err != nil || got != "" {
		t.Fatalf("ordinary repository enrollment = %q, %v", got, err)
	}
}

func TestFactoryBudgetDurableReplacementAndUnknownDispatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "budget.db")
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := d.InsertRepo(t.TempDir(), "https://example.test/project", "main")
	if err != nil {
		t.Fatal(err)
	}
	run := factoryBudgetRun(t, d, repo, "nonce-1", "card-generation")
	first, err := d.ReserveFactoryRepair(run.ID, "review", 1)
	if err != nil || first.Ordinal != 1 {
		t.Fatalf("first: %#v %v", first, err)
	}
	if err = d.ClaimFactoryRepairDispatch(first.ID, run.ID, "test"); err == nil {
		t.Fatal("wrong step acquired repair")
	}
	if err = d.ClaimFactoryRepairDispatch(first.ID, run.ID, "review"); err != nil {
		t.Fatal(err)
	}
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err = d.ClaimFactoryRepairDispatch(first.ID, run.ID, "review"); !errors.Is(err, ErrFactoryRepairDispatched) {
		t.Fatalf("unknown dispatch replay: %v", err)
	}
	if _, err = d.ReserveFactoryRepair(run.ID, "review", 1); !errors.Is(err, ErrFactoryRepairDispatched) {
		t.Fatalf("round replay: %v", err)
	}
	replacement := factoryBudgetRun(t, d, repo, "nonce-2", "card-generation")
	for i, step := range []string{"test", "document"} {
		r, err := d.ReserveFactoryRepair(replacement.ID, step, 1)
		if err != nil || r.Ordinal != i+2 {
			t.Fatalf("replacement pass %d: %#v %v", i+2, r, err)
		}
	}
	if _, err = d.ReserveFactoryRepair(replacement.ID, "lint", 1); !errors.Is(err, ErrFactoryBudgetExhausted) {
		t.Fatalf("fourth: %v", err)
	}
	// A new nonce/run does not replenish even after a clean restart.
	third := factoryBudgetRun(t, d, repo, "nonce-3", "card-generation")
	if _, err = d.ReserveFactoryRepair(third.ID, "ci", 1); !errors.Is(err, ErrFactoryBudgetExhausted) {
		t.Fatalf("replacement exhausted: %v", err)
	}
}

func TestFactoryBudgetConcurrentConnectionsNeverExceedThree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "budget.db")
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	repo, err := d.InsertRepo(t.TempDir(), "https://example.test/project", "main")
	if err != nil {
		t.Fatal(err)
	}
	run := factoryBudgetRun(t, d, repo, "nonce", "generation")
	const workers = 8
	connections := make([]*DB, workers)
	for i := range connections {
		connections[i], err = Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer connections[i].Close()
	}
	var wg sync.WaitGroup
	results := make(chan error, workers)
	for i, conn := range connections {
		wg.Add(1)
		go func(i int, conn *DB) {
			defer wg.Done()
			_, err := conn.ReserveFactoryRepair(run.ID, fmt.Sprintf("step-%d", i), 1)
			results <- err
		}(i, conn)
	}
	wg.Wait()
	close(results)
	admitted := 0
	for err := range results {
		if err == nil {
			admitted++
		} else if !errors.Is(err, ErrFactoryBudgetExhausted) {
			t.Fatalf("unexpected concurrent error: %v", err)
		}
	}
	if admitted != 3 {
		t.Fatalf("admitted %d repairs, want exactly 3", admitted)
	}
}

func TestFactoryBudgetRejectsUnboundAndChangedIdentity(t *testing.T) {
	d := openTestDB(t)
	repo, err := d.InsertRepo(t.TempDir(), "https://example.test/project", "main")
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := d.InsertRun(repo.ID, "feature", "head", "base")
	if err != nil {
		t.Fatal(err)
	}
	if err = d.EnsureFactoryBudget(legacy); err == nil {
		t.Fatal("legacy run enrolled")
	}
	enrolled, err := d.IsFactoryControlledRun(legacy.ID)
	if err != nil || enrolled {
		t.Fatalf("legacy enrollment %v %v", enrolled, err)
	}
	run := factoryBudgetRun(t, d, repo, "nonce", "generation")
	changed := "other"
	run.LaunchValidationGeneration = &changed
	if err = d.EnsureFactoryBudget(run); err == nil {
		t.Fatal("changed generation accepted")
	}
	for _, invalid := range []string{"", "with space", "é", string(make([]byte, 129))} {
		if validFactoryIdentity(invalid) {
			t.Fatalf("invalid identity accepted: %q", invalid)
		}
	}
}
