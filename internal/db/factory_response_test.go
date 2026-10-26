package db

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/kunchenguid/no-mistakes/internal/types"
)

func factoryResponseFixture(t *testing.T, d *DB, branch string) (*Run, *StepResult, FactoryResponseRequest) {
	t.Helper()
	repo, err := d.InsertRepo(t.TempDir(), "https://example.com/"+branch+".git", "main")
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.InsertRunWithIntentAndLaunchNonce(repo.ID, branch, "full-head", "base", nil, "nonce-"+branch, "generation", "digest", "", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.EnsureFactoryBudget(run); err != nil {
		t.Fatal(err)
	}
	if err = d.UpdateRunStatus(run.ID, types.RunRunning); err != nil {
		t.Fatal(err)
	}
	sr, err := d.InsertStepResult(run.ID, types.StepReview)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.ParkStepForApproval(run.ID, sr.ID, types.StepStatusAwaitingApproval, 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	gate, err := d.ParkFactoryGate(run.ID, sr.ID, 1, "full-head")
	if err != nil {
		t.Fatal(err)
	}
	payload := FactoryResponsePayload{Step: types.StepReview, Action: types.ActionFix, FindingIDs: []string{"finding-1"}}
	digest, err := FactoryPayloadDigest(payload)
	if err != nil {
		t.Fatal(err)
	}
	return run, sr, FactoryResponseRequest{RunID: run.ID, ExpectedGate: *gate, OperationID: "operation-1", PayloadDigest: digest, Payload: payload}
}

func TestFactoryResponseLostAcknowledgementReplayAfterGateMoves(t *testing.T) {
	d := openTestDB(t)
	run, sr, q := factoryResponseFixture(t, d, "replay")
	first, newAdmission, err := d.ClaimFactoryResponse(q)
	if err != nil || !newAdmission {
		t.Fatalf("claim: %v %v", newAdmission, err)
	}
	if err = d.StartFactoryResponse(run.ID, q.OperationID); err != nil {
		t.Fatal(err)
	}
	if err = d.CompleteFactoryResponse(run.ID, q.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.ParkFactoryGate(run.ID, sr.ID, 2, "full-head"); err != nil {
		t.Fatal(err)
	}
	if err = d.UpdateRunStatus(run.ID, types.RunCompleted); err != nil {
		t.Fatal(err)
	}
	replay, newAdmission, err := d.ClaimFactoryResponse(q)
	if err != nil || newAdmission || replay.AcceptedAt != first.AcceptedAt || replay.State != "completed" {
		t.Fatalf("replay: %#v new=%v err=%v", replay, newAdmission, err)
	}
	if err = d.StartFactoryResponse(run.ID, q.OperationID); err == nil {
		t.Fatal("replay dispatched twice")
	}
	conflict := q
	conflict.Payload.Action = types.ActionApprove
	conflict.PayloadDigest, _ = FactoryPayloadDigest(conflict.Payload)
	if _, _, err = d.ClaimFactoryResponse(conflict); err == nil {
		t.Fatal("conflicting digest accepted")
	}
	receipt, err := d.GetFactoryResponseReceipt(run.ID, q.OperationID)
	if err != nil || receipt.PayloadDigest != first.PayloadDigest {
		t.Fatalf("lost ack lookup: %#v %v", receipt, err)
	}
}

func TestFactoryResponseRejectsStaleGateHeadAndRun(t *testing.T) {
	d := openTestDB(t)
	run, sr, q := factoryResponseFixture(t, d, "stale")
	if _, err := d.ParkFactoryGate(run.ID, sr.ID, 1, "full-head"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.ClaimFactoryResponse(q); err == nil {
		t.Fatal("same-step replaced park accepted")
	}
	g, err := d.GetFactoryGate(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	q.ExpectedGate = *g
	if _, err = d.sql.Exec(`UPDATE runs SET head_sha='moved-head' WHERE id=?`, run.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = d.ClaimFactoryResponse(q); err == nil {
		t.Fatal("stale full head accepted")
	}
	other, _, otherQ := factoryResponseFixture(t, d, "isolated")
	q.RunID = other.ID
	if _, _, err = d.ClaimFactoryResponse(q); err == nil {
		t.Fatal("cross-run gate accepted")
	}
	if _, fresh, err := d.ClaimFactoryResponse(otherQ); err != nil || !fresh {
		t.Fatalf("independent run: %v %v", fresh, err)
	}
}

func TestFactoryResponseStopOrdering(t *testing.T) {
	for _, stopFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "stop-first", false: "claim-first"}[stopFirst], func(t *testing.T) {
			d := openTestDB(t)
			run, _, q := factoryResponseFixture(t, d, "order")
			if stopFirst {
				if err := d.FenceFactoryRun(run.ID); err != nil {
					t.Fatal(err)
				}
				if _, _, err := d.ClaimFactoryResponse(q); err == nil {
					t.Fatal("stop-first claim accepted")
				}
				return
			}
			if _, _, err := d.ClaimFactoryResponse(q); err != nil {
				t.Fatal(err)
			}
			if err := d.StartFactoryResponse(run.ID, q.OperationID); err != nil {
				t.Fatal(err)
			}
			if err := d.FenceFactoryRun(run.ID); err != nil {
				t.Fatal(err)
			}
			if _, fresh, err := d.ClaimFactoryResponse(q); err != nil || fresh {
				t.Fatalf("claim-first lost receipt: %v %v", fresh, err)
			}
		})
	}
	t.Run("fence-between-admission-and-start", func(t *testing.T) {
		d := openTestDB(t)
		run, _, q := factoryResponseFixture(t, d, "gap")
		if _, _, err := d.ClaimFactoryResponse(q); err != nil {
			t.Fatal(err)
		}
		if err := d.FenceFactoryRun(run.ID); err != nil {
			t.Fatal(err)
		}
		if err := d.StartFactoryResponse(run.ID, q.OperationID); err == nil {
			t.Fatal("dispatched after stop")
		}
	})
}

func TestFactoryResponseConcurrentRetryAdmitsOnce(t *testing.T) {
	d := openTestDB(t)
	_, _, q := factoryResponseFixture(t, d, "concurrent")
	var wg sync.WaitGroup
	var mu sync.Mutex
	admissions := 0
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, fresh, err := d.ClaimFactoryResponse(q)
			if err != nil {
				t.Error(err)
			}
			if fresh {
				mu.Lock()
				admissions++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if admissions != 1 {
		t.Fatalf("admissions=%d", admissions)
	}
}

func TestFactoryResponseRestartParksUnknownWithoutReplay(t *testing.T) {
	for _, started := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "started"}[started], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.sqlite")
			d, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			run, _, q := factoryResponseFixture(t, d, "restart")
			if _, _, err = d.ClaimFactoryResponse(q); err != nil {
				t.Fatal(err)
			}
			if started {
				if err = d.StartFactoryResponse(run.ID, q.OperationID); err != nil {
					t.Fatal(err)
				}
			}
			if err = d.Close(); err != nil {
				t.Fatal(err)
			}
			d, err = Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			if err = d.RecoverFactoryResponses(); err != nil {
				t.Fatal(err)
			}
			receipt, err := d.GetFactoryResponseReceipt(run.ID, q.OperationID)
			if err != nil || receipt.State != "uncertain" {
				t.Fatalf("receipt=%#v err=%v", receipt, err)
			}
			gate, err := d.GetFactoryGate(run.ID)
			if err != nil || gate.State != "uncertain" {
				t.Fatalf("gate=%#v err=%v", gate, err)
			}
			if _, fresh, err := d.ClaimFactoryResponse(q); err != nil || fresh {
				t.Fatalf("uncertain replay admitted: %v %v", fresh, err)
			}
			if err = d.StartFactoryResponse(run.ID, q.OperationID); err == nil {
				t.Fatal("unknown operation redispatched")
			}
			parked, err := d.GetRun(run.ID)
			if err != nil || parked.AwaitingAgentSince == nil {
				t.Fatalf("not parked: %#v %v", parked, err)
			}
			ids, err := d.FactoryUncertainRunIDs()
			if err != nil || len(ids) != 1 || ids[0] != run.ID {
				t.Fatalf("preserved=%v err=%v", ids, err)
			}
		})
	}
}

func TestFactoryFenceDoesNotPreventLegacyRepositoryEject(t *testing.T) {
	d := openTestDB(t)
	repo, err := d.InsertRepo(t.TempDir(), "https://example.test/legacy-eject", "main")
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.InsertRunWithIntentAndLaunchNonce(repo.ID, "main", "head", "base", nil, "", "", "", "", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.FenceFactoryRun(run.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteRepo(repo.ID); err != nil {
		t.Fatalf("eject legacy repository after stop: %v", err)
	}
	if got, err := d.GetRun(run.ID); err != nil || got != nil {
		t.Fatalf("ejected legacy run still visible: %#v, %v", got, err)
	}
}

func TestFactoryRepositoryEjectClearsReceiptsWithoutRefillingBudget(t *testing.T) {
	d := openTestDB(t)
	run, sr, request := factoryResponseFixture(t, d, "eject")
	repo, err := d.GetRepo(run.RepoID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReserveFactoryRepair(run.ID, sr.ID, 1); err != nil {
		t.Fatal(err)
	}
	if _, fresh, err := d.ClaimFactoryResponse(request); err != nil || !fresh {
		t.Fatalf("claim response: fresh=%v, %v", fresh, err)
	}
	if err := d.StartFactoryResponse(run.ID, request.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := d.CompleteFactoryResponse(run.ID, request.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateRunStatus(run.ID, types.RunCompleted); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteRepo(repo.ID); err != nil {
		t.Fatalf("eject controlled repository: %v", err)
	}
	if gate, err := d.GetFactoryGate(run.ID); err != nil || gate != nil {
		t.Fatalf("ejected gate still visible: %#v, %v", gate, err)
	}
	if receipt, err := d.GetFactoryResponseReceipt(run.ID, request.OperationID); err != nil || receipt != nil {
		t.Fatalf("ejected receipt still visible: %#v, %v", receipt, err)
	}
	recreated, err := d.InsertRepo(repo.WorkingPath, repo.UpstreamURL, repo.DefaultBranch)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := d.InsertRunWithIntentAndLaunchNonce(recreated.ID, run.Branch, "head", "base", nil, "replacement-nonce", *run.LaunchValidationGeneration, "digest", "", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureFactoryBudget(replacement); err != nil {
		t.Fatal(err)
	}
	if used, err := d.GetFactoryBudget(replacement.ID); err != nil || used != 1 {
		t.Fatalf("eject refilled generation budget: used=%d, %v", used, err)
	}
	for round := 2; round <= 3; round++ {
		repair, err := d.ReserveFactoryRepair(replacement.ID, "replacement-review", round)
		if err != nil || repair.Ordinal != round {
			t.Fatalf("remaining repair %d: %#v, %v", round, repair, err)
		}
	}
	if _, err := d.ReserveFactoryRepair(replacement.ID, "replacement-review", 4); !errors.Is(err, ErrFactoryBudgetExhausted) {
		t.Fatalf("eject bypassed three-pass ceiling: %v", err)
	}
}
