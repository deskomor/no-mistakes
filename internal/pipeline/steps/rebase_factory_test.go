package steps

import (
	"context"
	"strings"
	"testing"

	"github.com/kunchenguid/no-mistakes/internal/config"
)

func TestFactoryConflictResolversRequireReservedFixPass(t *testing.T) {
	for _, strategy := range []string{config.RebaseStrategyMerge, config.RebaseStrategyRebase} {
		for _, fixing := range []bool{false, true} {
			name := strategy + "/initial"
			if fixing {
				name = strategy + "/fix-without-reservation"
			}
			t.Run(name, func(t *testing.T) {
				f := newMergeFixture(t, true)
				// No agent is supplied: an unreserved conflict must be rejected
				// before agent dispatch, not delegated as a read-only assessment.
				sctx := f.context(t, nil, strategy)
				sctx.Config.ControlledExecution = true
				sctx.Fixing = fixing
				var err error
				if strategy == config.RebaseStrategyMerge {
					err = mergeWithAgent(context.Background(), sctx, "origin/main")
				} else {
					err = rebaseWithAgent(context.Background(), sctx, "origin/main")
				}
				if err == nil || !strings.Contains(err.Error(), "reserved repair pass") {
					t.Fatalf("unreserved conflict resolver: %v", err)
				}
				assertRestoredToReviewedHead(t, f.dir, f.headSHA)
			})
		}
	}
}
