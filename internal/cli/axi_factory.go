package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/kunchenguid/no-mistakes/internal/db"
	"github.com/kunchenguid/no-mistakes/internal/ipc"
	"github.com/kunchenguid/no-mistakes/internal/paths"
	"github.com/spf13/cobra"
)

// Factory controls deliberately expose JSON identities without branch inference.
func newAxiFactoryRespondCmd() *cobra.Command {
	var requestPath string
	cmd := &cobra.Command{Use: "factory-respond", Short: "Submit one exact-gate controlled response (JSON receipt)", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if requestPath == "" {
			return fmt.Errorf("--request JSON file (or - for stdin) required")
		}
		var input io.Reader = cmd.InOrStdin()
		if requestPath != "-" {
			f, err := os.Open(requestPath)
			if err != nil {
				return err
			}
			defer f.Close()
			input = f
		}
		var q db.FactoryResponseRequest
		decoder := json.NewDecoder(io.LimitReader(input, 1<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&q); err != nil {
			return err
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return fmt.Errorf("request must contain exactly one JSON object")
		}
		digest, err := db.FactoryPayloadDigest(q.Payload)
		if err != nil {
			return err
		}
		if q.PayloadDigest == "" {
			q.PayloadDigest = digest
		} else if digest != q.PayloadDigest {
			return fmt.Errorf("payload_digest must match SHA-256 of canonical payload JSON")
		}
		p, err := paths.New()
		if err != nil {
			return err
		}
		// Do not autostart a daemon: an unknown/old method must fail closed.
		client, err := ipc.Dial(p.Socket())
		if err != nil {
			return err
		}
		defer client.Close()
		var receipt db.FactoryResponseReceipt
		if err = client.Call(ipc.MethodFactoryRespond, &q, &receipt); err != nil {
			return fmt.Errorf("strict response unconfirmed; query factory-receipt with the same run/operation before any retry: %w", err)
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(receipt)
	}}
	cmd.Flags().StringVar(&requestPath, "request", "", "Immutable response JSON file, or - for stdin")
	return cmd
}

func newAxiFactoryLookupCmd(receipt bool) *cobra.Command {
	var runID, operationID string
	name := "factory-gate"
	if receipt {
		name = "factory-receipt"
	}
	cmd := &cobra.Command{Use: name, Short: "Read an exact controlled identity offline (JSON)", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if runID == "" || (receipt && operationID == "") {
			return fmt.Errorf("--run required; receipt also requires --operation")
		}
		p, err := paths.New()
		if err != nil {
			return err
		}
		database, err := db.OpenReadOnly(p.DB())
		if err != nil {
			return err
		}
		defer database.Close()
		var value any
		if receipt {
			value, err = database.GetFactoryResponseReceipt(runID, operationID)
		} else {
			value, err = database.GetFactoryGate(runID)
		}
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(value)
	}}
	cmd.Flags().StringVar(&runID, "run", "", "Exact durable run ID")
	if receipt {
		cmd.Flags().StringVar(&operationID, "operation", "", "Exact response operation ID")
	}
	return cmd
}

func newAxiFactoryBudgetCmd() *cobra.Command {
	var runID string
	cmd := &cobra.Command{Use: "factory-budget", Short: "Read the durable shared repair allowance offline (JSON)", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if runID == "" {
			return fmt.Errorf("--run required")
		}
		p, err := paths.New()
		if err != nil {
			return err
		}
		database, err := db.OpenReadOnly(p.DB())
		if err != nil {
			return err
		}
		defer database.Close()
		used, err := database.GetFactoryBudget(runID)
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
			RunID     string `json:"run_id"`
			Limit     int    `json:"limit"`
			Used      int    `json:"used"`
			Remaining int    `json:"remaining"`
		}{runID, 3, used, 3 - used})
	}}
	cmd.Flags().StringVar(&runID, "run", "", "Exact controlled run ID")
	return cmd
}
