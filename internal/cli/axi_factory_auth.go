package cli

import (
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/kunchenguid/no-mistakes/internal/factoryauth"
	"github.com/spf13/cobra"
)

func newAxiFactoryAuthCmd() *cobra.Command {
	var options factoryauth.Options
	cmd := &cobra.Command{Use: "factory-auth", Short: "Own one Linux isolated foreground Factory credential host", Long: "Own one Linux isolated foreground Factory credential host. The controller must keep its stdin pipe open for the entire ownership lifetime; EOF or a read failure stops the host. Stdin is consumed only for liveness, independently of the credential subprocess's stdio protocol.", Args: cobra.NoArgs, SilenceUsage: true, RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		// This command owns the controlling stream, including closing it on
		// startup failure so its liveness reader cannot outlive the command.
		input, ok := cmd.InOrStdin().(io.ReadCloser)
		if !ok {
			return errors.New("factory-auth requires a closable controlling stdin pipe")
		}
		ownedInput, err := factoryAuthOwnerInput(input)
		if err != nil {
			_ = input.Close()
			return err
		}
		input = ownedInput
		ownerGone := make(chan struct{})
		go func() {
			_, _ = io.Copy(io.Discard, input)
			stop()
			close(ownerGone)
		}()
		defer func() {
			stop()
			_ = input.Close()
			<-ownerGone
		}()
		return factoryauth.Run(ctx, options, cmd.OutOrStdout())
	}}
	cmd.Flags().StringVar(&options.OMP, "omp", "", "Absolute supported omp executable (minimum18.12.3)")
	cmd.Flags().StringVar(&options.SourceHome, "source-home", "", "Absolute read-only credential source home")
	cmd.Flags().StringVar(&options.SourceAgentDir, "source-agent-dir", "", "Absolute read-only source agent directory")
	cmd.Flags().StringVar(&options.RuntimeDir, "runtime-dir", "", "Private empty per-card agent directory")
	cmd.Flags().StringVar(&options.Model, "model", "", "Exact source provider/model")
	for _, flag := range []string{"omp", "source-home", "source-agent-dir", "runtime-dir", "model"} {
		_ = cmd.MarkFlagRequired(flag)
	}
	return cmd
}
