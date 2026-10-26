package agent

import (
	"fmt"
	"github.com/kunchenguid/no-mistakes/internal/factorysandbox"
)

// EnsureFactoryControlled admits only the verified default acp:omp adapter,
// including all configured fallback/role members. Unknown wrappers fail closed.
func EnsureFactoryControlled(a Agent) error {
	if err := factorysandbox.Supported(); err != nil {
		return err
	}
	switch current := a.(type) {
	case *acpxAgent:
		if current.target == "omp" && current.rawCommand == "" {
			return nil
		}
	case steeredAgent:
		return EnsureFactoryControlled(current.Agent)
	case *fallbackAgent:
		if len(current.agents) == 0 {
			break
		}
		for _, member := range current.agents {
			if err := EnsureFactoryControlled(member); err != nil {
				return err
			}
		}
		return nil
	case *reviewAgents:
		for _, member := range current.all() {
			if err := EnsureFactoryControlled(member); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("controlled execution requires the default acp:omp adapter; unsupported adapter %T", a)
}
