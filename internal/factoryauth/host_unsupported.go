//go:build !linux

package factoryauth

import (
	"context"
	"errors"
	"os/exec"
)

func supportedHost() error              { return errors.New("factory-auth supports Linux with bubblewrap only") }
func ownRuntime(string) (func(), error) { return nil, supportedHost() }
func hostCommand(context.Context, Options, string, string) (*exec.Cmd, error) {
	return nil, supportedHost()
}
