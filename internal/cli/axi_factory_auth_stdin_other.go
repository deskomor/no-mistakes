//go:build !linux

package cli

import (
	"errors"
	"io"
)

func factoryAuthOwnerInput(io.ReadCloser) (io.ReadCloser, error) {
	return nil, errors.New("factory-auth requires Linux bubblewrap")
}
