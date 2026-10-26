//go:build linux

package cli

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// Inherited stdin can be a blocking os.File: closing it does not interrupt its
// active kernel read. Own a nonblocking duplicate registered with Go's poller,
// so signal/startup cancellation can close and join the liveness reader.
func factoryAuthOwnerInput(input io.ReadCloser) (io.ReadCloser, error) {
	file, ok := input.(*os.File)
	if !ok {
		return input, nil
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&(os.ModeNamedPipe|os.ModeSocket) == 0 {
		return nil, errors.New("factory-auth requires a controlling stdin pipe or stream socket")
	}
	if info.Mode()&os.ModeSocket != 0 {
		descriptor := int(file.Fd())
		kind, kindErr := unix.GetsockoptInt(descriptor, unix.SOL_SOCKET, unix.SO_TYPE)
		domain, domainErr := unix.GetsockoptInt(descriptor, unix.SOL_SOCKET, unix.SO_DOMAIN)
		if kindErr != nil || domainErr != nil || kind != unix.SOCK_STREAM || domain != unix.AF_UNIX {
			return nil, errors.New("factory-auth requires a local stream control socket")
		}
	}
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("controlling stdin pipe unavailable")
	}
	if err = unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, errors.New("controlling stdin pipe cannot be cancelled")
	}
	owned := os.NewFile(uintptr(fd), "factory-auth-owner")
	if owned == nil {
		_ = unix.Close(fd)
		return nil, errors.New("controlling stdin pipe unavailable")
	}
	if err = file.Close(); err != nil {
		_ = owned.Close()
		return nil, errors.New("controlling stdin ownership failed")
	}
	return owned, nil
}
