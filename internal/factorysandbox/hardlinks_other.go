//go:build !linux

package factorysandbox

import "errors"

func rejectHardlinks(string) error {
	return errors.New("controlled execution requires Linux hardlink validation")
}
