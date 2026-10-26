package factorysandbox

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// WalkDir does not follow symlinks. Writable regular files must not be aliases
// of host state, even when the other name is outside every mounted tree.
func rejectHardlinks(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Nlink != 1 {
				return fmt.Errorf("controlled writable tree contains multiply-linked regular file: %s", path)
			}
		} else if info.Mode()&os.ModeSocket != 0 || info.Mode()&os.ModeDevice != 0 || info.Mode()&os.ModeNamedPipe != 0 {
			return fmt.Errorf("controlled writable tree contains host IPC/device: %s", path)
		}
		return nil
	})
}
