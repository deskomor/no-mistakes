package factorysandbox

import (
	"net/url"
	"os"
	"path/filepath"
)

// IncludeLocalMirrors grants only existing absolute repositories from trusted
// registration metadata, never a mutable Git remote or an enclosing directory.
func IncludeLocalMirrors(protected []string, mirrors ...string) ([]string, error) {
	for _, remote := range mirrors {
		local := remote
		if parsed, err := url.Parse(remote); err == nil && parsed.Scheme == "file" && (parsed.Host == "" || parsed.Host == "localhost") && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" {
			local = parsed.Path
		}
		if !filepath.IsAbs(local) {
			continue
		}
		if _, err := os.Stat(local); err == nil {
			protected = append(protected, local)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	return protected, nil
}
