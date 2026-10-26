package factorysandbox

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Factory transports address private local mirrors only. Do not send a client
// executable path to an SSH host or claim control over a remote HTTP server.
func localGitTransportOption(executable, dir, verb string, args, records []string) (string, error) {
	if verb != "push" && verb != "fetch" && verb != "ls-remote" {
		return "", nil
	}
	for _, arg := range args {
		if arg == "--exec" || strings.HasPrefix(arg, "--exec=") || arg == "--receive-pack" || strings.HasPrefix(arg, "--receive-pack=") || arg == "--upload-pack" || strings.HasPrefix(arg, "--upload-pack=") || (verb == "ls-remote" && arg == "-u") {
			return "", fmt.Errorf("controlled Git refuses custom transport executable %q", arg)
		}
		if arg == "--repo" || strings.HasPrefix(arg, "--repo=") || (verb == "fetch" && (arg == "--all" || arg == "--multiple")) {
			return "", fmt.Errorf("controlled Git requires one positional local transport target")
		}
	}
	target := "origin"
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if i+1 < len(args) {
				target = args[i+1]
			}
			break
		}
		switch arg {
		case "-o", "--push-option", "--depth", "--deepen", "--shallow-since", "--shallow-exclude", "--refmap", "--filter", "--negotiation-tip", "--server-option", "-j", "--jobs":
			if i+1 >= len(args) {
				return "", fmt.Errorf("controlled Git option %s requires a value", arg)
			}
			i++
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		target = arg
		break
	}
	var fetchURL, pushURL string
	configuredRemote := false
	for _, record := range records {
		key, value, _ := strings.Cut(record, "\n")
		lower := strings.ToLower(key)
		configuredRemote = configuredRemote || strings.HasPrefix(key, "remote."+target+".")
		if strings.HasPrefix(lower, "url.") && (strings.HasSuffix(lower, ".insteadof") || strings.HasSuffix(lower, ".pushinsteadof")) {
			return "", fmt.Errorf("controlled local transport refuses URL rewrite %s", key)
		}
		if key == "remote."+target+".url" {
			if fetchURL != "" || value == "" {
				return "", fmt.Errorf("controlled transport requires one remote URL")
			}
			fetchURL = value
		}
		if key == "remote."+target+".pushurl" {
			if pushURL != "" || value == "" {
				return "", fmt.Errorf("controlled transport requires one push URL")
			}
			pushURL = value
		}
	}
	if configuredRemote && fetchURL == "" {
		return "", fmt.Errorf("controlled transport requires one nonempty fetch URL")
	}
	if fetchURL != "" {
		target = fetchURL
	}
	if verb == "push" && pushURL != "" {
		target = pushURL
	}
	if strings.HasPrefix(target, "file://") {
		parsed, err := url.Parse(target)
		if err != nil || parsed.User != nil || (parsed.Host != "" && parsed.Host != "localhost") || parsed.RawQuery != "" || parsed.Fragment != "" {
			return "", fmt.Errorf("controlled transport requires a local file URL")
		}
		target = parsed.Path
	} else if !filepath.IsAbs(target) && strings.Contains(target, ":") {
		return "", fmt.Errorf("controlled Factory transport supports only local mirrors, not %q", target)
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(dir, target)
	}
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		return "", fmt.Errorf("controlled transport requires an existing local mirror: %s", target)
	}
	server := "'" + strings.ReplaceAll(executable, "'", "'\\''") + "' -c core.hooksPath=/dev/null -c uploadpack.packObjectsHook=/usr/bin/env -c core.alternateRefsCommand= "
	if verb == "push" {
		return "--receive-pack=" + server + "receive-pack", nil
	}
	return "--upload-pack=" + server + "upload-pack", nil
}
