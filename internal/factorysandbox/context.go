package factorysandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type policyKey struct{}
type gitPolicy struct {
	evidence  string
	protected []string
}

// WithPolicy opts all context-aware parent Git subprocesses into the controlled
// boundary. Call before any pipeline Git work, and retain the returned context
// through Execute/Resume and their derived contexts. Legacy callers are unchanged.
func WithPolicy(ctx context.Context, evidence string, protected []string) context.Context {
	return context.WithValue(ctx, policyKey{}, gitPolicy{evidence, append([]string(nil), protected...)})
}

type gitScratchIndexKey struct{}

// WithGitScratchIndex grants parent Git plumbing one caller-owned scratch
// directory for its index and marker files. The caller must create the directory
// first and exclusively own it until all derived Git commands have finished.
// This grant has no effect without WithPolicy and never applies to agent commands.
func WithGitScratchIndex(ctx context.Context, indexDir string) context.Context {
	return context.WithValue(ctx, gitScratchIndexKey{}, indexDir)
}

type gitWorktreeDestinationKey struct{}

// WithGitWorktreeDestination grants native worktree add only its exact, empty,
// precreated destination. The trusted caller exclusively owns this directory;
// its parent and sibling paths are never mounted writable.
func WithGitWorktreeDestination(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, gitWorktreeDestinationKey{}, dir)
}

// WrapGitCommand scopes the complete Git process tree. Native integration is not
// a repair dispatch, but only built-in Git transformations may write the managed
// product/Git roots. Configured executable extensions are never admitted here.
// The caller must defer cleanup until after the command has finished.
func WrapGitCommand(ctx context.Context, cmd *exec.Cmd, args []string) (func(), error) {
	policy, controlled := ctx.Value(policyKey{}).(gitPolicy)
	if !controlled {
		return func() {}, nil
	}
	// commitIndex deliberately supplies a temporary empty hooks directory.
	// Our stronger immutable /dev/null override replaces that equivalent flag.
	if len(args) >= 2 && args[0] == "-c" && strings.HasPrefix(args[1], "core.hooksPath=") {
		args = args[2:]
	}
	prefix, verb, rest, err := gitInvocation(args)
	if err != nil {
		return nil, err
	}
	mutation := true
	switch verb {
	case "status", "diff", "log", "show", "rev-parse", "rev-list", "merge-base", "symbolic-ref", "for-each-ref", "ls-remote", "ls-files", "ls-tree", "cat-file", "patch-id", "check-ref-format":
		mutation = false
		if verb == "symbolic-ref" {
			// Only the query form is read-only.
			positional := 0
			for _, arg := range rest {
				if !strings.HasPrefix(arg, "-") {
					positional++
				}
			}
			mutation = positional > 1 || containsArg(rest, "--delete")
		}
	case "config":
		mutation = true
		for _, arg := range rest {
			switch arg {
			case "--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "-l":
				mutation = false
			}
		}
	case "remote":
		mutation = len(rest) != 0 && rest[0] != "get-url" && rest[0] != "-v" && rest[0] != "--verbose"
	case "worktree":
		mutation = len(rest) == 0 || rest[0] != "list"
	case "branch", "tag":
		mutation = len(rest) != 0 && !containsArg(rest, "--list") && !containsArg(rest, "--show-current")
	case "hash-object":
		mutation = containsArg(rest, "-w")
	case "init", "add", "commit", "commit-tree", "update-index", "update-ref", "read-tree", "write-tree", "reset", "checkout", "switch", "fetch", "push", "rebase", "merge", "merge-tree", "cherry-pick", "revert", "clean", "stash", "apply":
	default:
		return nil, fmt.Errorf("controlled Git refuses unsupported native command %q", verb)
	}
	// Remove ambient executable/config injection; retain identity and scratch
	// index variables deliberately supplied by the parent Git plumbing.
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	scratch := gitScratch{}
	for _, entry := range env {
		key, value, _ := strings.Cut(entry, "=")
		if key != "GIT_INDEX_FILE" {
			continue
		}
		dir, granted := ctx.Value(gitScratchIndexKey{}).(string)
		if !granted || dir == "" || !filepath.IsAbs(dir) || dir != filepath.Clean(dir) || !filepath.IsAbs(value) || value != filepath.Clean(value) || filepath.Dir(value) != dir {
			return nil, fmt.Errorf("controlled Git refuses ungranted scratch index %q", value)
		}
		if scratch.index != "" {
			return nil, fmt.Errorf("controlled Git refuses duplicate scratch index")
		}
		scratch = gitScratch{dir: filepath.Clean(dir), index: value}
	}
	if dir, granted := ctx.Value(gitWorktreeDestinationKey{}).(string); granted {
		if verb != "worktree" || len(rest) != 4 || rest[0] != "add" || rest[1] != "--detach" || rest[2] != dir {
			return nil, fmt.Errorf("controlled Git destination grant requires exact worktree add")
		}
		scratch.destination = dir
	}
	clean := make([]string, 0, len(env)+8)
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "GIT_CONFIG") || strings.HasPrefix(key, "GIT_SSH") || key == "GIT_EXEC_PATH" || key == "GIT_EXTERNAL_DIFF" || key == "GIT_PROXY_COMMAND" || key == "GIT_ASKPASS" || key == "SSH_ASKPASS" || key == "GIT_EDITOR" || key == "GIT_SEQUENCE_EDITOR" || key == "GIT_PAGER" || key == "GIT_ALLOW_PROTOCOL" {
			continue
		}
		clean = append(clean, entry)
	}
	cmd.Env = append(clean, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "GIT_EDITOR=true", "GIT_SEQUENCE_EDITOR=true", "GIT_PAGER=cat", "GIT_ALLOW_PROTOCOL=file:http:https:ssh")
	settings := []string{
		"core.hooksPath=/dev/null", "core.fsmonitor=false", "core.untrackedCache=false", "core.pager=cat", "core.editor=true",
		"core.sshCommand=ssh -F /dev/null -o PermitLocalCommand=no -o ProxyCommand=none -o ProxyJump=none", "core.gitProxy=", "core.alternateRefsCommand=",
		"credential.helper=", "credential.interactive=false", "core.askPass=", "commit.gpgSign=false", "tag.gpgSign=false", "push.gpgSign=false",
		"diff.external=", "diff.trustExitCode=false", "submodule.recurse=false", "fetch.recurseSubmodules=false", "push.recurseSubmodules=no",
		"protocol.allow=never", "protocol.file.allow=always", "protocol.http.allow=always", "protocol.https.allow=always", "protocol.ssh.allow=always",
		"uploadpack.packObjectsHook=/usr/bin/env", "rebase.autoStash=false", "merge.autoStash=false",
	}
	// Enumerate attributes' executable drivers without invoking any driver. The
	// inspection itself runs in the same read-only OS boundary, never on host.
	inspectArgs := append(append([]string(nil), prefix...), "config", "--null", "--list")
	inspect := exec.CommandContext(ctx, cmd.Path, inspectArgs...)
	inspect.Dir, inspect.Env = cmd.Dir, cmd.Env
	cleanup, err := WrapAssessment(inspect, policy.evidence, policy.protected, false)
	if err != nil {
		return nil, err
	}
	out, inspectErr := inspect.Output()
	cleanup()
	if inspectErr != nil {
		return nil, fmt.Errorf("inspect controlled Git configuration: %w", inspectErr)
	}
	records := strings.Split(string(out), "\x00")
	transport, err := localGitTransportOption(cmd.Path, cmd.Dir, verb, rest, records)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		key, _, _ := strings.Cut(record, "\n")
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "filter.") {
			if dot := strings.LastIndex(key, "."); dot > len("filter.") {
				base := key[:dot]
				settings = append(settings, base+".clean=", base+".smudge=", base+".process=", base+".required=false")
			}
		}
		if strings.HasPrefix(lower, "merge.") && strings.HasSuffix(lower, ".driver") {
			settings = append(settings, key+"=false")
		}
		if strings.HasPrefix(lower, "diff.") && strings.HasSuffix(lower, ".textconv") {
			settings = append(settings, key+"=")
		}
		if strings.HasPrefix(lower, "remote.") {
			for _, suffix := range []string{".uploadpack", ".receivepack", ".proxy", ".vcs"} {
				if strings.HasSuffix(lower, suffix) {
					return nil, fmt.Errorf("controlled Git refuses executable transport setting %s", key)
				}
			}
		}
	}
	hardened := []string{cmd.Args[0]}
	for _, setting := range settings {
		hardened = append(hardened, "-c", setting)
	}
	cmd.Args = append(hardened, prefix...)
	cmd.Args = append(cmd.Args, verb)
	if transport != "" {
		cmd.Args = append(cmd.Args, transport)
	}
	cmd.Args = append(cmd.Args, rest...)
	return wrapCommand(cmd, policy.evidence, policy.protected, false, mutation, scratch)
}

// Only parent-owned global routing flags are supported. In particular -c and
// --exec-path must not override the execution policy after its own settings.
func gitInvocation(args []string) ([]string, string, []string, error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-C" || arg == "--git-dir" || arg == "--work-tree" {
			i++
			if i >= len(args) {
				break
			}
			continue
		}
		if strings.HasPrefix(arg, "--git-dir=") || strings.HasPrefix(arg, "--work-tree=") {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return nil, "", nil, fmt.Errorf("controlled Git refuses global option %q", arg)
		}
		return args[:i], arg, args[i+1:], nil
	}
	return nil, "", nil, fmt.Errorf("controlled Git requires a built-in command")
}

func containsArg(args []string, wanted string) bool {
	for _, arg := range args {
		if arg == wanted {
			return true
		}
	}
	return false
}
