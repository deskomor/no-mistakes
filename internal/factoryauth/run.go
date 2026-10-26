package factoryauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kunchenguid/no-mistakes/internal/shellenv"
)

type Options struct{ OMP, SourceHome, SourceAgentDir, RuntimeDir, Model string }
type Readiness struct {
	Ready       bool   `json:"ready"`
	PID         int    `json:"pid"`
	Model       string `json:"model"`
	SourceModel string `json:"source_model"`
	RuntimeDir  string `json:"runtime_dir"`
	Version     string `json:"version"`
}

func safePath(p string, exists bool) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
		return errors.New("Factory paths must be clean absolute non-root paths")
	}
	for v := p; v != "/"; v = filepath.Dir(v) {
		s, e := os.Lstat(v)
		if e != nil {
			if os.IsNotExist(e) && v == p && !exists {
				continue
			}
			return errors.New("Factory path unavailable")
		}
		if s.Mode()&os.ModeSymlink != 0 {
			return errors.New("Factory symlink paths unsupported")
		}
	}
	return nil
}
func within(a, b string) bool { return a == b || strings.HasPrefix(a, b+string(os.PathSeparator)) }
func validate(o Options) error {
	for _, p := range []string{o.OMP, o.SourceHome, o.SourceAgentDir} {
		if e := safePath(p, true); e != nil {
			return e
		}
	}
	if e := safePath(o.RuntimeDir, false); e != nil {
		return e
	}
	if within(o.SourceHome, o.RuntimeDir) || within(o.RuntimeDir, o.SourceAgentDir) || within(o.SourceAgentDir, o.RuntimeDir) || within(o.RuntimeDir, filepath.Join(o.SourceHome, ".omp")) || within(o.RuntimeDir, filepath.Join(o.SourceHome, ".config")) || within(o.OMP, o.RuntimeDir) {
		return errors.New("runtime must not overlap credential configuration or contain source paths")
	}
	parts := strings.SplitN(o.Model, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.ContainsAny(o.Model, "*,@\\\n\r\t ") {
		return errors.New("exact provider/model required; selectors and routed models unsupported")
	}
	return nil
}
func writePrivate(path string, value any) error {
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return errors.New("owned runtime configuration already exists")
	}
	_, e = f.Write(append(b, '\n'))
	ce := f.Close()
	if e != nil {
		_ = os.Remove(path)
		return e
	}
	if ce != nil {
		_ = os.Remove(path)
	}
	return ce
}

// Run serves one private card until context cancellation or credential-peer failure.
// Linux bubblewrap exposes only system runtimes and explicitly approved read-only
// sources; private /factory scratch is writable. The CLI binds context lifetime
// to its controlling stdin. Inference networking remains available.
func Run(ctx context.Context, o Options, out io.Writer) error {
	if e := supportedHost(); e != nil {
		return e
	}
	if e := validate(o); e != nil {
		return e
	}
	release, e := ownRuntime(o.RuntimeDir)
	if e != nil {
		return e
	}
	defer release()
	scratch, e := os.MkdirTemp("", "no-mistakes-factory-auth-")
	if e != nil {
		return errors.New("private host scratch unavailable")
	}
	defer os.RemoveAll(scratch)
	if e = os.Mkdir(filepath.Join(scratch, "neutral"), 0700); e != nil {
		return e
	}
	overlay := filepath.Join(scratch, "overlay.yml")
	// PI_CONFIG_FILES is an official settings overlay, loaded after source and
	// project settings. Disable fallback BEFORE inference, not merely on response.
	if e = writePrivate(overlay, map[string]any{"retry": map[string]any{"modelFallback": false, "fallbackChains": map[string]any{}}}); e != nil {
		return e
	}
	hostCtx, stop := context.WithCancel(ctx)
	defer stop()
	cmd, e := hostCommand(hostCtx, o, scratch, overlay)
	if e != nil {
		return e
	}
	shellenv.ConfigureShellCommand(cmd)
	input, e := cmd.StdinPipe()
	if e != nil {
		return e
	}
	output, e := cmd.StdoutPipe()
	if e != nil {
		return e
	}
	cmd.Stderr = io.Discard
	if e = shellenv.StartShellCommand(cmd); e != nil {
		return errors.New("credential host could not start")
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); shellenv.TerminateShellCommandGroup(cmd); close(exited) }()
	defer func() { _ = input.Close(); stop(); shellenv.TerminateShellCommandGroup(cmd); <-exited }()
	peer := newTransport(input, output)
	defer peer.fail()
	startup, cancel := context.WithTimeout(hostCtx, 30*time.Second)
	version, e := peer.waitReady(startup)
	cancel()
	if e != nil {
		return errors.New("credential host readiness failed; source config/auth is read-only and write-requiring migration or refresh is unsupported")
	}
	startup, cancel = context.WithTimeout(hostCtx, 30*time.Second)
	catalog, e := peer.call(startup, "GET", "/v1/models", nil)
	cancel()
	if e != nil {
		return errors.New("credential host catalog failed; source config/auth is read-only and write-requiring migration or refresh is unsupported")
	}
	selected, e := selectedCatalog(catalog, o.Model)
	if e != nil {
		return e
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return errors.New("private loopback listener unavailable")
	}
	defer listener.Close()
	secret := make([]byte, 32)
	if _, e = rand.Read(secret); e != nil {
		return e
	}
	token := hex.EncodeToString(secret)
	id := strings.SplitN(o.Model, "/", 2)[1]
	model := "factory-gateway/" + id
	// JSON is YAML 1.2 and accepted by omp's YAML loader. Pricing and reasoning
	// metadata are deliberately omitted: the official catalog does not expose them.
	models := map[string]any{"providers": map[string]any{"factory-gateway": map[string]any{"baseUrl": "http://" + listener.Addr().String() + "/v1", "api": "openai-completions", "apiKey": token, "models": []any{map[string]any{"id": id, "name": selected.Name, "input": selected.Input, "contextWindow": selected.Context, "maxTokens": selected.MaxTokens}}}}}
	if e = writePrivate(filepath.Join(o.RuntimeDir, "models.yml"), models); e != nil {
		return e
	}
	defer os.Remove(filepath.Join(o.RuntimeDir, "models.yml"))
	cfg := map[string]any{"modelRoles": map[string]any{"default": model, "smol": model, "slow": model, "tiny": model}, "enabledProviders": []string{"factory-gateway"}, "retry": map[string]any{"modelFallback": false, "fallbackChains": map[string]any{}}, "power": map[string]any{"sleepPrevention": "off"}}
	if e = writePrivate(filepath.Join(o.RuntimeDir, "config.yml"), cfg); e != nil {
		return e
	}
	defer os.Remove(filepath.Join(o.RuntimeDir, "config.yml"))
	g := &gateway{peer: peer, token: token, source: o.Model, model: model, catalog: selected, slots: make(chan struct{}, 4)}
	server := &http.Server{Handler: g, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: requestTimeout + 10*time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return hostCtx }}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	defer server.Close()
	if e = json.NewEncoder(out).Encode(Readiness{true, os.Getpid(), model, o.Model, o.RuntimeDir, version}); e != nil {
		return errors.New("readiness output failed")
	}
	select {
	case <-ctx.Done():
		return nil
	case <-peer.done:
		return errProtocol
	case <-exited:
		return errors.New("credential host exited")
	case <-served:
		return errors.New("credential listener stopped")
	}
}
