package factoryauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testGateway(p *transport) *gateway {
	return &gateway{peer: p, token: strings.Repeat("a", 64), source: "provider/model", model: "factory-gateway/model", slots: make(chan struct{}, 1)}
}
func gatewayRequest(g *gateway, method, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}
func TestAuthorizationAndScopeRefuseWithoutHost(t *testing.T) {
	// A nil peer makes any accidental forwarding fail loudly.
	g := testGateway(nil)
	for _, c := range []struct {
		method, path, body, token string
		status                    int
	}{
		{"POST", "/v1/chat/completions", "invalid", "", 401},
		{"POST", "/v1/chat/completions", `{"model":"other/model"}`, g.token, 403},
		{"POST", "/v1/chat/completions", `{"model":"model,other"}`, g.token, 403},
		{"POST", "/v1/chat/completions", `{"model":"model","stream":"yes"}`, g.token, 400},
		{"GET", "/v1/usage", "", g.token, 404},
		{"GET", "/v1/models?secret=x", "", g.token, 404},
		{"POST", "/v1/chat/completions", strings.Repeat("x", requestLimit+1), g.token, 413},
	} {
		w := gatewayRequest(g, c.method, c.path, c.body, c.token)
		if w.Code != c.status {
			t.Fatalf("%s %s status%d want%d", c.method, c.path, w.Code, c.status)
		}
	}
	w := gatewayRequest(g, "GET", "/v1/models", "", g.token)
	if w.Code != 200 || strings.Contains(w.Body.String(), "provider/model") || !strings.Contains(w.Body.String(), g.model) {
		t.Fatal(w.Body.String())
	}
	g.slots <- struct{}{}
	w = gatewayRequest(g, "POST", "/v1/chat/completions", `{"model":"model"}`, g.token)
	if w.Code != 429 {
		t.Fatal("inflight limit not enforced")
	}
}
func TestForwardingPinsSourceAndRedactsErrors(t *testing.T) {
	for _, c := range []struct {
		name, reply string
		status      int
	}{
		{"success", `"status":200,"body":{"model":"provider/model","choices":[]}`, 200},
		{"secret error", `"status":401,"body":{"error":"sensitive-provider-token"}`, 502},
		{"model mismatch", `"status":200,"body":{"model":"other/model","choices":[]}`, 502},
		{"stream mismatch", `"status":200,"body":"data: {\"model\":\"other/model\"}\n\ndata: [DONE]\n\n"`, 502},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, r, w := pipePeer(t)
			g := testGateway(p)
			result := make(chan *httptest.ResponseRecorder, 1)
			stream := c.name == "stream mismatch"
			go func() {
				result <- gatewayRequest(g, "POST", "/v1/chat/completions", fmt.Sprintf(`{"model":"model","messages":[],"stream":%t}`, stream), g.token)
			}()
			line, e := r.ReadBytes('\n')
			if e != nil {
				t.Fatal(e)
			}
			var req struct {
				ID   string `json:"id"`
				Path string `json:"path"`
				Body struct {
					Model string `json:"model"`
				} `json:"body"`
			}
			if e = json.Unmarshal(line, &req); e != nil {
				t.Fatal(e)
			}
			if req.Body.Model != g.source || req.Path != "/v1/chat/completions" {
				t.Fatalf("unpinned: %s", line)
			}
			_, _ = fmt.Fprintf(w, "{\"id\":%q,%s}\n", req.ID, c.reply)
			select {
			case got := <-result:
				if got.Code != c.status || strings.Contains(got.Body.String(), "sensitive-provider-token") {
					t.Fatalf("status/body: %d %s", got.Code, got.Body)
				}
			case <-time.After(time.Second):
				t.Fatal("request not answered")
			}
		})
	}
}
func TestClientDisconnectTerminatesOnlyOwnedTransport(t *testing.T) {
	p, r, _ := pipePeer(t)
	g := testGateway(p)
	other, _, _ := pipePeer(t)
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"model","messages":[]}`)).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+g.token)
	finished := make(chan struct{})
	go func() { g.ServeHTTP(httptest.NewRecorder(), req); close(finished) }()
	_ = requestID(t, r)
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("disconnected request survived")
	}
	select {
	case <-p.done:
	default:
		t.Fatal("owned host not disconnected")
	}
	select {
	case <-other.done:
		t.Fatal("other card disconnected")
	default:
	}
}
func TestCatalogRequiresActualSelectedMetadata(t *testing.T) {
	good := `{"data":[{"id":"provider/model","api":"anthropic-messages","display_name":"Model","context_length":200000,"max_output_tokens":32000,"input_modalities":["text","image"]}]}`
	for _, c := range []struct {
		body string
		ok   bool
	}{{good, true}, {strings.ReplaceAll(good, "provider/model", "other/model"), false}, {strings.ReplaceAll(good, "200000", "0"), false}, {strings.ReplaceAll(good, `"api":`, `"kind":"judge","api":`), false}, {strings.ReplaceAll(good, `"api":`, `"supports_tools":false,"api":`), false}} {
		_, e := selectedCatalog(reply{Status: 200, Body: json.RawMessage(c.body)}, "provider/model")
		if (e == nil) != c.ok {
			t.Fatalf("catalog accepted=%v: %s", e == nil, c.body)
		}
	}
}
func TestCompleteSSERequiresEveryChunkExactModel(t *testing.T) {
	good := "data: {\"model\":\"provider/model\",\"choices\":[]}\n\ndata: [DONE]\n\n"
	if !validSSE(good, "provider/model") {
		t.Fatal("valid stream refused")
	}
	for _, s := range []string{"", strings.ReplaceAll(good, "provider/model", "model"), strings.TrimSuffix(good, "data: [DONE]\n\n"), good + "data: {\"model\":\"provider/model\"}\n"} {
		if validSSE(s, "provider/model") {
			t.Fatalf("invalid stream accepted: %q", s)
		}
	}
}
