package factoryauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const requestLimit = 8 << 20
const requestTimeout = 4 * time.Minute

type catalogModel struct {
	ID        string   `json:"id"`
	OwnedBy   string   `json:"owned_by"`
	API       string   `json:"api"`
	Name      string   `json:"display_name"`
	Kind      string   `json:"kind"`
	Input     []string `json:"input_modalities"`
	Context   int      `json:"context_length"`
	MaxTokens int      `json:"max_output_tokens"`
	Tools     *bool    `json:"supports_tools"`
}

func selectedCatalog(r reply, source string) (catalogModel, error) {
	var c struct {
		Data []catalogModel `json:"data"`
	}
	if r.Status != 200 || json.Unmarshal(r.Body, &c) != nil {
		return catalogModel{}, errors.New("credential host catalog unavailable")
	}
	var found *catalogModel
	for _, m := range c.Data {
		if m.ID == source {
			if found != nil {
				return catalogModel{}, errors.New("ambiguous source model")
			}
			v := m
			found = &v
		}
	}
	if found == nil || found.Kind != "" && found.Kind != "chat" || found.Context <= 0 || found.MaxTokens <= 0 || found.API == "" || found.Tools != nil && !*found.Tools {
		return catalogModel{}, errors.New("selected source model lacks supported chat metadata")
	}
	text := false
	for _, v := range found.Input {
		if v == "text" {
			text = true
		}
		if v != "text" && v != "image" {
			return catalogModel{}, errors.New("unsupported source modality")
		}
	}
	if !text {
		return catalogModel{}, errors.New("selected source model lacks text modality")
	}
	return *found, nil
}

type gateway struct {
	peer          *transport
	token         string
	source, model string
	catalog       catalogModel
	slots         chan struct{}
}

func reject(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":{"message":"Factory credential request refused"}}`)
}
func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Authentication precedes route, body parsing, and every host operation.
	got := sha256.Sum256([]byte(r.Header.Get("Authorization")))
	want := sha256.Sum256([]byte("Bearer " + g.token))
	if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
		reject(w, 401)
		return
	}
	if r.URL.RawQuery != "" || r.URL.RawPath != "" {
		reject(w, 404)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/v1/models" {
		m := g.catalog
		m.ID = g.model
		m.OwnedBy = "factory-gateway"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": []catalogModel{m}})
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
		reject(w, 404)
		return
	}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		reject(w, 429)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, requestLimit))
	if e != nil {
		reject(w, 413)
		return
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(b, &body) != nil || body == nil {
		reject(w, 400)
		return
	}
	var model string
	if json.Unmarshal(body["model"], &model) != nil || (model != g.model && model != strings.TrimPrefix(g.model, "factory-gateway/")) {
		reject(w, 403)
		return
	}
	body["model"], _ = json.Marshal(g.source)
	var stream bool
	if raw, ok := body["stream"]; ok && json.Unmarshal(raw, &stream) != nil {
		reject(w, 400)
		return
	}
	response, e := g.peer.call(ctx, "POST", "/v1/chat/completions", body)
	if e != nil {
		reject(w, 502)
		return
	}
	// Upstream/provider error bodies may contain credentials or private URLs.
	if response.Status != 200 {
		reject(w, 502)
		return
	}
	if stream {
		var s string
		if json.Unmarshal(response.Body, &s) != nil || !validSSE(s, g.source) {
			g.peer.fail()
			reject(w, 502)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, s)
		return
	}
	var result struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(response.Body, &result) != nil || result.Model != g.source {
		g.peer.fail()
		reject(w, 502)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(response.Body)
}
func validSSE(s, model string) bool {
	seen, done := false, false
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		v := strings.TrimPrefix(line, "data: ")
		if v == "[DONE]" {
			done = true
			continue
		}
		if done {
			return false
		}
		var chunk struct {
			Model string `json:"model"`
		}
		if json.Unmarshal([]byte(v), &chunk) != nil || chunk.Model != model {
			return false
		}
		seen = true
	}
	return seen && done
}
