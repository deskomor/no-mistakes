// Package factoryauth owns the Linux foreground credential boundary for Factory.
package factoryauth

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
)

const maxFrame = 32 << 20

var errProtocol = errors.New("credential host protocol failed")

type reply struct {
	ID       string          `json:"id"`
	Status   int             `json:"status"`
	Body     json.RawMessage `json:"body"`
	Encoding string          `json:"encoding"`
}
type transport struct {
	input   io.WriteCloser
	mu      sync.Mutex
	writeMu sync.Mutex
	pending map[string]chan reply
	next    uint64
	done    chan struct{}
	ready   chan string
	once    sync.Once
}

func newTransport(input io.WriteCloser, output io.Reader) *transport {
	p := &transport{input: input, pending: make(map[string]chan reply), done: make(chan struct{}), ready: make(chan string, 1)}
	go p.read(output)
	return p
}
func (p *transport) fail() { p.once.Do(func() { close(p.done); _ = p.input.Close() }) }
func supportedVersion(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	n := [3]int{}
	for i, s := range parts {
		x, e := strconv.Atoi(s)
		if e != nil || x < 0 {
			return false
		}
		n[i] = x
	}
	return n[0] > 18 || n[0] == 18 && (n[1] > 12 || n[1] == 12 && n[2] >= 3)
}
func (p *transport) read(output io.Reader) {
	defer p.fail()
	s := bufio.NewScanner(output)
	s.Buffer(make([]byte, 64<<10), maxFrame)
	if !s.Scan() {
		return
	}
	var ready struct {
		Ready   bool   `json:"ready"`
		Version string `json:"version"`
	}
	if json.Unmarshal(s.Bytes(), &ready) != nil || !ready.Ready || !supportedVersion(ready.Version) {
		return
	}
	p.ready <- ready.Version
	for s.Scan() {
		var r reply
		if json.Unmarshal(s.Bytes(), &r) != nil || r.ID == "" || r.Status < 100 || r.Status > 599 || len(r.Body) == 0 || r.Encoding != "" {
			return
		}
		p.mu.Lock()
		ch, ok := p.pending[r.ID]
		if ok {
			delete(p.pending, r.ID)
		}
		p.mu.Unlock()
		if !ok {
			return
		}
		ch <- r
	}
}
func (p *transport) waitReady(ctx context.Context) (string, error) {
	select {
	case v := <-p.ready:
		return v, nil
	case <-p.done:
		return "", errProtocol
	case <-ctx.Done():
		p.fail()
		return "", ctx.Err()
	}
}
func (p *transport) call(ctx context.Context, method, path string, body any) (reply, error) {
	if err := ctx.Err(); err != nil {
		return reply{}, err
	}
	// Unregister before returning: caller cleanup cancellation must not kill a
	// completed request's transport or unrelated in-flight requests.
	stopCancellation := context.AfterFunc(ctx, p.fail)
	defer stopCancellation()
	p.mu.Lock()
	p.next++
	id := strconv.FormatUint(p.next, 10)
	ch := make(chan reply, 1)
	p.pending[id] = ch
	p.mu.Unlock()
	frame, e := json.Marshal(struct {
		ID     string `json:"id"`
		Method string `json:"method"`
		Path   string `json:"path"`
		Body   any    `json:"body,omitempty"`
	}{id, method, path, body})
	if e != nil || len(frame) >= maxFrame {
		p.fail()
		return reply{}, errProtocol
	}
	p.writeMu.Lock()
	_, e = p.input.Write(append(frame, '\n'))
	p.writeMu.Unlock()
	if e != nil {
		p.fail()
		return reply{}, errProtocol
	}
	select {
	case r := <-ch:
		return r, nil
	case <-p.done:
		return reply{}, errProtocol
	case <-ctx.Done():
		// The official protocol has no per-request cancellation. Terminate this card's
		// host rather than leave inference running, accept late replies, or retry it.
		p.fail()
		return reply{}, ctx.Err()
	}
}
