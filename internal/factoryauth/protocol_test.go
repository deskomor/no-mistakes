package factoryauth

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/kunchenguid/no-mistakes/internal/shellenv"
)

func pipePeer(t *testing.T) (*transport, *bufio.Reader, *io.PipeWriter) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	p := newTransport(inW, outR)
	t.Cleanup(func() { p.fail(); _ = inR.Close(); _ = outW.Close(); _ = outR.Close() })
	go func() { _, _ = io.WriteString(outW, "{\"ready\":true,\"version\":\"18.12.3\"}\n") }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, e := p.waitReady(ctx); e != nil {
		t.Fatal(e)
	}
	return p, bufio.NewReader(inR), outW
}
func requestID(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	line, e := r.ReadBytes('\n')
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		ID string `json:"id"`
	}
	if e = json.Unmarshal(line, &v); e != nil {
		t.Fatal(e)
	}
	return v.ID
}
func TestRepliesAreCorrelatedNotArrivalOrdered(t *testing.T) {
	p, r, w := pipePeer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	type result struct {
		r reply
		e error
	}
	a, b := make(chan result, 1), make(chan result, 1)
	go func() { v, e := p.call(ctx, "GET", "/first", nil); a <- result{v, e} }()
	first := requestID(t, r)
	go func() { v, e := p.call(ctx, "GET", "/second", nil); b <- result{v, e} }()
	second := requestID(t, r)
	_, _ = fmt.Fprintf(w, "{\"id\":%q,\"status\":200,\"body\":{\"value\":2}}\n", second)
	rb := <-b
	if rb.e != nil || !strings.Contains(string(rb.r.Body), "2") {
		t.Fatalf("second: %+v", rb)
	}
	select {
	case <-a:
		t.Fatal("first completed on second reply")
	default:
	}
	_, _ = fmt.Fprintf(w, "{\"id\":%q,\"status\":200,\"body\":{\"value\":1}}\n", first)
	ra := <-a
	if ra.e != nil || !strings.Contains(string(ra.r.Body), "1") {
		t.Fatalf("first: %+v", ra)
	}
	// A duplicate is fatal, never reassigned to another outstanding request.
	_, _ = fmt.Fprintf(w, "{\"id\":%q,\"status\":200,\"body\":{}}\n", first)
	select {
	case <-p.done:
	case <-ctx.Done():
		t.Fatal("duplicate did not close transport")
	}
}

func TestCompletedCallCleanupKeepsTransportUsable(t *testing.T) {
	p, r, w := pipePeer(t)
	go func() {
		for {
			line, err := r.ReadBytes('\n')
			if err != nil {
				return
			}
			var request struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(line, &request) != nil {
				return
			}
			if _, err := fmt.Fprintf(w, "{\"id\":%q,\"status\":200,\"body\":{\"available\":true}}\n", request.ID); err != nil {
				return
			}
		}
	}()
	for i := 0; i < 1024; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		response, err := p.call(ctx, "GET", "/v1/models", nil)
		cancel()
		if err != nil || response.Status != 200 || string(response.Body) != `{"available":true}` {
			t.Fatalf("cleanup of a completed request killed subsequent request %d: response=%+v err=%v", i, response, err)
		}
	}
}
func TestReadinessAndProtocolFailures(t *testing.T) {
	for _, line := range []string{"", "not-json\n", "{\"ready\":false,\"version\":\"18.12.3\"}\n", "{\"ready\":true,\"version\":\"18.12.2\"}\n", "{\"id\":\"1\",\"status\":200,\"body\":{}}\n"} {
		t.Run(fmt.Sprintf("%q", line), func(t *testing.T) {
			inR, inW := io.Pipe()
			p := newTransport(inW, strings.NewReader(line))
			defer inR.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, e := p.waitReady(ctx); e == nil {
				t.Fatal("accepted invalid initial frame")
			}
		})
	}
	for _, frame := range []string{"garbage\n", "{\"id\":\"unissued\",\"status\":200,\"body\":{}}\n", "{\"id\":1,\"status\":200,\"body\":{}}\n"} {
		t.Run(frame, func(t *testing.T) {
			p, _, w := pipePeer(t)
			_, _ = io.WriteString(w, frame)
			select {
			case <-p.done:
			case <-time.After(time.Second):
				t.Fatal("bad reply accepted")
			}
		})
	}
}
func TestCancellationUnblocksPipeWriteAndLeavesOtherPeerAlive(t *testing.T) {
	p, _, _ := pipePeer(t)
	other, _, _ := pipePeer(t)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, e := p.call(ctx, "POST", "/v1/chat/completions", map[string]string{"model": "p/m"})
		result <- e
	}()
	cancel()
	select {
	case e := <-result:
		if e == nil {
			t.Fatal("cancel succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked write survived cancellation")
	}
	select {
	case <-other.done:
		t.Fatal("cancelled another card")
	default:
	}
}

// This process is a deliberately non-cooperating peer; cancellation must reap
// the actual subprocess even though the protocol has no cancellation frame.
func TestStdioPeerHelper(t *testing.T) {
	if os.Getenv("FACTORY_AUTH_TEST_PEER") != "1" {
		return
	}
	_, _ = fmt.Fprintln(os.Stdout, `{"ready":true,"version":"18.12.3"}`)
	for {
		time.Sleep(time.Hour)
	}
}
func TestPeerProcessIsReapedOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStdioPeerHelper$")
	cmd.Env = []string{"FACTORY_AUTH_TEST_PEER=1", "HOME=" + t.TempDir()}
	shellenv.ConfigureShellCommand(cmd)
	in, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	out, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = shellenv.StartShellCommand(cmd); e != nil {
		t.Fatal(e)
	}
	defer shellenv.TerminateShellCommandGroup(cmd)
	p := newTransport(in, out)
	defer p.fail()
	readyCtx, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	if _, e = p.waitReady(readyCtx); e != nil {
		cancel()
		_ = cmd.Wait()
		t.Fatal(e)
	}
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	cancel()
	select {
	case e := <-wait:
		if e == nil {
			t.Fatal("non-cooperating peer exited successfully")
		}
		if cmd.ProcessState == nil {
			t.Fatal("child not reaped")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("credential subprocess survived cancellation")
	}
}
