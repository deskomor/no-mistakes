package factoryauth

import (
	"context"
	"testing"
	"time"
)

func TestEOFRejectsOutstandingRequestWithoutRetry(t *testing.T) {
	p, r, w := pipePeer(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, e := p.call(ctx, "POST", "/v1/chat/completions", map[string]string{"model": "provider/model"})
		result <- e
	}()
	_ = requestID(t, r)
	_ = w.Close()
	select {
	case e := <-result:
		if e == nil {
			t.Fatal("EOF accepted as successful inference")
		}
	case <-ctx.Done():
		t.Fatal("EOF did not resolve pending request")
	}
	select {
	case <-p.done:
	default:
		t.Fatal("EOF left transport usable")
	}
}
