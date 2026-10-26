//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kunchenguid/no-mistakes/internal/factoryauth"
)

func TestFactoryAuthCancellationClosesInheritedStdinWithOwnerOpen(t *testing.T) {
	for _, transport := range []string{"pipe", "socketpair"} {
		t.Run(transport, func(t *testing.T) { testFactoryAuthInheritedControl(t, transport) })
	}
}

func testFactoryAuthInheritedControl(t *testing.T, transport string) {
	t.Helper()
	args, runtimeDir, pidFile := factoryAuthOwnerFixture(t, false)
	var descriptors [2]int
	if transport == "socketpair" {
		pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		descriptors = pair
	} else if err := syscall.Pipe2(descriptors[:], syscall.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	input := os.NewFile(uintptr(descriptors[0]), "inherited-blocking-stdin")
	owner := os.NewFile(uintptr(descriptors[1]), "controller-writer")
	defer input.Close()
	defer owner.Close()
	output, writer := io.Pipe()
	defer output.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := newAxiFactoryAuthCmd()
	cmd.SetContext(ctx)
	cmd.SetIn(input)
	cmd.SetOut(writer)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	completed := make(chan error, 1)
	go func() { completed <- cmd.Execute() }()
	ready := make(chan error, 1)
	go func() {
		var frame factoryauth.Readiness
		err := json.NewDecoder(output).Decode(&frame)
		if err == nil && !frame.Ready {
			err = io.ErrUnexpectedEOF
		}
		ready <- err
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("credential owner never became ready")
	}
	cancel()
	// Keep the real OS pipe's writer OPEN: SIGTERM/context cancellation must
	// interrupt the inherited reader itself, not wait for the owner to vanish.
	select {
	case err := <-completed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(8 * time.Second):
		_ = owner.Close()
		<-completed
		t.Fatal("cancel waited for owner EOF on inherited stdin")
	}
	if _, err := os.Stat(filepath.Join(runtimeDir, "models.yml")); !os.IsNotExist(err) {
		t.Fatalf("owned model configuration survived: %v", err)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range strings.Fields(string(data)) {
		pid, err := strconv.Atoi(value)
		if err != nil {
			t.Fatal(err)
		}
		factoryAuthAssertProcessGone(t, pid)
	}
}

func TestFactoryAuthRejectsNonStreamOwnerBeforeStartup(t *testing.T) {
	for _, transport := range []struct {
		name         string
		domain, kind int
	}{
		{"datagram", syscall.AF_UNIX, syscall.SOCK_DGRAM},
		{"packet", syscall.AF_UNIX, syscall.SOCK_SEQPACKET},
		{"inet", syscall.AF_INET, syscall.SOCK_STREAM},
	} {
		t.Run(transport.name, func(t *testing.T) {
			args, runtimeDir, pidFile := factoryAuthOwnerFixture(t, false)
			fd, err := syscall.Socket(transport.domain, transport.kind|syscall.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			input := os.NewFile(uintptr(fd), "unsupported-owner")
			defer input.Close()
			cmd := newAxiFactoryAuthCmd()
			cmd.SetIn(input)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs(args)
			if err := cmd.Execute(); err == nil {
				t.Fatal("unsupported owner reached credential startup")
			}
			for _, path := range []string{runtimeDir, pidFile} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("unsupported owner created %s: %v", path, err)
				}
			}
		})
	}
}
