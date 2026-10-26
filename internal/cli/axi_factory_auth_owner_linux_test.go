//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// This fixture deliberately fakes bwrap, not the ownership implementation: the
// command still starts a real peer and descendant, owns a real flock, writes its
// runtime configuration and serves its readiness frame. Sandbox policy is tested
// separately in factoryauth; no credentials or ambient configuration are used.
func factoryAuthOwnerFixture(t *testing.T, startupFailure bool) (args []string, runtimeDir, pidFile string) {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "source-home")
	agent := filepath.Join(home, ".omp", "agent")
	bin := filepath.Join(root, "bin")
	for _, dir := range []string{agent, bin} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, contents string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(contents), 0700); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(bin, "bwrap"), "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n if [ \"$1\" = -- ]; then shift; exec \"$@\"; fi\n shift\ndone\nexit 91\n")
	pidFile = filepath.Join(root, "peer-pids")
	quotedPIDFile := "'" + strings.ReplaceAll(pidFile, "'", "'\"'\"'") + "'"
	peer := "#!/bin/sh\n"
	if startupFailure {
		peer += "exit 17\n"
	} else {
		peer += "sleep 300 &\nprintf '%s %s\\n' \"$$\" \"$!\" > " + quotedPIDFile + "\n" +
			"printf '%s\\n' '{\"ready\":true,\"version\":\"18.12.3\"}'\n" +
			"while IFS= read -r request; do\n" +
			" id=${request#*\\\"id\\\":\\\"}; id=${id%%\\\"*}\n" +
			" printf '{\"id\":\"%s\",\"status\":200,\"body\":{\"data\":[{\"id\":\"dummy/model\",\"api\":\"openai-completions\",\"display_name\":\"Dummy\",\"input_modalities\":[\"text\"],\"context_length\":4096,\"max_output_tokens\":128,\"supports_tools\":true}]}}\\n' \"$id\"\n" +
			"done\nwait\n"
	}
	omp := filepath.Join(bin, "omp")
	write(omp, peer)
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	runtimeDir = filepath.Join(root, "runtime")
	return []string{"--omp", omp, "--source-home", home, "--source-agent-dir", agent, "--runtime-dir", runtimeDir, "--model", "dummy/model"}, runtimeDir, pidFile
}

func TestFactoryAuthControllingStdinLifetime(t *testing.T) {
	for _, readFailure := range []bool{false, true} {
		t.Run(fmt.Sprintf("readFailure=%t", readFailure), func(t *testing.T) {
			args, runtimeDir, pidFile := factoryAuthOwnerFixture(t, false)
			input, owner := io.Pipe()
			output, readiness := io.Pipe()
			ctx, cancel := context.WithCancel(context.Background())
			cmd := newAxiFactoryAuthCmd()
			cmd.SetArgs(args)
			cmd.SetContext(ctx)
			cmd.SetIn(input)
			cmd.SetOut(readiness)
			cmd.SetErr(io.Discard)
			finished := make(chan error, 1)
			exited := make(chan struct{})
			go func() {
				defer close(exited)
				err := cmd.Execute()
				_ = readiness.Close()
				finished <- err
			}()
			t.Cleanup(func() {
				cancel()
				_ = owner.Close()
				_ = output.Close()
				select {
				case <-exited:
				case <-time.After(8 * time.Second):
					t.Error("credential command did not finish fixture cleanup")
				}
			})
			type readyResult struct {
				value factoryauth.Readiness
				err   error
			}
			ready := make(chan readyResult, 1)
			go func() {
				var value factoryauth.Readiness
				err := json.NewDecoder(output).Decode(&value)
				ready <- readyResult{value, err}
			}()
			select {
			case result := <-ready:
				if result.err != nil || !result.value.Ready || result.value.Model != "factory-gateway/model" || result.value.RuntimeDir != runtimeDir {
					t.Fatalf("readiness: %+v, %v", result.value, result.err)
				}
			case <-time.After(8 * time.Second):
				t.Fatal("command did not become ready with owner pipe open")
			}
			for _, name := range []string{"models.yml", "config.yml"} {
				if _, err := os.Stat(filepath.Join(runtimeDir, name)); err != nil {
					t.Fatalf("ready without %s: %v", name, err)
				}
			}
			lock, err := os.OpenFile(filepath.Join(runtimeDir, ".factory-auth.lock"), os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
				_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
				t.Fatal("ready command did not hold runtime lock")
			}
			pids, err := os.ReadFile(pidFile)
			if err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-finished:
				t.Fatalf("command exited while owner input was open: %v", err)
			default:
			}
			if readFailure {
				_ = owner.CloseWithError(errors.New("controller input failed"))
			} else {
				_ = owner.Close()
			}
			select {
			case err := <-finished:
				if err != nil {
					t.Fatalf("owner disconnect failed: %v", err)
				}
			case <-time.After(8 * time.Second):
				t.Fatal("command survived controlling stdin disappearance")
			}
			for _, name := range []string{"models.yml", "config.yml"} {
				if _, err := os.Stat(filepath.Join(runtimeDir, name)); !os.IsNotExist(err) {
					t.Fatalf("owned %s survived exit: %v", name, err)
				}
			}
			if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				t.Fatalf("runtime lock survived owner disappearance: %v", err)
			}
			_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			for _, value := range strings.Fields(string(pids)) {
				pid, err := strconv.Atoi(value)
				if err != nil || pid <= 1 {
					t.Fatalf("invalid fixture pid %q", value)
				}
				factoryAuthAssertProcessGone(t, pid)
			}
		})
	}
}

func factoryAuthAssertProcessGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if os.IsNotExist(err) {
			return
		}
		if err == nil {
			end := strings.LastIndex(string(stat), ") ")
			if end >= 0 && strings.HasPrefix(string(stat)[end+2:], "Z ") {
				return // Dead; init owns zombie bookkeeping.
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("credential peer/descendant %d survived owner disappearance", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestFactoryAuthStartupFailureClosesControllingReader(t *testing.T) {
	args, runtimeDir, _ := factoryAuthOwnerFixture(t, true)
	input, owner := io.Pipe()
	defer owner.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := newAxiFactoryAuthCmd()
	cmd.SetArgs(args)
	cmd.SetContext(ctx)
	cmd.SetIn(input)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err == nil {
		t.Fatal("failed credential peer was accepted")
	}
	if _, err := owner.Write([]byte("still owned?")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("controlling reader remained open after startup failure: %v", err)
	}
	lock, err := os.OpenFile(filepath.Join(runtimeDir, ".factory-auth.lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("startup failure retained runtime lock: %v", err)
	}
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	for _, name := range []string{"models.yml", "config.yml"} {
		if _, err := os.Stat(filepath.Join(runtimeDir, name)); !os.IsNotExist(err) {
			t.Fatalf("startup failure retained %s: %v", name, err)
		}
	}
}
