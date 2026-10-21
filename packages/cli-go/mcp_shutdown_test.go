package main

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestMCPSignalChild(t *testing.T) {
	if os.Getenv("SH_SIGNAL_TEST_CHILD") != "1" {
		return
	}
	if runMCP() != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestMCPSignalRunsGracefulShutdown(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not support Unix process signals")
	}
	for _, signal := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(signal.String(), func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestMCPSignalChild$")
			cmd.Env = append(os.Environ(), "SH_SIGNAL_TEST_CHILD=1", "SECRETHANDOFF_NO_BROWSER=1")
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal("could not start shutdown probe")
			}
			t.Cleanup(func() { stdin.Close(); cmd.Process.Kill() })
			io.WriteString(stdin, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"shutdown-test","version":"1"}}}`+"\n")
			initialized := make(chan error, 1)
			go func() { _, err := bufio.NewReader(stdout).ReadString('\n'); initialized <- err }()
			select {
			case err := <-initialized:
				if err != nil {
					t.Fatal("shutdown probe did not initialize")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("shutdown probe initialization timed out")
			}
			if err := cmd.Process.Signal(signal); err != nil {
				t.Fatal("could not signal shutdown probe")
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err := <-done:
				if err != nil || stderr.Len() != 0 {
					t.Fatal("signal did not shut down cleanly")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("signal did not stop MCP")
			}
		})
	}
}
