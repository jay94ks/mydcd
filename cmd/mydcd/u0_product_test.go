// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

// U0 product boundary/rollback: build with the existing pinned offline cache,
// run one child daemon with disabled native modules, private DB/keys/socket and
// loopback UDP; stop/wait before deleting only this owned short temporary root.
func TestU0DaemonProductUnixStartupShutdownAndForeignPath(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root, err := os.MkdirTemp("", "mydc-u0-daemon-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	}()
	admin, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(admin.Private)
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.LocalAddr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	socket, file := filepath.Join(root, "management.sock"), filepath.Join(root, "node.yaml")
	text := fmt.Sprintf("version: 1\nnode:\n  id: node\n  listen: '%s'\n  state_dir: state\n  identity_dir: keys\n  management_socket: '%s'\nmodules:\n  network: {enabled: false}\n  workload: {enabled: false}\n  ingress: {enabled: false}\n", address, socket)
	if err := os.WriteFile(file, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	var initialized bytes.Buffer
	if code := run([]string{"--config", file, "init", "--admin-public-key", admin.Actor(), "--request-id", "init-u0"}, &initialized, io.Discard); code != 0 {
		t.Fatal("managed init", code)
	}
	var installed struct {
		Cluster string `json:"cluster"`
		NodeKey string `json:"node_key"`
	}
	if err := json.Unmarshal(initialized.Bytes(), &installed); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "mydcd")
	build := exec.CommandContext(ctx, "go", "build", "-p", "2", "-o", binary, "./cmd/mydcd")
	build.Dir = repo
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatal("daemon product build", err, string(output))
	}
	command := exec.CommandContext(ctx, binary, "--config", file, "run")
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	stopped := false
	stop := func() error {
		if stopped {
			return nil
		}
		_ = command.Process.Signal(syscall.SIGTERM)
		var err error
		select {
		case err = <-done:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			err = <-done
		}
		stopped = true
		return err
	}
	defer stop()
	started := make(chan error, 1)
	go func() {
		var event struct {
			Event  string `json:"event"`
			Socket string `json:"management_socket"`
		}
		err := json.NewDecoder(stdout).Decode(&event)
		if err == nil && (event.Event != "started" || event.Socket != socket) {
			err = fmt.Errorf("unexpected daemon startup metadata")
		}
		started <- err
	}()
	select {
	case err := <-started:
		if err != nil {
			_ = stop()
			t.Fatal("daemon startup", err, diagnostic.String())
		}
	case <-ctx.Done():
		_ = stop()
		t.Fatal("daemon startup", ctx.Err(), diagnostic.String())
	}
	public, err := mydcp.Discover(ctx, "unix", socket)
	if err != nil || hex.EncodeToString(public.Cluster[:]) != installed.Cluster || hex.EncodeToString(public.Key[:]) != installed.NodeKey || public.Node != "node" {
		t.Fatal("actual daemon Unix discovery", err)
	}
	if err := stop(); err != nil {
		t.Fatal("daemon normal shutdown", err, diagnostic.String())
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatal("owned socket not removed at daemon exit", err)
	}
	foreign := []byte("foreign path must survive check and failed run")
	if err := os.WriteFile(socket, foreign, 0600); err != nil {
		t.Fatal(err)
	}
	check := exec.CommandContext(ctx, binary, "--config", file, "check")
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatal("check must not bind/replace management path", err, string(output))
	}
	blocked := exec.CommandContext(ctx, binary, "--config", file, "run")
	output, err := blocked.CombinedOutput()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || !bytes.Contains(output, []byte("management socket path must be absent")) || bytes.Contains(output, []byte(`"event":"started"`)) {
		t.Fatal("daemon accepted foreign socket path", err, string(output))
	}
	if actual, err := os.ReadFile(socket); err != nil || !bytes.Equal(actual, foreign) {
		t.Fatal("daemon changed foreign path", err)
	}
	released, err := net.ListenPacket("udp4", address)
	if err != nil {
		t.Fatal("failed daemon left owned UDP listener", err)
	}
	if err := released.Close(); err != nil {
		t.Fatal(err)
	}
}
