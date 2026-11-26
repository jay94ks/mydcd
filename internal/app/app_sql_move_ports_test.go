// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

const (
	sqlMoveBlockedTCP = "192.0.2.2:8081"
	sqlMoveBlockedUDP = "192.0.2.2:8444"
)

// This owned fixture holds real sockets in node-b's existing private netns.
// It never reads a product frame, serves application traffic or reports Ready.
func TestManagedMovePortBlocker(t *testing.T) {
	marker := os.Getenv("MYDC_MOVE_PORT_BLOCKER")
	if marker == "" {
		t.Skip("owned SQL move port fixture only")
	}
	namespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil || !filepath.IsAbs(marker) || namespace == os.Getenv("MYDC_KERNEL_HOST_NETNS") || os.Getenv("MYDC_KERNEL_HOST_NETNS") == "" {
		t.Fatal("private namespace and owned absolute marker required", err)
	}
	tcp, err := net.Listen("tcp4", sqlMoveBlockedTCP)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp4", sqlMoveBlockedUDP)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	publish := func(stage string) {
		t.Helper()
		if err := os.WriteFile(marker+"."+stage, []byte(stage+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	publish("ready")
	input := bufio.NewScanner(os.Stdin)
	for _, stage := range []string{"tcp", "udp"} {
		if !input.Scan() {
			if err := input.Err(); err != nil {
				t.Fatal(err)
			}
			return // Parent cleanup closed its owned control pipe.
		}
		if input.Text() != stage {
			t.Fatal("unexpected owned port release order")
		}
		var err error
		if stage == "tcp" {
			err = tcp.Close()
		} else {
			err = udp.Close()
		}
		if err != nil {
			t.Fatal(err)
		}
		publish(stage)
	}
}

func holdSQLMovePorts(t *testing.T, ctx context.Context, root, namespace string, wait func(string, func() bool)) func(string) {
	t.Helper()
	if !filepath.IsAbs(namespace) {
		t.Fatal("original node-b namespace path required")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "sql-move-port-blocker")
	log, err := os.Create(marker + ".log")
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command("nsenter", "--net="+namespace, "--", self, "-test.run=^TestManagedMovePortBlocker$", "-test.v", "-test.timeout=490s")
	child.Env = append(os.Environ(), "MYDC_MOVE_PORT_BLOCKER="+marker)
	child.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	child.Stdout, child.Stderr = log, log
	input, err := child.StdinPipe()
	if err != nil {
		log.Close()
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		input.Close()
		log.Close()
		t.Fatal(err)
	}
	finished := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = child.Wait()
		_ = log.Close()
		close(finished)
	}()
	t.Cleanup(func() {
		_ = input.Close()
		select {
		case <-finished:
		default:
			_ = child.Process.Kill()
			<-finished
		}
	})
	markerReady := func(stage string) bool {
		t.Helper()
		if _, err := os.Stat(marker + "." + stage); err == nil {
			return true
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case <-finished:
			raw, _ := os.ReadFile(marker + ".log")
			t.Fatal("owned port blocker exited before "+stage, waitErr, string(raw))
		default:
		}
		return false
	}
	wait("owned node-b child holds actual declared TCP/HTTP3 UDP ports", func() bool { return markerReady("ready") })
	releasedTCP := false
	return func(stage string) {
		t.Helper()
		if stage != "tcp" && stage != "udp" || stage == "tcp" && releasedTCP || stage == "udp" && !releasedTCP {
			t.Fatal("invalid owned port release order")
		}
		if _, err := io.WriteString(input, stage+"\n"); err != nil {
			t.Fatal(err)
		}
		wait("owned "+stage+" socket positively closed", func() bool { return markerReady(stage) })
		if stage == "tcp" {
			releasedTCP = true
			return
		}
		_ = input.Close()
		select {
		case <-finished:
			if waitErr != nil {
				t.Fatal("owned port blocker Wait", waitErr)
			}
		case <-ctx.Done():
			t.Fatal("owned port blocker Wait", ctx.Err())
		}
	}
}
