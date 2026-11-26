// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
	"golang.org/x/sys/unix"
)

func runNodeShellTerminal(ctx context.Context, c *userauth.NodeShellChannel, out, diagnostic io.Writer) int {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	input := nodeShellInput(ctx, os.Stdin, c)
	window := nodeShellWindow(ctx, os.Stdin, c)
	heartbeat := nodeShellHeartbeat(ctx, c)
	defer func() { cancel(); _ = c.Close(); <-input; <-window; <-heartbeat }()
	writer := containerOutput{ctx: ctx, writer: out}
	for {
		r, err := c.Receive()
		if err != nil {
			return failure(diagnostic, errors.New("node shell disconnected; check it with mydc node shell sessions; no new shell was opened"), 4)
		}
		switch r.Kind {
		case "stdout":
			_, err = writer.Write(r.Data)
			clear(r.Data)
		case "end":
			if r.End.ClosedBy != nil {
				_, err = fmtNodeShellClosed(diagnostic, r.End)
			}
			if err != nil {
				return failure(diagnostic, err, 1)
			}
			return r.End.Code
		}
		if err != nil {
			return failure(diagnostic, err, 1)
		}
	}
}
func fmtNodeShellClosed(out io.Writer, end *mydcp.NodeShellEnd) (int, error) {
	return io.WriteString(out, "\r\nnode shell "+end.Reason+" by "+end.ClosedBy.Username+" ("+end.ClosedBy.User+")\r\n")
}
func nodeShellInput(ctx context.Context, file *os.File, c *userauth.NodeShellChannel) <-chan error {
	done := make(chan error, 1)
	go func() {
		var result error
		defer func() {
			if result != nil && ctx.Err() == nil {
				_ = c.Close()
			}
			done <- result
		}()
		buffer := make([]byte, mydcp.NodeShellChunkBytes)
		defer clear(buffer)
		for {
			if result = containerPoll(ctx, int(file.Fd()), unix.POLLIN); result != nil {
				return
			}
			n, err := unix.Read(int(file.Fd()), buffer)
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
				continue
			}
			if n > 0 {
				if result = c.Send(mydcp.NodeShellRecord{Kind: "stdin", Data: buffer[:n]}); result != nil {
					return
				}
			}
			if err != nil {
				result = err
				return
			}
			if n == 0 {
				result = c.Send(mydcp.NodeShellRecord{Kind: "half-close"})
				return
			}
		}
	}()
	return done
}
func nodeShellWindow(ctx context.Context, file *os.File, c *userauth.NodeShellChannel) <-chan error {
	done := make(chan error, 1)
	window := make(chan os.Signal, 1)
	signal.Notify(window, syscall.SIGWINCH)
	go func() {
		defer signal.Stop(window)
		for {
			select {
			case <-ctx.Done():
				done <- ctx.Err()
				return
			case <-window:
				rows, cols := containerTerminalSize(file)
				if err := c.Send(mydcp.NodeShellRecord{Kind: "resize", Rows: rows, Cols: cols}); err != nil {
					_ = c.Close()
					done <- err
					return
				}
			}
		}
	}()
	return done
}
