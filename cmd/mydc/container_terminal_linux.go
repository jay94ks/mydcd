// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/userauth"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func containerTerminalSize(file *os.File) (uint16, uint16) {
	cols, rows, err := term.GetSize(int(file.Fd()))
	if err != nil || rows < 1 || cols < 1 || rows > 65535 || cols > 65535 {
		return 24, 80
	}
	return uint16(rows), uint16(cols)
}
func makeContainerTerminalRaw(file *os.File) (func(), error) {
	fd := int(file.Fd())
	if !term.IsTerminal(fd) {
		return func() {}, nil
	}
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	return func() { _ = term.Restore(fd, state) }, nil
}

func containerPoll(ctx context.Context, fd int, event int16) error {
	poll := []unix.PollFd{{Fd: int32(fd), Events: event}}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := unix.Poll(poll, 100)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		if poll[0].Revents&unix.POLLNVAL != 0 {
			return os.ErrClosed
		}
		if poll[0].Revents&(event|unix.POLLHUP|unix.POLLERR) != 0 {
			return nil
		}
	}
}

func containerInput(ctx context.Context, file *os.File, channel *userauth.ContainerChannel) <-chan error {
	done := make(chan error, 1)
	go func() {
		var result error
		defer func() {
			if result != nil && ctx.Err() == nil {
				_ = channel.Close()
			}
			done <- result
		}()
		buffer := make([]byte, containerops.SessionChunkBytes)
		for {
			if result = containerPoll(ctx, int(file.Fd()), unix.POLLIN); result != nil {
				return
			}
			n, err := unix.Read(int(file.Fd()), buffer)
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
				continue
			}
			if n > 0 {
				if result = channel.Send(containerops.SessionRecord{Kind: "stdin", Data: buffer[:n]}); result != nil {
					return
				}
			}
			if err != nil {
				result = err
				return
			}
			if n == 0 {
				result = channel.Send(containerops.SessionRecord{Kind: "stdin-eof"})
				return
			}
		}
	}()
	return done
}

func containerWindow(ctx context.Context, file *os.File, channel *userauth.ContainerChannel) <-chan error {
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
				if err := channel.Send(containerops.SessionRecord{Kind: "resize", Rows: rows, Cols: cols}); err != nil {
					_ = channel.Close()
					done <- err
					return
				}
			}
		}
	}()
	return done
}

// CLI owns its stdin/stdout stream readers/writers. Poll in bounded chunks
// makes ordinary terminal/pipe backpressure cancellable without closing the
// user's original file descriptors or changing their shared O_NONBLOCK flags.
type containerOutput struct {
	ctx    context.Context
	writer io.Writer
}

func (w containerOutput) Write(p []byte) (int, error) {
	file, ok := w.writer.(*os.File)
	if !ok {
		if err := w.ctx.Err(); err != nil {
			return 0, err
		}
		return w.writer.Write(p)
	}
	total := 0
	for len(p) > 0 {
		if err := containerPoll(w.ctx, int(file.Fd()), unix.POLLOUT); err != nil {
			return total, err
		}
		size := min(len(p), 4096)
		n, err := unix.Write(int(file.Fd()), p[:size])
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		if n > 0 {
			total += n
			p = p[n:]
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}
