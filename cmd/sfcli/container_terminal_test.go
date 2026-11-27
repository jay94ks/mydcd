// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestContainerOutputBrokenPipeDoesNotSliceNegativeWriteCount(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
	defer writer.Close()
	n, err := (containerOutput{ctx: context.Background(), writer: writer}).Write([]byte("bounded-output"))
	if n != 0 || !errors.Is(err, unix.EPIPE) {
		t.Fatal("broken output pipe did not preserve native failure", n, err)
	}
}

func TestContainerOutputCancellationKeepsUserFDAndFlags(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	fd := int(writer.Fd())
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Fill only this owned pipe, then restore its original blocking flag.
	if err = unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	for {
		_, err = unix.Write(fd, make([]byte, 4096))
		if errors.Is(err, unix.EAGAIN) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := (containerOutput{ctx: ctx, writer: writer}).Write([]byte("output")); done <- err }()
	cancel()
	select {
	case err = <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled CLI output retained writer")
	}
	after, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || after != flags {
		t.Fatal("CLI closed user FD or changed shared flags", err, after, flags)
	}
}
