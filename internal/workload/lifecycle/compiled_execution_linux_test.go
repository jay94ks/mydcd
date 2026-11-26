// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lifecycle

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCompiledExecutableKeepsExactBytesAndRejectsMutation(t *testing.T) {
	data := compiledTestELF(runtime.GOARCH)
	f, err := compiledExecutable(data)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = f.WriteAt([]byte{0}, 0); !errors.Is(err, unix.EPERM) {
		t.Fatal("executable bytes remained writable", err)
	}
	if err = f.Truncate(0); !errors.Is(err, unix.EPERM) {
		t.Fatal("executable remained truncatable", err)
	}
	read := make([]byte, len(data))
	if n, err := f.ReadAt(read, 0); err != nil || n != len(data) || !bytes.Equal(read, data) {
		t.Fatal("changed executable bytes", n, err)
	}
}

func TestCompiledDiagnosticLimitCancelsOriginalExecution(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var output bytes.Buffer
	w := &compiledRunDiagnostic{checkerDiagnostic: checkerDiagnostic{out: &output, remaining: 2}, cancel: cancel}
	if n, err := w.Write([]byte("ok")); n != 2 || err != nil || ctx.Err() != nil {
		t.Fatal(n, err, ctx.Err())
	}
	if _, err := w.Write([]byte("private-overflow")); err == nil || !w.exceeded() || ctx.Err() == nil || output.String() != "ok" {
		t.Fatal("output limit did not cancel or leaked overflow", err, ctx.Err(), output.Len())
	}
}
