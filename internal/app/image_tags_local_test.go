// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"
	"time"
)

func TestImageTagCopiesPersist(t *testing.T) {
	dir := t.TempDir()
	tag := "docker.io/library/alpine:latest"
	digest := "docker.io/library/alpine@sha256:" + "ab0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"[:64]
	c := newImageTagCopies(dir)
	if _, ok := c.Get("t1", tag); ok {
		t.Fatal("empty store returned a copy")
	}
	if err := c.Set("t1", tag, digest, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	again := newImageTagCopies(dir)
	if got, ok := again.Get("t1", tag); !ok || got != digest {
		t.Fatalf("reloaded copy = %q %v", got, ok)
	}
	if _, ok := again.Get("t2", tag); ok {
		t.Fatal("copy leaked across workspaces")
	}
}
