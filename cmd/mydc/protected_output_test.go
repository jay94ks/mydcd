// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegistryCredentialDestinationRejectsPublicReadOnlyAndStandardFDs(t *testing.T) {
	root := t.TempDir()
	for _, mode := range []os.FileMode{0600, 0644} {
		path := filepath.Join(root, mode.String())
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_EXCL, mode)
		if err != nil {
			t.Fatal(err)
		}
		if err = f.Chmod(mode); err != nil {
			t.Fatal(err)
		}
		dup, err := registryCredentialOutput(registryOutputFD{value: int(f.Fd()), set: true})
		if mode == 0600 {
			if err != nil {
				t.Fatal(err)
			}
			if _, err = dup.WriteString("derived-login-only"); err != nil {
				t.Fatal(err)
			}
			if err = dup.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = f.WriteString("-caller-still-open"); err != nil {
				t.Fatal("original descriptor was closed", err)
			}
		} else if err == nil {
			dup.Close()
			t.Fatal("public file accepted")
		}
		f.Close()
		ro, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if dup, err := registryCredentialOutput(registryOutputFD{value: int(ro.Fd()), set: true}); err == nil {
			dup.Close()
			t.Fatal("read-only destination accepted")
		}
		ro.Close()
	}
	for fd := 0; fd < 3; fd++ {
		if f, err := registryCredentialOutput(registryOutputFD{value: fd, set: true}); err == nil {
			f.Close()
			t.Fatal("credential sent to stdio")
		}
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	dup, err := registryCredentialOutput(registryOutputFD{value: int(w.Fd()), set: true})
	if err != nil {
		t.Fatal("explicit pipe rejected", err)
	}
	dup.Close()
}
