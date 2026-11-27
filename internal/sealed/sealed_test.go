// SPDX-License-Identifier: Apache-2.0

package sealed

import (
	"bytes"
	"testing"
)

func TestSealBindsMasterSaltInfoAndAAD(t *testing.T) {
	master := bytes.Repeat([]byte{1}, 32)
	plain := []byte("private value")
	box, err := Seal(master, []byte("salt"), "sfc/test/v1", plain, []byte("aad"))
	if err != nil || bytes.Contains(box, plain) || len(box) != len(plain)+Overhead {
		t.Fatal("seal", err)
	}
	if got, err := Open(master, []byte("salt"), "sfc/test/v1", box, []byte("aad")); err != nil || !bytes.Equal(got, plain) {
		t.Fatal("open", err)
	}
	for _, c := range []struct {
		master, salt []byte
		info, aad    string
	}{
		{bytes.Repeat([]byte{2}, 32), []byte("salt"), "sfc/test/v1", "aad"},
		{master, []byte("other"), "sfc/test/v1", "aad"},
		{master, []byte("salt"), "sfc/other/v1", "aad"},
		{master, []byte("salt"), "sfc/test/v1", "moved"},
	} {
		if _, err := Open(c.master, c.salt, c.info, box, []byte(c.aad)); err == nil {
			t.Fatal("opened with a different binding", c.info, c.aad)
		}
	}
	if _, err := Seal(master[:31], []byte("salt"), "sfc/test/v1", plain, nil); err == nil {
		t.Fatal("short master accepted")
	}
}
