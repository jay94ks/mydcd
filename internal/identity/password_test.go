// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestPasswordLibraryProtectedRoundTripAndBoundedKDF(t *testing.T) {
	v, err := PasswordHash([]byte("private-password"), bytes.Repeat([]byte{7}, 16), DefaultPasswordCost())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := v.ProtectedBytes()
	if err != nil {
		t.Fatal(err)
	}
	r, err := RestorePasswordVerifier(raw)
	if err != nil || !r.Verify([]byte("private-password")) || r.Verify([]byte("different")) {
		t.Fatal("password mismatch", err)
	}
	raw[len(raw)-1] ^= 1
	if !r.Verify([]byte("private-password")) {
		t.Fatal("restored private material aliased input")
	}
	if _, err = json.Marshal(v); err == nil {
		t.Fatal("private verifier serialized")
	}
	if fmt.Sprintf("%#v", v) != "[redacted password verifier]" {
		t.Fatal("private verifier formatted")
	}
	for _, cost := range []PasswordCost{{Memory: 1, Iterations: 1, Threads: 1}, {Memory: 65 * 1024, Iterations: 1, Threads: 1}, {Memory: 8 * 1024, Iterations: 0, Threads: 1}, {Memory: 8 * 1024, Iterations: 1, Threads: 3}} {
		if _, err = PasswordHash([]byte("private"), bytes.Repeat([]byte{1}, 16), cost); err == nil {
			t.Fatal("unbounded/invalid KDF")
		}
	}
	for _, data := range [][]byte{nil, raw[:10], append(bytes.Clone(raw), 0)} {
		if _, err = RestorePasswordVerifier(data); err == nil {
			t.Fatal("invalid private encoding")
		}
	}
}
func TestPasswordTerminalRejectsEchoedPipeInput(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if value, err := ReadPassword(int(r.Fd())); err == nil || len(value) != 0 {
		t.Fatal("echoed/non-terminal input accepted")
	}
}
