// SPDX-License-Identifier: Apache-2.0

package vps

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestSealOpen(t *testing.T) {
	master := bytes.Repeat([]byte{7}, 32)
	_, sealer, _ := ed25519.GenerateKey(rand.Reader)
	cluster := [32]byte{1}
	key, err := DeriveKey(master, "iwinv-main")
	if err != nil {
		t.Fatal(err)
	}
	c := Credential{AccessKey: "ACCESS-abcd1234", SecretKey: "very-secret", SSHSeed: strings.Repeat("ab", 32)}
	s, err := Seal(cluster, "iwinv-main", "op-1", c, key, sealer)
	if err != nil {
		t.Fatal(err)
	}
	if s.Hint != "1234" || bytes.Contains(s.Box, []byte("very-secret")) || !strings.HasPrefix(s.SSHPublic, "ssh-ed25519 AAAA") || !strings.HasSuffix(s.SSHPublic, " sfc-iwinv-main") {
		t.Fatalf("sealed = %+v", s)
	}
	got, err := Open(s, key)
	if err != nil || got != c {
		t.Fatalf("open = %v", err)
	}
	other, _ := DeriveKey(master, "iwinv-b")
	if _, err := Open(s, other); err == nil {
		t.Fatal("opened with another account's key")
	}
	if _, ok := got.SSHSigner(); !ok {
		t.Fatal("ssh key lost")
	}
	if (Credential{AccessKey: "a", SecretKey: "b", SSHSeed: "zz"}).Valid() {
		t.Fatal("bad ssh seed accepted")
	}
	swapped := s
	swapped.SSHPublic = "ssh-ed25519 AAAAother sfc-iwinv-main"
	if swapped.Validate() == nil {
		t.Fatal("signature did not bind the ssh public key")
	}
	moved := s
	moved.Account = "iwinv-b"
	if moved.Validate() == nil {
		t.Fatal("signature did not bind the account")
	}
	if _, err := DeriveKey(master, "Bad_Name"); err == nil {
		t.Fatal("bad account name accepted")
	}
}
