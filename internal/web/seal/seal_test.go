// SPDX-License-Identifier: Apache-2.0

package seal

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, KeySize) }

func TestRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	b, err := Open(dir, key(1))
	if err != nil || !b.Ready() {
		t.Fatalf("open: %v %v", b.state, err)
	}
	if err := b.Put("ai-claude", []byte("sk-ant-secret-1234")); err != nil {
		t.Fatal(err)
	}
	if err := b.Put("dns-cf1", []byte("tok")); err != nil {
		t.Fatal(err)
	}
	v, err := b.Get("ai-claude")
	if err != nil || string(v) != "sk-ant-secret-1234" {
		t.Fatalf("get: %q %v", v, err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "ai-claude"))
	if bytes.Contains(raw, []byte("secret")) {
		t.Fatal("plaintext on disk")
	}
	for _, p := range []string{dir, filepath.Join(dir, "ai-claude")} {
		fi, _ := os.Stat(p)
		if fi.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s mode %v", p, fi.Mode())
		}
	}
	names, _ := b.List()
	if strings.Join(names, ",") != "ai-claude,dns-cf1" {
		t.Fatalf("list: %v", names)
	}
	if err := b.Delete("dns-cf1"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get("dns-cf1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted: %v", err)
	}
	if err := b.Delete("dns-cf1"); err != nil {
		t.Fatalf("delete missing: %v", err)
	}

	// reopen with the same key
	b2, _ := Open(dir, key(1))
	if v, err := b2.Get("ai-claude"); err != nil || string(v) != "sk-ant-secret-1234" {
		t.Fatalf("reopen: %q %v", v, err)
	}
}

func TestNoKeyAndWrongKey(t *testing.T) {
	dir := t.TempDir()
	b, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := b.Status(); st != StateNoKey {
		t.Fatalf("state %v", st)
	}
	if err := b.Put("x", []byte("v")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("put without key: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("no-key box must not write")
	}

	good, _ := Open(dir, key(1))
	good.Put("ai-openai", []byte("v"))
	bad, err := Open(dir, key(2))
	if err != nil {
		t.Fatal(err)
	}
	if st, reason := bad.Status(); st != StateWrongKey || reason == "" {
		t.Fatalf("wrong key: %v %q", st, reason)
	}
	if _, err := bad.Get("ai-openai"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("get with wrong key: %v", err)
	}
	if _, err := Open(dir, []byte("short")); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestTamperAndRename(t *testing.T) {
	dir := t.TempDir()
	b, _ := Open(dir, key(1))
	b.Put("a", []byte("value-a"))
	// a file moved to another name does not open
	raw, _ := os.ReadFile(filepath.Join(dir, "a"))
	os.WriteFile(filepath.Join(dir, "b"), raw, 0o600)
	if _, err := b.Get("b"); err == nil {
		t.Fatal("renamed file opened")
	}
	// a flipped byte does not open
	raw[len(raw)-1] ^= 1
	os.WriteFile(filepath.Join(dir, "a"), raw, 0o600)
	if _, err := b.Get("a"); err == nil {
		t.Fatal("damaged file opened")
	}
}

func TestNames(t *testing.T) {
	for _, n := range []string{"ai-claude", "dns-01", "acme-le.account"} {
		if !ValidName(n) {
			t.Errorf("%q rejected", n)
		}
	}
	for _, n := range []string{"", "_check", ".tmp-1", "../x", "a/b", "A", "a..b", strings.Repeat("a", 129)} {
		if ValidName(n) {
			t.Errorf("%q accepted", n)
		}
	}
}

func TestParseKey(t *testing.T) {
	k := key(7)
	for _, s := range []string{hex.EncodeToString(k) + "\n", "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="} {
		got, err := ParseKey(s)
		if err != nil || !bytes.Equal(got, k) {
			t.Errorf("%q: %x %v", s, got, err)
		}
	}
	if k, err := ParseKey("  "); err != nil || k != nil {
		t.Errorf("empty: %v %v", k, err)
	}
	if _, err := ParseKey("abcd"); err == nil {
		t.Error("short key accepted")
	}
	if Hint([]byte("sk-ant-0123456789")) != "…6789" || Hint([]byte("short")) != "" {
		t.Error("hint")
	}
}

func TestRekey(t *testing.T) {
	dir := t.TempDir()
	b, _ := Open(dir, key(1))
	b.Put("ai-claude", []byte("one"))
	b.Put("dns-a", []byte("two"))

	ch, _ := OpenRekey(dir, key(1), key(2))
	if !ch.Ready() {
		t.Fatal(ch.Status())
	}
	// every file and the check now open with the new key alone
	nb, _ := Open(dir, key(2))
	if !nb.Ready() {
		t.Fatal(nb.Status())
	}
	for n, want := range map[string]string{"ai-claude": "one", "dns-a": "two"} {
		if v, err := nb.Get(n); err != nil || string(v) != want {
			t.Fatalf("%s: %q %v", n, v, err)
		}
	}
	if old, _ := Open(dir, key(1)); old.Ready() {
		t.Fatal("old key still opens after the change")
	}
	// starting again with both keys (the old one not yet swapped) is harmless
	again, _ := OpenRekey(dir, key(1), key(2))
	if !again.Ready() {
		t.Fatal(again.Status())
	}
	if v, _ := again.Get("dns-a"); string(v) != "two" {
		t.Fatalf("after second run: %q", v)
	}
}

func TestRekeyResumes(t *testing.T) {
	dir := t.TempDir()
	b, _ := Open(dir, key(1))
	b.Put("a", []byte("A"))
	b.Put("b", []byte("B"))
	// simulate a crash after "a" was sealed again with key 2
	two, id2, _ := newAEAD(key(2))
	partial := &Box{dir: dir, state: StateReady, aead: two, keyID: id2}
	partial.put("a", []byte("A"))
	// key 1 now fails on "a" but the check file still opens
	resumed, _ := OpenRekey(dir, key(1), key(2))
	if !resumed.Ready() {
		t.Fatal(resumed.Status())
	}
	for n, want := range map[string]string{"a": "A", "b": "B"} {
		if v, err := resumed.Get(n); err != nil || string(v) != want {
			t.Fatalf("%s: %q %v", n, v, err)
		}
	}
}

func TestResetAndEntries(t *testing.T) {
	dir := t.TempDir()
	b, _ := Open(dir, key(1))
	b.Put("ai-claude", []byte("x"))
	b.Put("dns-cf.token", []byte("y"))
	es, _ := b.Entries()
	if len(es) != 2 || es[0].Kind != "ai" || es[1].Kind != "dns" || es[0].Modified.IsZero() {
		t.Fatalf("entries: %+v", es)
	}
	if err := b.Reset(); !errors.Is(err, ErrReady) {
		t.Fatalf("reset of a working box: %v", err)
	}
	if v, err := b.Get("ai-claude"); err != nil || string(v) != "x" {
		t.Fatalf("refused reset changed data: %q %v", v, err)
	}
	lost, _ := Open(dir, key(9))
	if lost.Ready() {
		t.Fatal("wrong key ready")
	}
	if err := lost.Reset(); err != nil {
		t.Fatal(err)
	}
	if !lost.Ready() {
		t.Fatal(lost.Status())
	}
	if names, _ := lost.List(); len(names) != 0 {
		t.Fatalf("reset left %v", names)
	}
	if again, _ := Open(dir, key(9)); !again.Ready() {
		t.Fatal("reset key does not reopen")
	}
	if err := (&Box{state: StateNoKey}).Reset(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("reset without key: %v", err)
	}
}

func TestSealBlob(t *testing.T) {
	key := make([]byte, KeySize)
	key[0] = 7
	b, err := Open(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := b.SealBlob("web-backup", []byte("웹 데이터"))
	if err != nil || bytes.Contains(raw, []byte("웹 데이터")) {
		t.Fatalf("seal: %v", err)
	}
	if v, err := b.OpenBlob("web-backup", raw); err != nil || string(v) != "웹 데이터" {
		t.Fatalf("open: %q %v", v, err)
	}
	if _, err := b.OpenBlob("other", raw); err == nil {
		t.Fatal("opened for another purpose")
	}
	other := make([]byte, KeySize)
	b2, _ := Open(t.TempDir(), other)
	if _, err := b2.OpenBlob("web-backup", raw); err == nil {
		t.Fatal("opened with another key")
	}
}
