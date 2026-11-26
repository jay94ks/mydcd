// SPDX-License-Identifier: Apache-2.0

package wallet

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/localstore"
)

// These actual crypto/filesystem boundary cases run in U0's final validation,
// together with profiles, transport and CLI consumers, not after each edit.
func TestU0WalletAEADAuthenticatesHeaderAndCanonicalPayload(t *testing.T) {
	password := []byte("wallet-boundary-passphrase")
	entry := Entry{Name: "operator-private", Seed: [32]byte{1, 2, 3}}
	defer clear(entry.Seed[:])
	first, e := Seal(password, []Entry{entry})
	if e != nil {
		t.Fatal(e)
	}
	defer clear(first)
	second, e := Seal(password, []Entry{entry})
	if e != nil {
		t.Fatal(e)
	}
	defer clear(second)
	if bytes.Equal(first, second) || bytes.Equal(first[18:34], second[18:34]) || bytes.Equal(first[34:46], second[34:46]) {
		t.Fatal("save reused salt or nonce")
	}
	if bytes.Contains(first, []byte(entry.Name)) || bytes.Contains(first, entry.Seed[:]) || bytes.Contains(first, password) {
		t.Fatal("private wallet contains plaintext material")
	}
	entries, e := Unseal(password, first)
	if e != nil || len(entries) != 1 || entries[0].Name != entry.Name || entries[0].Seed != entry.Seed {
		Clear(entries)
		t.Fatal("actual encrypted roundtrip", e)
	}
	Clear(entries)
	if entries, e := Unseal([]byte("wrong"), first); e == nil || entries != nil {
		Clear(entries)
		t.Fatal("wrong password returned key material")
	}
	for _, offset := range []int{18, 34, len(first) - 1} {
		bad := bytes.Clone(first)
		bad[offset] ^= 1
		entries, e := Unseal(password, bad)
		clear(bad)
		if e == nil || entries != nil {
			Clear(entries)
			t.Fatal("unauthenticated wallet material", offset)
		}
	}
}
func TestU0WalletDiskPrivateOwnershipLockAndReadback(t *testing.T) {
	home := t.TempDir()
	password := []byte("native-file-password")
	nextPassword := []byte("changed-native-password")
	d, e := OpenDisk(home, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if e = d.Init(password); e != nil {
		t.Fatal(e)
	}
	if other, e := OpenDisk(home, false); e == nil {
		_ = other.Close()
		t.Fatal("second writer acquired lock")
	} else if !errors.Is(e, localstore.ErrBusy) {
		t.Fatal(e)
	}
	entry := Entry{Name: "operator", Seed: [32]byte{9}}
	defer clear(entry.Seed[:])
	if changed, e := d.Put(entry); e != nil || !changed {
		t.Fatal(changed, e)
	}
	if e = d.Save(password); e != nil {
		t.Fatal(e)
	}
	saved, e := os.ReadFile(filepath.Join(home, ".mydc", "wallet.bin"))
	if e != nil {
		t.Fatal(e)
	}
	defer clear(saved)
	if bytes.Contains(saved, entry.Seed[:]) {
		t.Fatal("private seed persisted unencrypted")
	}
	for _, name := range []string{"wallet.bin", "wallet.lock"} {
		info, e := os.Stat(filepath.Join(home, ".mydc", name))
		if e != nil || info.Mode().Perm() != 0600 {
			t.Fatal("private file mode", name, e)
		}
	}
	info, e := os.Stat(filepath.Join(home, ".mydc"))
	if e != nil || info.Mode().Perm() != 0700 {
		t.Fatal("private directory mode", e)
	}
	if e = d.Close(); e != nil {
		t.Fatal(e)
	}
	d, e = OpenDisk(home, false)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if e = d.Unlock(password); e != nil {
		t.Fatal(e)
	}
	read, e := d.Get("operator")
	if e != nil || read.Seed != entry.Seed {
		clear(read.Seed[:])
		t.Fatal("original key readback", e)
	}
	clear(read.Seed[:])
	if _, e = d.Put(Entry{Name: "operator", Seed: [32]byte{99}}); !errors.Is(e, ErrExists) {
		t.Fatal("named key replacement", e)
	}
	if e = d.Init(password); !errors.Is(e, ErrExists) {
		t.Fatal("wallet reinit", e)
	}
	if e = d.Save(nextPassword); e != nil {
		t.Fatal(e)
	}
	if e = d.Close(); e != nil {
		t.Fatal(e)
	}
	d, e = OpenDisk(home, false)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if e = d.Unlock(password); e == nil {
		t.Fatal("old password still accepted")
	}
	if e = d.Unlock(nextPassword); e != nil {
		t.Fatal(e)
	}
	read, e = d.Get("operator")
	if e != nil || read.Public() != entry.Public() {
		clear(read.Seed[:])
		t.Fatal("password change replaced signer", e)
	}
	clear(read.Seed[:])
}

type cutWalletFiles struct {
	diskFiles
	at    string
	fired bool
}

func (f *cutWalletFiles) WriteNew(name string, b []byte) error {
	if !f.fired && f.at == "intent" && name == intentFile {
		f.fired = true
		return localstore.ErrState
	}
	return f.diskFiles.WriteNew(name, b)
}
func (f *cutWalletFiles) Rename(a, b string) error {
	if !f.fired && f.at == "rename" {
		f.fired = true
		return localstore.ErrState
	}
	return f.diskFiles.Rename(a, b)
}
func (f *cutWalletFiles) Sync() error {
	if !f.fired && f.at == "published-sync" {
		f.fired = true
		return localstore.ErrState
	}
	return f.diskFiles.Sync()
}
func (f *cutWalletFiles) Remove(name string) error {
	if !f.fired && f.at == "intent-remove" && name == intentFile {
		f.fired = true
		return localstore.ErrState
	}
	return f.diskFiles.Remove(name)
}
func TestU0WalletCommitCutsRecoverOriginalCiphertext(t *testing.T) {
	for _, cut := range []string{"intent", "rename", "published-sync", "intent-remove"} {
		t.Run(cut, func(t *testing.T) {
			home := t.TempDir()
			pass := []byte("staged-file-password")
			d, e := OpenDisk(home, true)
			if e != nil {
				t.Fatal(e)
			}
			defer d.Close()
			if e = d.Init(pass); e != nil {
				t.Fatal(e)
			}
			original, e := os.ReadFile(filepath.Join(home, ".mydc", walletFile))
			if e != nil {
				t.Fatal(e)
			}
			defer clear(original)
			entry := Entry{Name: "kept-key", Seed: [32]byte{18}}
			defer clear(entry.Seed[:])
			if _, e = d.Put(entry); e != nil {
				t.Fatal(e)
			}
			real := d.files
			fault := &cutWalletFiles{diskFiles: real, at: cut}
			d.files = fault
			if e = d.Save(pass); !errors.Is(e, ErrPending) || !fault.fired {
				t.Fatal("cut not retained as pending", e)
			}
			d.files = real
			status, e := d.Status()
			if e != nil {
				t.Fatal(e)
			}
			candidate, _ := os.ReadFile(filepath.Join(home, ".mydc", nextFile))
			defer clear(candidate)
			published, _ := os.ReadFile(filepath.Join(home, ".mydc", walletFile))
			defer clear(published)
			goal := sha256.Sum256(candidate)
			if status.Published {
				goal = sha256.Sum256(published)
			}
			if cut == "intent" {
				if !status.UnpublishedCandidate || status.Pending || !bytes.Equal(original, published) {
					t.Fatal("unstaged candidate changed original")
				}
				if e = d.Recover(false); !errors.Is(e, ErrPending) {
					t.Fatal("unaccepted candidate promoted", e)
				}
				if e = d.Recover(true); e != nil {
					t.Fatal(e)
				}
				after, e := os.ReadFile(filepath.Join(home, ".mydc", walletFile))
				defer clear(after)
				if e != nil || !bytes.Equal(after, original) {
					t.Fatal("abort changed original", e)
				}
			} else {
				if !status.Pending {
					t.Fatal("intent lost")
				}
				if status.Published {
					if e = d.Recover(true); !errors.Is(e, ErrPublished) {
						t.Fatal("post-publication rollback allowed", e)
					}
				}
				if e = d.Close(); e != nil {
					t.Fatal(e)
				}
				d, e = OpenDisk(home, false)
				if e != nil {
					t.Fatal(e)
				}
				defer d.Close()
				if e = d.Recover(false); e != nil {
					t.Fatal(e)
				}
				after, e := os.ReadFile(filepath.Join(home, ".mydc", walletFile))
				defer clear(after)
				if e != nil || sha256.Sum256(after) != goal {
					t.Fatal("recovery reencrypted/replaced original goal", e)
				}
				if e = d.Unlock(pass); e != nil {
					t.Fatal(e)
				}
				read, e := d.Get(entry.Name)
				if e != nil || read.Seed != entry.Seed {
					clear(read.Seed[:])
					t.Fatal("recovered key changed", e)
				}
				clear(read.Seed[:])
			}
			status, e = d.Status()
			if e != nil || status.Pending || status.UnpublishedCandidate {
				t.Fatal("commit not closed", status, e)
			}
		})
	}
}
func TestU0WalletRejectsSymlinkHardlinkAndUnsafeModes(t *testing.T) {
	home := t.TempDir()
	d, e := OpenDisk(home, true)
	if e != nil {
		t.Fatal(e)
	}
	pass := []byte("original-private-wallet")
	if e = d.Init(pass); e != nil {
		t.Fatal(e)
	}
	_ = d.Close()
	root := filepath.Join(home, ".mydc")
	file := filepath.Join(root, walletFile)
	raw, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	if e = os.Chmod(file, 0644); e != nil {
		t.Fatal(e)
	}
	d, e = OpenDisk(home, false)
	if e != nil {
		t.Fatal(e)
	}
	if d.Unlock(pass) == nil {
		_ = d.Close()
		t.Fatal("unsafe wallet accepted")
	}
	_ = d.Close()
	if e = os.Chmod(file, 0600); e != nil {
		t.Fatal(e)
	}
	foreign := filepath.Join(home, "foreign.bin")
	if e = os.WriteFile(foreign, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(file); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(foreign, file); e != nil {
		t.Fatal(e)
	}
	d, e = OpenDisk(home, false)
	if e != nil {
		t.Fatal(e)
	}
	if d.Unlock(pass) == nil {
		_ = d.Close()
		t.Fatal("symlink wallet accepted")
	}
	_ = d.Close()
	unchanged, e := os.ReadFile(foreign)
	defer clear(unchanged)
	if e != nil || !bytes.Equal(unchanged, raw) {
		t.Fatal("foreign file touched", e)
	}
	if e = os.Remove(file); e != nil {
		t.Fatal(e)
	}
	if e = os.Link(foreign, file); e != nil {
		t.Fatal(e)
	}
	d, e = OpenDisk(home, false)
	if e != nil {
		t.Fatal(e)
	}
	if d.Unlock(pass) == nil {
		_ = d.Close()
		t.Fatal("hardlink wallet accepted")
	}
	_ = d.Close()
	if e = os.Remove(file); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(file, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(root, 0755); e != nil {
		t.Fatal(e)
	}
	if d, e = OpenDisk(home, false); e == nil {
		_ = d.Close()
		t.Fatal("unsafe directory adopted")
	}
	_ = os.Chmod(root, 0700)
}
