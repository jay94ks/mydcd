// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"encoding/json"
	"os"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/secrets"
)

// SecretWriteIntent contains only public original metadata and signed facts.
// Attempted is synced BEFORE private input can be transmitted. Neither values,
// passwords, verifiers nor private-input digests belong in this record.
type SecretWriteIntent struct {
	Schema              uint8
	Profile             [32]byte
	User, Realm         string
	Request             secrets.WriteRequest
	Epoch, ExpectedTree uint64
	Attempted           bool
	Sequence            uint64
	Pending             *secrets.WriteObservation `json:",omitempty"`
}

func secretWriteRoot(home string, c Client, user string, create bool) (*os.Root, error) {
	r, err := operationRoot(home, c, user, create)
	if err != nil {
		return nil, err
	}
	if !create {
		if _, err = r.Lstat("secret-writes"); os.IsNotExist(err) {
			_ = r.Close()
			return nil, ErrOperationMissing
		}
	}
	next, err := descend(r, "secret-writes", create)
	_ = r.Close()
	return next, err
}
func secretWriteName(realm, id string) string { return operationName(realm + "\x00" + id) }
func validSecretIntent(c Client, session access.Session, i SecretWriteIntent) bool {
	return i.Schema == 1 && i.Profile == c.JournalProfile() && i.User == session.User && i.Epoch > 0 && i.Request.ID != "" && i.Request.Object != "" && i.Request.Epoch > 0 && i.Request.Profile != "" && i.Request.ProviderObject != "" && i.Sequence <= 128 && (i.Pending == nil || i.Attempted && i.Sequence > 0 && i.Pending.Cluster == c.Cluster && i.Pending.Tenant == i.Realm && samePublic(i.Pending.Request, i.Request))
}
func samePublic(a, b any) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}
func readSecretIntent(r *os.Root, c Client, session access.Session, realm, id string) (SecretWriteIntent, error) {
	var i SecretWriteIntent
	name := secretWriteName(realm, id)
	if _, err := r.Lstat(name); os.IsNotExist(err) {
		return i, ErrOperationMissing
	}
	if readPrivate(r, name, &i) != nil || !validSecretIntent(c, session, i) || i.Realm != realm || i.Request.ID != id {
		return i, ErrPrivateState
	}
	return i, nil
}
func LoadSecretWrite(home string, c Client, session access.Session, realm, id string) (SecretWriteIntent, error) {
	if c.Verify(session) != nil {
		return SecretWriteIntent{}, ErrPrivateState
	}
	r, err := secretWriteRoot(home, c, session.User, false)
	if err != nil {
		return SecretWriteIntent{}, err
	}
	defer r.Close()
	return readSecretIntent(r, c, session, realm, id)
}
func StageSecretWrite(home string, c Client, session access.Session, p control.VaultWritePlan, epoch uint64, recoveryOnly bool) (SecretWriteIntent, error) {
	i := SecretWriteIntent{Schema: 1, Profile: c.JournalProfile(), User: session.User, Realm: p.Realm, Request: p.Request, Epoch: epoch, ExpectedTree: p.TreeRevision, Attempted: recoveryOnly}
	if c.Verify(session) != nil || p.Schema != 1 || !validSecretIntent(c, session, i) || recoveryOnly && p.Write == nil {
		return i, ErrPrivateState
	}
	r, err := secretWriteRoot(home, c, session.User, true)
	if err != nil {
		return i, err
	}
	defer r.Close()
	unlock, err := lockProfile(r)
	if err != nil {
		return i, err
	}
	defer unlock()
	old, err := readSecretIntent(r, c, session, p.Realm, p.Request.ID)
	if err == nil {
		if !samePublic(old.Request, i.Request) {
			return old, ErrPrivateState
		}
		return old, nil
	}
	if err != ErrOperationMissing {
		return i, err
	}
	dir, err := r.Open(".")
	if err != nil {
		return i, err
	}
	names, err := dir.Readdirnames(-1)
	_ = dir.Close()
	if err != nil || len(names) >= 256 {
		return i, ErrPrivateState
	}
	return i, writePrivate(r, secretWriteName(i.Realm, i.Request.ID), i)
}

// ReplaceSecretWrite is a private-file CAS. In particular, only one concurrent
// CLI can cross the false->true BEFORE-SEND boundary for the original write.
func ReplaceSecretWrite(home string, c Client, session access.Session, old, next SecretWriteIntent) error {
	if c.Verify(session) != nil || !validSecretIntent(c, session, next) || old.Attempted && !next.Attempted || next.Sequence < old.Sequence {
		return ErrPrivateState
	}
	left, right := old, next
	left.Attempted, left.Sequence, left.Pending = false, 0, nil
	right.Attempted, right.Sequence, right.Pending = false, 0, nil
	if !samePublic(left, right) {
		return ErrPrivateState
	}
	r, err := secretWriteRoot(home, c, session.User, false)
	if err != nil {
		return err
	}
	defer r.Close()
	unlock, err := lockProfile(r)
	if err != nil {
		return err
	}
	defer unlock()
	actual, err := readSecretIntent(r, c, session, old.Realm, old.Request.ID)
	if err != nil || !samePublic(actual, old) {
		return ErrPrivateState
	}
	return writePrivate(r, secretWriteName(next.Realm, next.Request.ID), next)
}
