// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"github.com/jay94ks/mydcd/internal/access"
)

// NativeRemoved binds positive journal/SDK completion to one explicit shared
// deletion. Absence without that original journal is not a completion proof.
type NativeRemoved struct {
	Schema                     uint8
	Scope                      Scope
	Owner                      Owner
	Key                        string
	Generation, DeleteRevision uint64
	Signature                  []byte
	DataRetained               bool `json:",omitempty"`
}

func NativeRemovedBytes(p NativeRemoved) []byte {
	p.Signature = nil
	return signedBytes("mydc-volume-native-removed-1", p)
}

func (p NativeRemoved) Verify() error {
	if p.Schema != 1 || !validScope(p.Scope) || !validOwner(p.Owner) || p.Key == "" || p.Generation == 0 || p.DeleteRevision == 0 || !verify(p.Owner.Key, NativeRemovedBytes(p), p.Signature) {
		return ErrVolume
	}
	if p.Scope.TenantManaged() != p.DataRetained || p.DataRetained && (p.Key != FixedNativeKey(p.Scope) || p.Generation != p.Scope.Generation) {
		return ErrVolume
	}
	return nil
}

type Deletion struct {
	Revision uint64
	Gone     *NativeRemoved `json:",omitempty"`
}

func (s State) DeleteRevision() uint64 {
	if s.d.Deletion == nil {
		return 0
	}
	return s.d.Deletion.Revision
}
func (s State) Deleting() bool { return s.d.Deletion != nil && s.d.Deletion.Gone == nil }
func (s State) Deleted() bool  { return s.d.Deletion != nil && s.d.Deletion.Gone != nil }

func (s State) Removal() (NativeRemoved, bool) {
	if !s.Deleted() {
		return NativeRemoved{}, false
	}
	p := *s.d.Deletion.Gone
	p.Signature = append([]byte(nil), p.Signature...)
	return p, true
}

func (s State) validDeletion() bool {
	d := s.d.Deletion
	if d == nil {
		return true
	}
	if d.Revision == 0 || d.Revision > s.d.Revision || len(s.d.Consumers) != 0 || s.d.Active != "" || len(s.d.Retained) != 0 {
		return false
	}
	if d.Gone == nil {
		return s.d.Revision == d.Revision
	}
	return d.Gone.Verify() == nil && d.Gone.Scope == s.d.Scope && d.Gone.Owner == s.d.Owner && d.Gone.DeleteRevision == d.Revision && d.Revision < s.d.Revision
}

func (s State) BeginDelete(c access.Catalog, actor string, expected uint64) (State, error) {
	if c.AuthorizeCleanup(actor, s.d.Scope.Tenant, access.ManageVolumes) != nil {
		return s, access.ErrDenied
	}
	if s.d.Fixed {
		return s, ErrUnregisterRequired
	}
	return s.beginDeletion(expected)
}

// Unregister reuses the same original closure/deletion journal but requires a
// signed DataRetained fact. It never authorizes unlinking the source directory.
func (s State) BeginUnregister(c access.Catalog, actor string, expected uint64) (State, error) {
	if c.AuthorizeCleanup(actor, s.d.Scope.Tenant, access.ManageVolumes) != nil {
		return s, access.ErrDenied
	}
	if !s.d.Fixed {
		return s, ErrVolume
	}
	return s.beginDeletion(expected)
}

func (s State) beginDeletion(expected uint64) (State, error) {
	if expected != s.d.Revision || s.d.Deletion != nil || len(s.d.Consumers) != 0 || s.d.Active != "" || len(s.d.Retained) != 0 {
		return s, ErrVolume
	}
	n, err := s.clone()
	if err != nil {
		return s, err
	}
	n.d.Deletion = &Deletion{Revision: n.d.Revision}
	return n, nil
}

func (s State) CompleteDelete(proof NativeRemoved) (State, error) {
	if !s.Deleting() || proof.Verify() != nil || proof.Scope != s.d.Scope || proof.Owner != s.d.Owner || proof.DeleteRevision != s.DeleteRevision() {
		return s, ErrVolume
	}
	n, err := s.clone()
	if err != nil {
		return s, err
	}
	proof.Signature = append([]byte(nil), proof.Signature...)
	n.d.Deletion.Gone = &proof
	return n, nil
}
