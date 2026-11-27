// SPDX-License-Identifier: Apache-2.0

package wallet

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/cliprofile"
)

// RecordNames lists private record identifiers only. Account names/grants are
// decoded by the authentication owner, not exposed by wallet's public key list.
func (d *Disk) RecordNames() ([]string, error) {
	if !d.loaded || d.check() != nil {
		return nil, ErrWallet
	}
	names := []string{}
	for _, e := range d.entries {
		if !e.IsKey() {
			names = append(names, e.Name)
		}
	}
	return names, nil
}

func (d *Disk) Record(name string) ([]byte, error) {
	if !d.loaded || d.check() != nil || !cliprofile.ValidKeyName(name) {
		return nil, ErrWallet
	}
	for _, e := range d.entries {
		if e.Name == name {
			if e.IsKey() {
				return nil, ErrWallet
			}
			return bytes.Clone(e.Record), nil
		}
	}
	return nil, ErrMissing
}

// PutRecord prepares one explicit CAS in the encrypted wallet transaction. A
// nil expected digest means create-only. It never replaces a private-key entry.
// Save/actual readback remain necessary before callers publish a login/reference.
func (d *Disk) PutRecord(name string, data []byte, expected *[32]byte) error {
	if !d.loaded || d.check() != nil || !cliprofile.ValidKeyName(name) || len(data) < 1 || len(data) > MaxRecordBytes {
		return ErrWallet
	}
	for i := range d.entries {
		e := &d.entries[i]
		if e.Name != name {
			continue
		}
		if e.IsKey() || expected == nil {
			return ErrExists
		}
		if sha256.Sum256(e.Record) != *expected {
			return ErrWallet
		}
		next := bytes.Clone(data)
		clear(e.Record)
		e.Record = next
		return nil
	}
	if expected != nil {
		return ErrMissing
	}
	if len(d.entries) >= MaxEntries {
		return ErrWallet
	}
	d.entries = append(d.entries, Entry{Name: name, Record: bytes.Clone(data)})
	slices.SortFunc(d.entries, func(a, b Entry) int { return strings.Compare(a.Name, b.Name) })
	return nil
}

func (d *Disk) ReadBackRecord(name string, password []byte) ([]byte, error) {
	if err := d.Unlock(password); err != nil {
		return nil, err
	}
	return d.Record(name)
}
