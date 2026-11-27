// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/jay94ks/seafield/internal/network"
)

type authoritySnapshot struct {
	Schema     uint8
	Cluster    [32]byte
	Revision   uint64
	At         int64
	Book       network.Journal
	Services   []json.RawMessage
	Clients    []json.RawMessage
	Leases     []json.RawMessage
	References *referenceSnapshot
	Archives   []RetiredNetwork `json:",omitempty"`
}

// Only the deterministic validation of exact canonical snapshot bytes is
// retained. Every decode still constructs its own Book, maps and proof bytes;
// no decoded Authority, permission, clock or native observation is cached.
// A single bounded entry also works across unrelated app checkpoint changes.
const authorityValidationBytes = 1 << 20

type authorityValidated struct{ raw []byte }

var validatedAuthority atomic.Pointer[authorityValidated]

func (a Authority) validate() error {
	if a.cluster == ([32]byte{}) || a.at < 0 || a.at > 1<<62 {
		return ErrLease
	}
	book, err := network.Restore(a.book.Checkpoint())
	if err != nil {
		return ErrLease
	}
	for _, v := range book.Checkpoint().Allocations {
		if strings.HasPrefix(v.Endpoint, "dhcp/") {
			return ErrLease
		}
	}
	for _, v := range book.Checkpoint().Floors {
		if strings.HasPrefix(v.Endpoint, "dhcp/") {
			return ErrLease
		}
	}
	return nil
}
func (a Authority) Encode() ([]byte, error) {
	if e := a.validateArchives(); e != nil {
		return nil, e
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	s := authoritySnapshot{Schema: 1, Cluster: a.cluster, Revision: a.revision, At: a.at, Book: a.book.Checkpoint()}
	for _, v := range a.archives {
		s.Archives = append(s.Archives, ownRetiredNetwork(v))
	}
	slices.SortFunc(s.Archives, func(a, b RetiredNetwork) int {
		return strings.Compare(retiredNetworkKey(a.Network), retiredNetworkKey(b.Network))
	})
	var err error
	s.References, err = a.referencesSnapshot()
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > 32<<20 {
		return nil, ErrLease
	}
	return raw, nil
}
func DecodeAuthority(raw []byte) (Authority, error) {
	var s authoritySnapshot
	if len(raw) > 32<<20 || json.Unmarshal(raw, &s) != nil || s.Schema != 1 || len(s.Services) != 0 || len(s.Clients) != 0 || len(s.Leases) != 0 || len(s.Archives) > maxRecords {
		return Authority{}, ErrLease
	}
	book, err := network.Restore(s.Book)
	if err != nil {
		return Authority{}, ErrLease
	}
	a := Authority{cluster: s.Cluster, revision: s.Revision, at: s.At, book: book}
	a.archives = map[string]RetiredNetwork{}
	for _, v := range s.Archives {
		k := retiredNetworkKey(v.Network)
		if _, dup := a.archives[k]; dup {
			return Authority{}, ErrLease
		}
		a.archives[k] = ownRetiredNetwork(v)
	}
	a.references, err = decodeReferences(s.References)
	if err != nil {
		return Authority{}, err
	}
	checked := validatedAuthority.Load()
	if checked == nil || !bytes.Equal(checked.raw, raw) {
		canonical, err := a.Encode()
		if err != nil || !bytes.Equal(raw, canonical) {
			return Authority{}, ErrLease
		}
		if len(raw) <= authorityValidationBytes {
			validatedAuthority.Store(&authorityValidated{raw: bytes.Clone(raw)})
		}
	}
	return a, nil
}
