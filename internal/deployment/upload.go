// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/access"
)

const ArtifactPartBytes = 24 << 10
const ArtifactMaxBytes = 4 << 20

// Upload is a bounded immutable-content candidate. It is published by the same
// FSM as app inventory; it is not a second store, commit receipt or native job.
type Upload struct {
	Schema                            uint8
	Tenant, App, Deployment, User, ID string
	Length                            int
	Digest                            [32]byte
	Revision                          uint64
	Parts                             [][]byte
}

func NewUpload(tenant, app, deployment, user, id string, length int, digest [32]byte) (Upload, error) {
	u := Upload{Schema: 1, Tenant: tenant, App: app, Deployment: deployment, User: user, ID: id, Length: length, Digest: digest, Revision: 1}
	if length > 0 && length <= ArtifactMaxBytes {
		u.Parts = make([][]byte, (length+ArtifactPartBytes-1)/ArtifactPartBytes)
	}
	return u, u.Validate()
}

func (u Upload) Validate() error {
	if u.Schema != 1 || !identifier(u.Tenant) || !identifier(u.App) || !identifier(u.Deployment) || !identifier(u.User) || !identifier(u.ID) || u.Length < 1 || u.Length > ArtifactMaxBytes || u.Digest == ([32]byte{}) || u.Revision == 0 || len(u.Parts) != (u.Length+ArtifactPartBytes-1)/ArtifactPartBytes {
		return ErrInputs
	}
	for i, part := range u.Parts {
		if len(part) != 0 && len(part) != min(ArtifactPartBytes, u.Length-i*ArtifactPartBytes) {
			return ErrInputs
		}
	}
	return nil
}

func (u Upload) Add(index int, part []byte) (Upload, error) {
	if u.Validate() != nil || index < 0 || index >= len(u.Parts) || len(part) != min(ArtifactPartBytes, u.Length-index*ArtifactPartBytes) {
		return u, ErrInputs
	}
	if len(u.Parts[index]) != 0 {
		if bytes.Equal(u.Parts[index], part) {
			return u, nil
		}
		return u, ErrInputs
	}
	if u.Revision == ^uint64(0) {
		return u, ErrInputs
	}
	n := u
	n.Parts = make([][]byte, len(u.Parts))
	for i, p := range u.Parts {
		n.Parts[i] = bytes.Clone(p)
	}
	n.Parts[index] = bytes.Clone(part)
	n.Revision++
	if len(n.Missing()) == 0 {
		if _, err := n.Complete(); err != nil {
			return u, err
		}
	}
	return n, nil
}

func (u Upload) Missing() []int {
	var missing []int
	for i, p := range u.Parts {
		if len(p) == 0 {
			missing = append(missing, i)
		}
	}
	return missing
}

func (u Upload) Complete() ([]byte, error) {
	if u.Validate() != nil || len(u.Missing()) != 0 {
		return nil, ErrInputs
	}
	raw := make([]byte, 0, u.Length)
	for _, p := range u.Parts {
		raw = append(raw, p...)
	}
	if len(raw) != u.Length || sha256.Sum256(raw) != u.Digest {
		return nil, ErrInputs
	}
	return raw, nil
}

func (u Upload) Encode() ([]byte, error) {
	if err := u.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(u)
}

func DecodeUpload(raw []byte) (Upload, error) {
	var u Upload
	if len(raw) > 6<<20 || json.Unmarshal(raw, &u) != nil || u.Validate() != nil {
		return Upload{}, ErrInputs
	}
	canonical, _ := u.Encode()
	if !bytes.Equal(raw, canonical) {
		return Upload{}, ErrInputs
	}
	if len(u.Missing()) == 0 {
		if _, err := u.Complete(); err != nil {
			return Upload{}, err
		}
	}
	return u, nil
}

type AppScope struct {
	Cluster                        [32]byte
	Actor, Tenant, App, Deployment string
}

func (b Blueprint) Scope() AppScope {
	return AppScope{b.d.Cluster, b.d.Actor, b.d.Tenant, b.d.App, b.d.Deployment}
}

func (e Execution) Scope() AppScope { return (Blueprint{e.d.Plan}).Scope() }

func (e Execution) ActiveOperation() string { return e.d.Operation }

func (e Execution) Steps() []Step { return (Blueprint{e.d.Plan}).Steps() }

// Authorize keeps the same current role/image checks as Prepare and Send.
func (e Execution) Authorize(c access.Catalog, key string) error {
	i := e.index(key)
	if i < 0 {
		return ErrInputs
	}
	return e.authorize(c, i)
}

func (a Inventory) Scope() AppScope {
	return AppScope{Cluster: a.d.Cluster, Tenant: a.d.Tenant, App: a.d.App, Deployment: a.d.Deployment}
}

func (a Inventory) Active() (OperationSummary, bool) {
	e, ok := a.Execution()
	if !ok {
		return OperationSummary{}, false
	}
	return summarize(e, e.Status()), true
}

func (a Inventory) Quiescent() bool {
	if a.d.Retirement != nil || a.pendingSubmission() {
		return false
	}
	e, ok := a.Execution()
	return !ok || e.Status() == "Succeeded" || e.Status() == "Closed"
}
