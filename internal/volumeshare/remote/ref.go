// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// MountRef names what a VolumeFS mount asks the home for: one remote
// consumer of one Volume generation. It travels as the mount's Volume field.
type MountRef struct {
	Scope    volumes.Scope
	Consumer string
}

const maxRef = 2048

func (r MountRef) String() string {
	raw, _ := json.Marshal(r)
	return string(raw)
}

// ParseMountRef accepts only the canonical encoding.
func ParseMountRef(s string) (MountRef, error) {
	var r MountRef
	if len(s) == 0 || len(s) > maxRef {
		return r, errors.New("remote volume: bad mount ref")
	}
	d := json.NewDecoder(bytes.NewReader([]byte(s)))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || r.String() != s || r.Consumer == "" || r.Scope.Tenant == "" || r.Scope.ID == "" || r.Scope.Generation == 0 {
		return MountRef{}, errors.New("remote volume: bad mount ref")
	}
	return r, nil
}
