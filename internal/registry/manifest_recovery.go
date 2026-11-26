// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"bytes"
	"encoding/json"
	"strings"

	oci "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/jay94ks/mydcd/internal/schema"
)

// All aliases, original bodies and repository names belong to the same sync
// transaction. Recovery rejects an incomplete graph instead of repairing it.
func (m *Metadata) validateStored() error {
	rows, err := m.db.ScanBounded(manifestPrefix, m.limits.Records, m.limits.TotalBytes)
	if err != nil {
		return ErrStorage
	}
	repos := map[string]string{}
	hasReference := map[string]bool{}
	for key, raw := range rows {
		if strings.HasPrefix(key, manifestPrefix+"repo/") {
			id, e := repoID(string(raw))
			if e != nil || key != manifestPrefix+"repo/"+id {
				return ErrStorage
			}
			repos[id] = string(raw)
		}
	}
	for key, raw := range rows {
		parts := strings.Split(strings.TrimPrefix(key, manifestPrefix), "/")
		if len(parts) == 2 && parts[0] == "repo" {
			continue
		}
		if len(parts) != 3 || repos[parts[1]] == "" {
			return ErrStorage
		}
		id, ref := parts[1], parts[2]
		switch parts[0] {
		case "data":
			data, e := schema.Decode[oci.ManifestData](raw)
			if e != nil || len(data.Body) == 0 || len(data.Body) > m.limits.ManifestBytes || !json.Valid(data.Body) {
				return ErrStorage
			}
			media := types.MediaType(data.ContentType)
			if !media.IsImage() && !media.IsIndex() {
				return ErrStorage
			}
			h, _, e := v1.SHA256(bytes.NewReader(data.Body))
			if e != nil || h.String() != ref || string(rows[manifestPrefix+"ref/"+id+"/"+ref]) != ref {
				return ErrStorage
			}
		case "published":
			stamp, e := schema.Decode[manifestPublication](raw)
			if e != nil || stamp.Schema != 1 || stamp.At == 0 || !manifestReference(repos[id], ref) || string(rows[manifestPrefix+"ref/"+id+"/"+ref]) != stamp.Digest {
				return ErrStorage
			}
		case "ref":
			digest := string(raw)
			if !manifestReference(repos[id], ref) || !strings.HasPrefix(digest, "sha256:") || !manifestReference(repos[id], digest) || strings.Contains(ref, ":") && ref != digest || rows[manifestPrefix+"data/"+id+"/"+digest] == nil {
				return ErrStorage
			}
			hasReference[id] = true
		default:
			return ErrStorage
		}
	}
	for id := range repos {
		if !hasReference[id] {
			return ErrStorage
		}
	}
	return nil
}
