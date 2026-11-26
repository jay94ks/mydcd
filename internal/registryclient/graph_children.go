// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"bytes"
	"slices"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// GraphContentDescriptor is an immediate edge, with its complete root-bound
// read query. It contains no credential or independently transferable grant.
type GraphContentDescriptor struct {
	Query GraphContentQuery
	Info  ContentInfo
}

// GraphContentChildren shares the owner's strict metadata validation with
// read-only SDK content stores. The caller must have verified the original
// root-to-selected path when obtaining raw; this verifies raw itself and its
// immediate edges without fetching siblings or a whole multi-platform graph.
func GraphContentChildren(q GraphContentQuery, media string, raw []byte) ([]GraphContentDescriptor, error) {
	if !q.Valid() || q.Kind != "manifest" {
		return nil, &Error{Code: "INVALID_IMAGE"}
	}
	selected := q.Selected()
	local := GraphContentQuery{Root: selected.Ref, Kind: "manifest"}
	if _, _, err := SelectGraphContent(local, func(string) (string, []byte, error) { return media, raw, nil }); err != nil {
		return nil, err
	}
	var out []GraphContentDescriptor
	add := func(d v1.Descriptor, kind string) error {
		child := q
		child.Path = slices.Clone(q.Path)
		child.Kind, child.Digest = kind, ""
		if kind == "manifest" {
			child.Path = append(child.Path, d.Digest.String())
		} else {
			child.Digest = d.Digest.String()
		}
		info := ContentInfo{Schema: 1, Ref: child.Selected().Ref, Kind: kind, Digest: d.Digest.String(), MediaType: string(d.MediaType), Bytes: d.Size}
		if !child.Valid() || !info.Valid(child.Selected()) {
			return &Error{Code: "INVALID_IMAGE"}
		}
		out = append(out, GraphContentDescriptor{Query: child, Info: info})
		return nil
	}
	if types.MediaType(media).IsIndex() {
		index, err := v1.ParseIndexManifest(bytes.NewReader(raw))
		if err != nil {
			return nil, &Error{Code: "INVALID_IMAGE"}
		}
		for _, child := range index.Manifests {
			if err := add(child, "manifest"); err != nil {
				return nil, err
			}
		}
	} else {
		manifest, err := v1.ParseManifest(bytes.NewReader(raw))
		if err != nil {
			return nil, &Error{Code: "INVALID_IMAGE"}
		}
		if err := add(manifest.Config, "config"); err != nil {
			return nil, err
		}
		for _, layer := range manifest.Layers {
			if err := add(layer, "layer"); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}
