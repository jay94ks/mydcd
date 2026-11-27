// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"
)

// The built-in registry's images in the fake (fixture Images). REQ-18
// catalogue, maintenance and prune read them: fake_registry_maintenance.go.

type imageState struct {
	images     map[string][]RegistryImage   // tenant → images (Registry "builtin")
	unref      map[string]uint64            // tenant → unreferenced blob bytes
	candidates map[string]map[string]string // tenant → app → CD candidate image ref
}

func (w *world) seedImages(f Fixture) {
	w.img = imageState{images: map[string][]RegistryImage{}, unref: map[string]uint64{}, candidates: map[string]map[string]string{}}
	for t, m := range f.ImageCandidates {
		w.img.candidates[t] = map[string]string{}
		for k, v := range m {
			w.img.candidates[t][k] = v
		}
	}
	for t, imgs := range f.Images {
		for _, im := range imgs {
			im.Registry = ImageRegistryBuiltin
			im.Tags = slices.Clone(im.Tags)
			if im.Digest == "" {
				sum := sha256.Sum256([]byte(im.Repository + "@" + strings.Join(im.Tags, ",")))
				im.Digest = "sha256:" + hexOf(sum[:])
			}
			w.img.images[t] = append(w.img.images[t], im)
		}
		w.img.unref[t] = 180 << 20
	}
}

func hexOf(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, 2*len(b))
	for i, c := range b {
		out[2*i], out[2*i+1] = h[c>>4], h[c&15]
	}
	return string(out)
}

func (w *world) builtinEndpoint(tenant string) string {
	for _, r := range w.registries {
		if r.Tenant == tenant && r.ID == "builtin" {
			return r.Endpoint
		}
	}
	return ""
}

func itoa(v uint64) string {
	b, _ := json.Marshal(v)
	return string(b)
}
