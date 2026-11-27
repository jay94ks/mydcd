// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/jay94ks/seafield/internal/schema"
	"slices"
)

// ManagedNativeID is shared by original native admission and its owner. Dynamic
// backend observations do not mint a second listener identity.
func ManagedNativeID(key string, generation uint64, spec Spec) string {
	spec.Lifecycle = schema.Lifecycle{}
	if spec.DynamicBackends {
		spec.BindingRevision = 0
		spec.Services = slices.Clone(spec.Services)
		for at := range spec.Services {
			spec.Services[at].Backends = nil
		}
	}
	raw, _ := json.Marshal(spec)
	h := sha256.Sum256(append([]byte(fmt.Sprintf("sfc-app-ingress-1\x00%s\x00%d\x00", key, generation)), raw...))
	return fmt.Sprintf("ingress/%x", h)
}
