// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"reflect"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/imagesource"
)

// CheckRegistrySources reuses the same selection core for a frozen preparation.
// Revocation/new reference cannot borrow an older approval under the same ID.
func (b Blueprint) CheckRegistrySources(definitions []imagesource.Definition) error {
	current := Blueprint{d: blueprintRecord{Tenant: b.d.Tenant}}
	if err := current.freezeRegistrySources(b.d.Input, definitions); err != nil {
		return err
	}
	if !reflect.DeepEqual(current.d.RegistrySources, b.d.RegistrySources) {
		return ErrInputs
	}
	return nil
}

func (b *Blueprint) freezeRegistrySources(input Compose, definitions []imagesource.Definition) error {
	if len(definitions) == 0 {
		return nil
	}
	for _, name := range mapKeys(input.Services) {
		image, err := access.PinImage(input.Services[name].Image)
		if err != nil {
			return inputError("IMAGE_NOT_PINNED", name)
		}
		spec, err := imagesource.Select(definitions, b.d.Tenant, image)
		if err != nil {
			return inputError("REGISTRY_SOURCE_UNAVAILABLE", name)
		}
		if spec == nil {
			continue
		}
		var sources []Source
		for _, ref := range spec.References() {
			sources = append(sources, Source{ref.Realm, ref.ID})
		}
		if len(sources) > 0 {
			if b.d.RegistrySources == nil {
				b.d.RegistrySources = map[string][]Source{}
			}
			b.d.RegistrySources[name] = sources
		}
	}
	return nil
}

func validRegistrySources(d blueprintRecord) bool {
	for name, sources := range d.RegistrySources {
		if _, ok := d.Input.Services[name]; !ok || len(sources) == 0 || len(sources) > 2 {
			return false
		}
		for i, source := range sources {
			if !identifier(source.Object) || source.Realm != "" && source.Realm != d.Tenant || slices.Contains(sources[:i], source) {
				return false
			}
		}
	}
	return true
}
