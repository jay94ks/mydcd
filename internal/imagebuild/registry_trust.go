// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/pelletier/go-toml/v2"
)

const MaxBuildTrustBytes = 4 << 20

type buildTrustFile struct {
	name string
	data []byte
}

func normalizeBuildTrust(inputs []FrozenSource, roots []registryclient.RegistryTrust) ([]registryclient.RegistryTrust, error) {
	allowed := map[string]bool{}
	for _, input := range inputs {
		_, host, _, err := registryclient.Normalize(input.Image)
		if err != nil {
			return nil, ErrInvalid
		}
		allowed[host] = true
	}
	byHost := map[string]registryclient.RegistryTrust{}
	for _, root := range roots {
		if !root.Valid() || !allowed[root.Authority] {
			return nil, ErrSourceFetch
		}
		certificates := slices.Clone(root.Certificates)
		slices.SortFunc(certificates, bytes.Compare)
		certificates = slices.CompactFunc(certificates, bytes.Equal)
		if len(certificates) == 0 {
			certificates = nil
		}
		root = registryclient.RegistryTrust{Authority: root.Authority, Certificates: certificates}
		if old, exists := byHost[root.Authority]; exists && !slices.EqualFunc(old.Certificates, root.Certificates, bytes.Equal) {
			// Host-scoped BuildKit TLS cannot silently union repository CA sets.
			return nil, ErrConflict
		}
		byHost[root.Authority] = root
	}
	var out []registryclient.RegistryTrust
	total := 0
	for host := range allowed {
		root, exists := byHost[host]
		if !exists {
			return nil, ErrSourceFetch
		}
		data, err := root.PEM()
		if err != nil || len(data) > MaxBuildTrustBytes-total {
			return nil, ErrSourceFetch
		}
		total += len(data)
		out = append(out, root)
	}
	slices.SortFunc(out, func(a, b registryclient.RegistryTrust) int { return strings.Compare(a.Authority, b.Authority) })
	return out, nil
}

func buildTrustControls(inputs []FrozenSource, roots []registryclient.RegistryTrust) ([]buildTrustFile, [32]byte, error) {
	normalized, err := normalizeBuildTrust(inputs, roots)
	if err != nil {
		return nil, [32]byte{}, err
	}
	type registryConfig struct {
		CA []string `toml:"ca"`
	}
	config := struct {
		Registry map[string]registryConfig `toml:"registry"`
	}{Registry: map[string]registryConfig{}}
	var files []buildTrustFile
	for i, root := range normalized {
		data, err := root.PEM()
		if err != nil {
			return nil, [32]byte{}, ErrSourceFetch
		}
		if len(data) == 0 {
			continue
		}
		name := fmt.Sprintf("tls/registry-%d.pem", i)
		files = append(files, buildTrustFile{name, data})
		config.Registry[root.Authority] = registryConfig{CA: []string{"/input/" + name}}
	}
	raw, err := toml.Marshal(config)
	if err != nil {
		return nil, [32]byte{}, ErrInvalid
	}
	files = append(files, buildTrustFile{"buildkitd.toml", raw})
	return files, digestJSON("sfc-imagebuild-registry-trust-1", normalized), nil
}
