// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/network/services"
)

func AppDNSNativeDigest(row AppDNSOwner) [32]byte {
	raw, _ := json.Marshal(row)
	return sha256.Sum256(append([]byte("sfc-app-dns-native-1\x00"), raw...))
}

// AppDNSMaterial joins a single committed snapshot. Reading it grants no new
// native effect; NativePermit separately checks current quorum/admission.
func (p Policy) AppDNSMaterial(s state.State, owner [32]byte, tenant, id string, originals ...[32]byte) (services.DNSOwnerPolicy, AppDNSOwner, error) {
	if len(originals) > 1 {
		return services.DNSOwnerPolicy{}, AppDNSOwner{}, ErrCatalog
	}
	if len(originals) == 1 {
		if !p.ownsResource(s, owner, originals[0]) {
			return services.DNSOwnerPolicy{}, AppDNSOwner{}, ErrCatalog
		}
		owner = originals[0]
	}
	apps, err := p.readOnlyApps(s)
	if err != nil {
		return services.DNSOwnerPolicy{}, AppDNSOwner{}, err
	}
	a, rows, ok := apps.NetworkDNS(owner)
	if !ok {
		return services.DNSOwnerPolicy{}, AppDNSOwner{}, ErrCatalog
	}
	for _, row := range rows {
		if row.Config.Tenant != tenant || row.Config.ID != id {
			continue
		}
		if row.Managed != nil {
			material, err := p.managedDNSMaterial(s, apps, owner, row)
			// NetworkDNS made an owned Authority above. The checked Apps view
			// is borrowed and must not escape through the returned material.
			material.Authority = a
			return material, row, err
		}
		projection, err := p.projectResourcesFromApps(s, apps)
		if err != nil {
			return services.DNSOwnerPolicy{}, row, err
		}
		goal, ok := projection.Goals[row.Source.Key]
		obj := s.Object(row.Source.Key)
		if !ok || goal.Goal.Kind != "dns" || goal.Goal.Owner != owner || !obj.Present || obj.Generation != row.Source.Generation || obj.Revision < row.Source.Revision {
			return services.DNSOwnerPolicy{}, row, ErrCatalog
		}
		entry, ok := apps.entries[appKey(goal.Goal.Tenant, goal.Goal.App)]
		if !ok {
			return services.DNSOwnerPolicy{}, row, ErrCatalog
		}
		var declaration deployment.DNSDeclaration
		if json.Unmarshal(goal.Goal.Config, &declaration) != nil || declaration.Limits.TCP < 1 {
			return services.DNSOwnerPolicy{}, row, ErrCatalog
		}
		if goal.Goal.Lifecycle != nil && goal.Goal.Lifecycle.Drain {
			if row.Config.Enabled {
				return services.DNSOwnerPolicy{}, row, ErrCatalog
			}
		} else if obj.Revision != row.Source.Revision || !row.Config.Enabled {
			return services.DNSOwnerPolicy{}, row, ErrCatalog
		}
		catalog, err := p.Catalog(s)
		if err != nil {
			return services.DNSOwnerPolicy{}, row, err
		}
		material := services.DNSOwnerPolicy{Catalog: catalog, Networks: projection.Resources.Networks, Authority: a, Actor: entry.Origin.Session.User, Config: row.Config, MaxConnections: declaration.Limits.TCP, RequestTimeout: time.Duration(declaration.Limits.Timeout) * time.Millisecond}
		for _, dependency := range goal.Goal.Dependencies {
			if !strings.HasPrefix(dependency.Key, "network/bridge/") {
				continue
			}
			bridge, known := projection.Goals[dependency.Key]
			if !known || bridge.Bridge == nil || bridge.Goal.Owner != owner || bridge.Bridge.Network != row.Config.Network || s.Object(dependency.Key).Generation != dependency.Generation {
				return material, row, ErrCatalog
			}
			if material.Bridge != "" {
				return material, row, ErrCatalog
			}
			material.Bridge, material.BridgeGeneration = dependency.Key, dependency.Generation
		}
		if material.Bridge == "" {
			return material, row, ErrCatalog
		}
		for _, group := range apps.network.Groups {
			for _, other := range group.Owners {
				material.ProtectedZones = append(material.ProtectedZones, other.Config.Zone)
				if other.Config.ClientZone != "" {
					material.ProtectedZones = append(material.ProtectedZones, other.Config.ClientZone)
				}
			}
		}
		return material, row, nil
	}
	return services.DNSOwnerPolicy{}, AppDNSOwner{}, ErrCatalog
}
