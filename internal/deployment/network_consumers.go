// SPDX-License-Identifier: Apache-2.0

package deployment

import "encoding/json"

// NetworkConsumerDemand is a capacity edge from original declaration metadata.
// It is neither a native pin nor an allocation/cleanup receipt. The consumer ID
// allows the same cold-replaced resource's current and future edge to share its
// budget while preserving every distinct source/owner dependency.
type NetworkConsumerDemand struct {
	Source, Consumer, Tenant, Node string
	Owner                          [32]byte
}

// NetworkConsumers consumes the same immutable declaration graph for committed
// Goals and pending move artifacts. No native object or generation is invented
// to estimate a future consumer.
func NetworkConsumers(scope AppScope, steps []Step) ([]NetworkConsumerDemand, error) {
	byKey := make(map[string]Step, len(steps))
	for _, s := range steps {
		if _, duplicate := byKey[s.Key]; duplicate {
			return nil, ErrInputs
		}
		byKey[s.Key] = s
	}
	var out []NetworkConsumerDemand
	add := func(source, consumer, tenant, node string, owner [32]byte) error {
		if source == "" || consumer == "" || tenant == "" || node == "" || owner == ([32]byte{}) {
			return ErrInputs
		}
		out = append(out, NetworkConsumerDemand{Source: source, Consumer: consumer, Tenant: tenant, Node: node, Owner: owner})
		return nil
	}
	bridge := func(parent Step, consumer string) error {
		switch parent.Kind {
		case "bridge":
			return add(parent.Key, consumer, scope.Tenant, parent.Node, parent.Owner)
		case "network-ref":
			var ref NetworkReference
			if json.Unmarshal(parent.Goal, &ref) != nil || ref.Tenant != scope.Tenant || ref.Node != parent.Node || ref.Owner != parent.Owner {
				return ErrInputs
			}
			return add(ref.Source.Key, consumer, ref.Tenant, ref.Node, ref.Owner)
		}
		return nil
	}
	for _, s := range steps {
		switch s.Kind {
		case "tunnel":
			if err := add(s.Key, s.Key+"/packet-plane", scope.Tenant, s.Node, s.Owner); err != nil {
				return nil, err
			}
		case "network-ref":
			if err := bridge(s, s.Key+"/bridge"); err != nil {
				return nil, err
			}
			var ref NetworkReference
			if json.Unmarshal(s.Goal, &ref) != nil {
				return nil, ErrInputs
			}
			if tun, frozen := ref.LocalTunnel(); frozen {
				if err := add(tun.Key, s.Key+"/tunnel", ref.Tenant, ref.Node, ref.Owner); err != nil {
					return nil, err
				}
			}
		case "task", "registry", "dns":
			for _, dep := range s.Dependencies {
				if err := bridge(byKey[dep.Key], s.Key+"/"+dep.Key); err != nil {
					return nil, err
				}
			}
		case "ingress":
			var original IngressDeclaration
			if json.Unmarshal(s.Goal, &original) != nil || original.Node != s.Node {
				return nil, ErrInputs
			}
			matched := map[string]bool{}
			for _, route := range IngressRoutes(original) {
				declaration := ingressForRoute(original, route)
				consumer := s.Key
				if len(original.Routes) > 0 {
					consumer += "/route/" + route.ID
				}
				found := false
				for _, taskKey := range s.Identity {
					instance, err := ReplicaInstanceForKey(scope.Tenant, scope.App, taskKey)
					if err != nil {
						return nil, ErrInputs
					}
					if instance.Service != declaration.Backend.Service {
						continue
					}
					if declaration.Backend.Network == "" {
						return nil, ErrInputs
					}
					matched[taskKey] = true
					alias := declaration.Backend.Network
					localKey := ResourceKey("network-ref", scope.Tenant, scope.App, alias+"/"+s.Node)
					if local, exists := byKey[localKey]; exists {
						var ref NetworkReference
						if local.Kind != "network-ref" || json.Unmarshal(local.Goal, &ref) != nil || ref.Tenant != scope.Tenant || ref.Node != s.Node || ref.Owner != local.Owner {
							return nil, ErrInputs
						}
						if instance.Node == s.Node {
							if err := bridge(local, consumer+"/"+taskKey+"/"+localKey); err != nil {
								return nil, err
							}
						} else {
							tun, frozen := ref.LocalTunnel()
							if !frozen {
								return nil, ErrInputs
							}
							if err := add(tun.Key, consumer+"/"+taskKey+"/"+tun.Key, ref.Tenant, ref.Node, ref.Owner); err != nil {
								return nil, err
							}
						}
					} else if instance.Node == s.Node {
						bridgeKey := ResourceKey("bridge", scope.Tenant, scope.App, alias+"/"+s.Node)
						local, exists := byKey[bridgeKey]
						if !exists || local.Kind != "bridge" || local.Node != s.Node {
							return nil, ErrInputs
						}
						if err := bridge(local, consumer+"/"+taskKey+"/"+bridgeKey); err != nil {
							return nil, err
						}
					} else {
						tunnelKey := ResourceKey("tunnel", scope.Tenant, scope.App, alias+"/"+s.Node)
						local, exists := byKey[tunnelKey]
						if !exists || local.Kind != "tunnel" || local.Node != s.Node {
							return nil, ErrInputs
						}
						if err := add(tunnelKey, consumer+"/"+taskKey+"/"+tunnelKey, scope.Tenant, local.Node, local.Owner); err != nil {
							return nil, err
						}
					}
					found = true
				}
				for _, dependency := range s.Dependencies {
					if ingressIdentity(s, dependency.Key) {
						continue
					}
					task, exists := byKey[dependency.Key]
					if !exists || task.Kind != "task" {
						continue
					}
					var config ComposeService
					if json.Unmarshal(task.Goal, &config) != nil {
						return nil, ErrInputs
					}
					instance, err := TaskInstanceForKey(scope.Tenant, scope.App, task.Key, config)
					if err != nil || instance.Node != task.Node {
						return nil, ErrInputs
					}
					if instance.Service != declaration.Backend.Service {
						continue
					}
					matched[task.Key] = true
					found = true
					taskKey := task.Key
					if task.Node == s.Node {
						for _, dep := range task.Dependencies {
							if err := bridge(byKey[dep.Key], consumer+"/"+taskKey+"/"+dep.Key); err != nil {
								return nil, err
							}
						}
						continue
					}
					var service ComposeService
					if json.Unmarshal(task.Goal, &service) != nil {
						return nil, ErrInputs
					}
					alias, err := ingressNetwork(declaration, service)
					if err != nil {
						return nil, err
					}
					localKey := ResourceKey("network-ref", scope.Tenant, scope.App, alias+"/"+s.Node)
					if local, exists := byKey[localKey]; exists {
						var ref NetworkReference
						if local.Kind != "network-ref" || json.Unmarshal(local.Goal, &ref) != nil || ref.Tenant != scope.Tenant || ref.Node != s.Node || ref.Owner != local.Owner {
							return nil, ErrInputs
						}
						tun, frozen := ref.LocalTunnel()
						if !frozen {
							return nil, ErrInputs
						}
						if err := add(tun.Key, consumer+"/"+taskKey+"/"+tun.Key, ref.Tenant, ref.Node, ref.Owner); err != nil {
							return nil, err
						}
					} else {
						tunnelKey := ResourceKey("tunnel", scope.Tenant, scope.App, alias+"/"+s.Node)
						tunnel, exists := byKey[tunnelKey]
						if !exists || tunnel.Kind != "tunnel" || tunnel.Node != s.Node {
							return nil, ErrInputs
						}
						if err := add(tunnelKey, consumer+"/"+taskKey+"/"+tunnelKey, scope.Tenant, tunnel.Node, tunnel.Owner); err != nil {
							return nil, err
						}
					}
				}
				if !found {
					return nil, ErrInputs
				}
			}
			for _, taskKey := range s.Identity {
				if !matched[taskKey] {
					return nil, ErrInputs
				}
			}
			for _, dep := range s.Dependencies {
				if task, exists := byKey[dep.Key]; exists && task.Kind == "task" && !matched[dep.Key] {
					return nil, ErrInputs
				}
			}
		}
	}
	return out, nil
}

func (b Blueprint) NetworkConsumers() ([]NetworkConsumerDemand, error) {
	return NetworkConsumers(b.Scope(), b.Steps())
}
