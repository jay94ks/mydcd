// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"encoding/hex"
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/engine"
	"strings"
)

func validTaskOwner(r Activation) bool {
	if r.TaskOwner == "" {
		return true
	}
	var task struct {
		Node         string
		ResourceKeys []lifecycle.IdentityTransition
	}
	if json.Unmarshal([]byte(r.Task.Spec), &task) != nil || task.Node != r.TaskOwner {
		return false
	}
	parts := strings.Split(r.TaskOwner, "/")
	if len(parts) != 2 {
		return false
	}
	raw, err := hex.DecodeString(parts[1])
	if err != nil || len(raw) != 32 {
		return false
	}
	var key [32]byte
	copy(key[:], raw)
	return r.TaskOwner == engine.Owner(r.Scope.Cluster, key) && lifecycle.ResourceIdentity(r.Scope.Cluster, r.Consumer.Owner.Node, key, r.Consumer.Owner.Key, task.ResourceKeys)
}
func taskOwner(r Activation) string {
	if r.TaskOwner != "" {
		return r.TaskOwner
	}
	return engine.Owner(r.Scope.Cluster, r.Consumer.Owner.Key)
}
func (s *Activations) taskIdentity(r Activation) (engine.Identity, error) {
	owner := s.client.Owner
	if r.TaskOwner != "" {
		if !validTaskOwner(r) {
			return engine.Identity{}, ErrActivation
		}
		owner = r.TaskOwner
	}
	return s.client.IdentityForOwner(owner, "container", r.TaskKey, r.Task)
}

// AttachRetained joins only local adapters opened by the installed runtime
// from its durable identity history. It grants no transport or command rights.
func (s *Activations) AttachRetained(other *Activations) error {
	if s == nil || other == nil || s == other || s.cluster != other.cluster || s.node == other.node || s.client == nil || other.client == nil || s.client.API.DaemonHost() != other.client.API.DaemonHost() {
		return ErrActivation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retained == nil {
		s.retained = map[[32]byte]*Activations{}
	}
	if prior := s.retained[other.node]; prior != nil && prior != other {
		return ErrActivation
	}
	s.retained[other.node] = other
	return nil
}
func (s *Activations) ownerStore(key [32]byte) *Activations {
	if key == s.node {
		return s
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retained[key]
}
func (s *Activations) mountSource(key string, scope Scope, owner Owner, generation uint64, binding string) (string, bool, error) {
	original := s.ownerStore(owner.Key)
	if original == nil {
		return "", false, ErrActivation
	}
	return original.native.MountSource(key, scope, owner, generation, binding)
}
func originalRef(r Activation) Activation { r.Operation = 0; return r }
func (s *Activations) fixedSourcePath(path string) bool {
	if s.native.fixed != nil && strings.HasPrefix(path, s.native.fixed.projector.path+"/") {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, owner := range s.retained {
		if owner.native.fixed != nil && strings.HasPrefix(path, owner.native.fixed.projector.path+"/") {
			return true
		}
	}
	return false
}
