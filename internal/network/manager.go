// SPDX-License-Identifier: Apache-2.0

package network

import (
	"context"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"sync"

	"github.com/moby/moby/client"
)

// Manager is the sole local owner of Bridge journals and their consumer pins.
// All Desired supplied here must already be committed in the cluster FSM.
type Manager struct {
	retained      map[string]*Manager
	consumerGroup *consumerOwnerGroup
	journal       *reconcile.Journal
	driver        *BridgeDriver
	admitMu       sync.Mutex
	admit         ConsumerAdmission
	journals      map[string]*reconcile.Journal
}

// ConsumerAdmission is the installed runtime's current quorum permission for
// this exact source. It cannot call back into Manager. Existing pin recovery
// bypasses it; it does not grant application/native authority or invent IDs.
type ConsumerAdmission func(context.Context, string, reconcile.Desired) (ConsumerBudget, error)
type BridgeLease struct {
	Key, Consumer, NetworkID, NetworkName string
	Pin                                   reconcile.Lease
	Spec                                  BridgeSpec
}

func OpenManager(path string, c *engine.Client) (*Manager, error) {
	return openManager(path, c, nil)
}

func OpenManagerWithAdmission(path string, c *engine.Client, admit ConsumerAdmission, protection ...BridgeProtection) (*Manager, error) {
	if admit == nil {
		return nil, reconcile.ErrLease
	}
	if len(protection) > 1 {
		return nil, ErrPolicy
	}
	m, err := openManager(path, c, admit)
	if err == nil && len(protection) == 1 {
		m.driver.Protect = protection[0]
	}
	return m, err
}

func openManager(path string, c *engine.Client, admit ConsumerAdmission) (*Manager, error) {
	j, err := reconcile.OpenJournal(path)
	if err != nil {
		return nil, err
	}
	return &Manager{journal: j, driver: &BridgeDriver{Engine: c}, admit: admit, journals: map[string]*reconcile.Journal{"bridge": j}}, nil
}

// UseEngineHooks makes the Bridge driver register each create with h, which
// the engine's sfc network driver asks at every step. Without it the Bridge
// driver sends no create.
func (m *Manager) UseEngineHooks(h *EngineHooks) { m.driver.Hooks = h }

func (m *Manager) Desired(key string, revision, generation uint64, s *BridgeSpec, capacity int) error {
	d := reconcile.Desired{Revision: revision}
	if s == nil {
		d.Retiring = generation
	}
	if s != nil {
		b, err := json.Marshal(s)
		if err != nil {
			return err
		}
		if _, err = DecodeBridge(string(b)); err != nil {
			return err
		}
		d.Resource = reconcile.Resource{Generation: generation, Spec: string(b), Present: true}
	}
	return m.journal.Desired(key, d, capacity)
}
func (m *Manager) Step(ctx context.Context, key string) error {
	return m.journal.Step(ctx, key, m.driver)
}
func (m *Manager) Acquire(ctx context.Context, key, consumer string, generation uint64) (BridgeLease, error) {
	_, err := m.borrow(ctx, key, consumer, generation)
	if err != nil {
		return BridgeLease{}, err
	}
	return m.InspectConsumer(ctx, key, consumer, generation)
}

func (m *Manager) borrow(ctx context.Context, key, consumer string, generation uint64) (reconcile.Lease, error) {
	return m.borrowFrom(ctx, m.journal, "bridge", key, consumer, generation)
}
func (m *Manager) InspectConsumer(ctx context.Context, key, consumer string, generation uint64) (BridgeLease, error) {
	lease, _, err := m.inspectConsumerNetwork(ctx, key, consumer, generation)
	return lease, err
}

// One owned inspection is shared only inside the current call. No native
// observation, lease or permission is retained for a later request.
func (m *Manager) inspectConsumerNetwork(ctx context.Context, key, consumer string, generation uint64) (BridgeLease, client.NetworkInspectResult, error) {
	// The durable pin survives an uncertain Inspect result. It is not returned
	// speculatively: the consumer must explicitly settle/return its dependency.
	r, err := m.journal.Read(key)
	if err != nil {
		return BridgeLease{}, client.NetworkInspectResult{}, err
	}
	pin, exists := r.Consumers[consumer]
	if !exists || pin.Generation != generation {
		return BridgeLease{}, client.NetworkInspectResult{}, reconcile.ErrLease
	}
	l, network, err := m.inspectNetwork(ctx, key, r.State.Applied)
	l.Consumer, l.Pin = consumer, pin
	return l, network, err
}

func (m *Manager) Inspect(ctx context.Context, key string) (string, error) {
	r, err := m.journal.Read(key)
	if err != nil {
		return "", err
	}
	if r.State.Pending != nil || !r.State.Applied.Present || r.State.Applied != r.State.Desired.Resource {
		return "", reconcile.ErrPending
	}
	l, err := m.inspect(ctx, key, r.State.Applied)
	return l.NetworkID, err
}

func (m *Manager) inspect(ctx context.Context, key string, resource reconcile.Resource) (BridgeLease, error) {
	lease, _, err := m.inspectNetwork(ctx, key, resource)
	return lease, err
}

func (m *Manager) inspectNetwork(ctx context.Context, key string, resource reconcile.Resource) (BridgeLease, client.NetworkInspectResult, error) {
	s, id, err := m.driver.parameters(key, reconcile.Operation{Kind: reconcile.Apply, Target: resource})
	if err != nil {
		return BridgeLease{}, client.NetworkInspectResult{}, err
	}
	got, err := m.driver.Engine.API.NetworkInspect(ctx, id.Name, client.NetworkInspectOptions{})
	if err != nil {
		return BridgeLease{}, client.NetworkInspectResult{}, err
	}
	if !matchBridge(got.Network, s, id) {
		return BridgeLease{}, client.NetworkInspectResult{}, engine.ErrOwnership
	}
	// An applied Bridge with no pending operation never reaches the driver's
	// Inspect, so after a restart this is where the engine hooks learn it
	// again; otherwise every container join is answered not-ready.
	if m.driver.Hooks != nil && resource.Present {
		m.driver.Hooks.Adopt(got.Network.ID, key, resource.Generation, s.MTU)
	}
	return BridgeLease{Key: key, NetworkID: got.Network.ID, NetworkName: got.Network.Name, Spec: s}, got, nil
}
func (m *Manager) Return(l BridgeLease) error { return m.journal.Return(l.Key, l.Consumer, l.Pin) }

// ReturnConsumer is called after the consumer proves its native object is gone.
// Recovery is idempotent, but a stored different generation is never returned.
func (m *Manager) ReturnConsumer(key, consumer string, generation uint64) error {
	r, err := m.journal.Read(key)
	if err != nil {
		return err
	}
	pin, exists := r.Consumers[consumer]
	if !exists {
		return nil
	}
	if pin.Generation != generation {
		return reconcile.ErrLease
	}
	return m.journal.Return(key, consumer, pin)
}
func (m *Manager) View(key string) (reconcile.Record, error) { return m.journal.Read(key) }
func (m *Manager) Keys() []string                            { return m.journal.Keys() }

// Gone proves terminal local absence for the exact committed Drain generation.
// A stale local journal or an unprocessed source cannot authorize shared reuse.
func (m *Manager) Gone(ctx context.Context, key string, revision, generation uint64, s BridgeSpec) (bool, error) {
	r, err := m.journal.Read(key)
	if err != nil {
		return false, err
	}
	if generation == 0 || revision == 0 || r.State.GenerationFloor != generation || r.State.Desired.Revision < revision || r.State.Pending != nil || r.State.Applied.Present || r.State.Desired.Present || len(r.Consumers) != 0 {
		return false, nil
	}
	absent, err := m.driver.Engine.Gone(ctx, "bridge", key)
	if err != nil || !absent {
		return false, err
	}
	s.Lifecycle = schema.Lifecycle{}
	b, err := json.Marshal(s)
	if err != nil {
		return false, err
	}
	outcome, err := m.driver.Inspect(ctx, key, reconcile.Operation{Kind: reconcile.Remove, Target: reconcile.Resource{Present: true, Generation: generation, Spec: string(b)}})
	return outcome == reconcile.EffectApplied && err == nil, err
}
func (m *Manager) Close() error { return m.journal.Close() }
