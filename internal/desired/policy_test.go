// SPDX-License-Identifier: Apache-2.0

package desired

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/workload"
	"net/netip"
	"strings"
	"testing"
)

type fixture struct {
	t       *testing.T
	p       Policy
	s       state.State
	private ed25519.PrivateKey
	owner   string
	bridge  network.BridgeSpec
	task    workload.ContainerSpec
}

func canonical(v any) string { b, _ := json.Marshal(v); return string(b) }
func newFixture(t *testing.T) *fixture {
	t.Helper()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := [32]byte(private.Public().(ed25519.PublicKey))
	p := Policy{Cluster: [32]byte{1}, Owners: map[string][32]byte{}}
	owner := Owner(p.Cluster, pub)
	p.Owners[owner] = pub
	s, _ := state.New("admin")
	f := &fixture{t: t, p: p, s: s, private: private, owner: owner}
	f.apply(NodePrefix+"a", NodeSpec{Schema: 1, Owner: owner, CPU: 1000000000, Memory: 128 << 20, MaxBridges: 2, MaxContainers: 4, MaxEndpoints: 4, MaxConsumers: 8}, state.Applied)
	f.bridge = network.BridgeSpec{Schema: 1, Network: "net", Owner: owner, MTU: 1280, Pools: []network.Pool{{ID: "a", Network: "net", Owner: owner, MTU: 1280, Prefix: netip.MustParsePrefix("10.251.240.0/24"), Gateway: netip.MustParseAddr("10.251.240.1")}}}
	f.apply(BridgePrefix+"a", f.bridge, state.Applied)
	f.task = workload.ContainerSpec{Schema: 1, Node: owner, Image: "sha256:" + strings.Repeat("01", 32), Command: []string{"/backend"}, Bridge: BridgePrefix + "a", BridgeGeneration: f.s.Object(BridgePrefix + "a").Generation, IPv4: netip.MustParseAddr("10.251.240.2"), Memory: 32 << 20, NanoCPU: 100000000}
	return f
}
func (f *fixture) command(key string, value any) state.Command {
	c := state.Command{Actor: "admin", Epoch: 1, RequestID: fmt.Sprint(f.s.Index() + 1), Key: key, Expected: f.s.Object(key).Revision}
	if value == nil {
		c.Delete = true
	} else {
		c.Value = canonical(value)
	}
	return c
}
func (f *fixture) submit(c state.Command, code state.Code) state.Result {
	f.t.Helper()
	before := f.s
	original := before.Object(c.Key)
	n, r, err := state.ApplyChecked(before, before.Index()+1, c, f.p.Validate)
	if err != nil || r.Code != code {
		f.t.Fatalf("%s result=%+v want=%d err=%v", c.Key, r, code, err)
	}
	if before.Object(c.Key) != original {
		f.t.Fatal("candidate mutated original")
	}
	f.s = n
	return r
}
func (f *fixture) apply(key string, value any, code state.Code) state.Result {
	f.t.Helper()
	return f.submit(f.command(key, value), code)
}
func (f *fixture) proof(key string, value any) []byte {
	f.t.Helper()
	o := f.s.Object(key)
	o.Value = canonical(value)
	b, err := f.p.RetirementBytes(key, o)
	if err != nil {
		f.t.Fatal(err)
	}
	return ed25519.Sign(f.private, b)
}

func TestPolicyCompetingAddressAndRetainedRejection(t *testing.T) {
	f := newFixture(t)
	first := f.apply(TaskPrefix+"a", f.task, state.Applied)
	rejected := f.command(TaskPrefix+"b", f.task)
	r := f.submit(rejected, state.Invalid)
	if f.s.Object(rejected.Key).Revision != 0 {
		t.Fatal("rejected contender left a reservation")
	}
	// Deletion or changed addresses cannot hide the still-running original.
	f.apply(TaskPrefix+"a", nil, state.Invalid)
	changed := f.task
	changed.IPv4 = changed.IPv4.Next()
	f.apply(TaskPrefix+"a", changed, state.Invalid)
	drain := f.task
	drain.Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{1}}
	f.apply(TaskPrefix+"a", drain, state.Applied)
	f.apply(TaskPrefix+"c", f.task, state.Invalid)
	drain.Lifecycle.Proof = f.proof(TaskPrefix+"a", drain)
	f.apply(TaskPrefix+"a", drain, state.Applied)
	f.apply(TaskPrefix+"b", f.task, state.Applied)
	if again := f.submit(rejected, state.Invalid); again != r {
		t.Fatal("freed address re-evaluated rejected request", again, r)
	}
	f.apply(TaskPrefix+"a", f.task, state.Invalid)
	f.apply(TaskPrefix+"a", nil, state.Applied)
	other := f.task
	other.IPv4 = other.IPv4.Next()
	newObject := f.apply(TaskPrefix+"a", other, state.Applied)
	if newObject.Generation <= first.Generation {
		t.Fatal("recreate reused generation")
	}
	other.Lifecycle = drain.Lifecycle
	f.apply(TaskPrefix+"a", other, state.Invalid) // old generation/native proof
}

func TestPolicyRetirementProofBindingsAndMonotonicity(t *testing.T) {
	f := newFixture(t)
	key := TaskPrefix + "a"
	f.apply(key, f.task, state.Applied)
	drain := f.task
	drain.Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{7}}
	f.apply(key, drain, state.Applied)
	valid := f.proof(key, drain)
	for _, what := range []string{"signature", "cluster", "key", "generation", "nonce", "owner", "native"} {
		t.Run(what, func(t *testing.T) {
			o := f.s.Object(key)
			candidate := drain
			p := f.p
			signedKey := key
			switch what {
			case "cluster":
				p.Cluster[0]++
			case "key":
				signedKey += "other"
			case "generation":
				o.Generation++
			case "nonce":
				candidate.Lifecycle.Nonce[0]++
			case "owner":
				seed := make([]byte, 32)
				seed[0] = 1
				foreign := ed25519.NewKeyFromSeed(seed)
				b, _ := f.p.RetirementBytes(key, o)
				candidate.Lifecycle.Proof = ed25519.Sign(foreign, b)
			case "native":
				candidate.Memory *= 2
			}
			if what == "cluster" || what == "key" || what == "generation" {
				o.Value = canonical(candidate)
				b, _ := p.RetirementBytes(signedKey, o)
				candidate.Lifecycle.Proof = ed25519.Sign(f.private, b)
			} else if what != "owner" {
				candidate.Lifecycle.Proof = append([]byte(nil), valid...)
			}
			if what == "signature" {
				candidate.Lifecycle.Proof[0] ^= 1
			}
			f.apply(key, candidate, state.Invalid)
		})
	}
	drain.Lifecycle.Proof = valid
	f.apply(key, drain, state.Applied)
	withoutProof := drain
	withoutProof.Lifecycle.Proof = nil
	f.apply(key, withoutProof, state.Invalid)
	withoutProof.Lifecycle.Nonce[0]++
	f.apply(key, withoutProof, state.Invalid)
	// Snapshot values retain the complete dependency and signed release meaning.
	b, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	g, err := f.p.Project(restored)
	if err != nil || g.IPAM.Count() != 0 || !g.Tasks[key].Lifecycle.Released() {
		t.Fatal("snapshot lost release", g, err)
	}
	// A generic valid state codec is insufficient for typed module recovery.
	bad := f.command(key, f.task)
	bad.Value = `{"Schema":1}`
	corrupt, _, err := state.Apply(f.s, f.s.Index()+1, bad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.Project(corrupt); err == nil {
		t.Fatal("typed corruption was accepted")
	}
}

func TestPolicyDependenciesAndSharedBudgets(t *testing.T) {
	f := newFixture(t)
	f.apply(TaskPrefix+"a", f.task, state.Applied)
	for _, what := range []string{"overlap", "bridge-drain", "bridge-delete", "bridge-change", "node-delete", "cpu-shrink", "memory-shrink", "endpoint-shrink", "count-shrink", "foreign-owner", "stale-bridge"} {
		t.Run(what, func(t *testing.T) {
			switch what {
			case "overlap":
				other := f.bridge
				other.Pools = append([]network.Pool(nil), other.Pools...)
				other.Pools[0].ID = "b"
				f.apply(BridgePrefix+"b", other, state.Invalid)
			case "bridge-drain":
				b := f.bridge
				b.Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{3}}
				f.apply(BridgePrefix+"a", b, state.Invalid)
			case "bridge-delete":
				f.apply(BridgePrefix+"a", nil, state.Invalid)
			case "bridge-change":
				b := f.bridge
				b.MTU = 1400
				f.apply(BridgePrefix+"a", b, state.Invalid)
			case "node-delete":
				f.apply(NodePrefix+"a", nil, state.Invalid)
			case "foreign-owner":
				task := f.task
				task.Node = "unapproved"
				task.IPv4 = task.IPv4.Next()
				f.apply(TaskPrefix+"b", task, state.Invalid)
			case "stale-bridge":
				task := f.task
				task.BridgeGeneration++
				task.IPv4 = task.IPv4.Next()
				f.apply(TaskPrefix+"b", task, state.Invalid)
			default:
				n, _ := schema.Decode[NodeSpec]([]byte(f.s.Object(NodePrefix + "a").Value))
				switch what {
				case "cpu-shrink":
					n.CPU = 1
				case "memory-shrink":
					n.Memory = 1
				case "endpoint-shrink":
					n.MaxEndpoints = 0
				case "count-shrink":
					n.MaxContainers = 0
				}
				f.apply(NodePrefix+"a", n, state.Invalid)
			}
		})
	}
	n, _ := schema.Decode[NodeSpec]([]byte(f.s.Object(NodePrefix + "a").Value))
	n.MaxConsumers = 1
	f.apply(NodePrefix+"a", n, state.Applied) // admission changes preserve local users
	view := f.s.Objects("")
	delete(view, TaskPrefix+"a")
	if !f.s.Object(TaskPrefix + "a").Present {
		t.Fatal("object view aliases FSM")
	}
}

func TestNativeLifecycleCorePreservesOriginalSpecAndIrreversibleDrain(t *testing.T) {
	f := newFixture(t)
	key := BridgePrefix + "original"
	original := state.Object{Present: true, Generation: 7, Revision: 7, Value: canonical(f.bridge)}
	nonce := [16]byte{1}
	value, err := WithLifecycle(key, original.Value, schema.Lifecycle{Drain: true, Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	draining := original
	draining.Revision, draining.Value = 8, value
	if err := ValidateLifecycle(key, original, draining); err != nil {
		t.Fatal(err)
	}
	life, owner, native, proofInput, err := NativeLifecycle(key, draining.Value)
	_, originalOwner, originalNative, _, originalErr := NativeLifecycle(key, original.Value)
	if err != nil || originalErr != nil || owner != originalOwner || string(native) != string(originalNative) || !life.Drain || life.Nonce != nonce {
		t.Fatal("lifecycle rewrite changed native identity", err)
	}
	reset := draining
	reset.Revision, reset.Value = 9, original.Value
	if ValidateLifecycle(key, draining, reset) == nil {
		t.Fatal("Drain was reversible")
	}
	changed, err := WithLifecycle(key, draining.Value, schema.Lifecycle{Drain: true, Nonce: [16]byte{2}})
	if err != nil {
		t.Fatal(err)
	}
	reset.Value = changed
	if ValidateLifecycle(key, draining, reset) == nil {
		t.Fatal("original Drain nonce was replaced")
	}
	tombstone := state.Object{Revision: 10, Generation: 7}
	if ValidateLifecycle(key, draining, tombstone) == nil {
		t.Fatal("native source deleted before terminal proof")
	}
	proof := ed25519.Sign(f.private, schema.GoneBytes(f.p.Cluster, key, original.Generation, proofInput))
	life.Proof = proof
	value, err = WithLifecycle(key, draining.Value, life)
	if err != nil {
		t.Fatal(err)
	}
	released := draining
	released.Revision, released.Value = 9, value
	if ValidateLifecycle(key, draining, released) != nil || ValidateLifecycle(key, released, tombstone) != nil {
		t.Fatal("original terminal lifecycle could not settle")
	}
	if schema.VerifyGone([32]byte(f.private.Public().(ed25519.PublicKey)), f.p.Cluster, key, original.Generation, proofInput, proof) != nil {
		t.Fatal("terminal proof did not retain original key/generation/nonce")
	}
}
