// SPDX-License-Identifier: Apache-2.0

package clusterapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	dockernet "github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

// ErrContainer: the cluster app container spec is invalid, or the Engine holds
// an object under the cluster app's name that this owner did not create.
var ErrContainer = errors.New("cluster app container does not match its owner")

// Bind is one host path the container sees.
type Bind struct {
	Source, Target string
	ReadOnly       bool `json:",omitempty"`
}

// ContainerSpec is one cluster app container as sfcd wants it. A changed spec
// is a new generation: the owner removes the old container, then creates the
// new one under the same name.
type ContainerSpec struct {
	Schema uint8
	App    string
	// Image is the Engine image ID the pull returned for the pinned
	// manifest Digest (on Seafield's containerd image store, that digest).
	Image, Digest string
	// Bridge is this server's sfc-system Bridge (its journal key in the
	// network module) and the generation the container borrows.
	Bridge           string
	BridgeGeneration uint64
	// Address is the app's fixed address in this server's pool
	// (network.ClusterAppAddress).
	Address  netip.Addr
	User     string
	Cmd, Env []string
	Binds    []Bind
}

func (s ContainerSpec) validate() error {
	_, known := Lookup(s.App)
	if s.Schema != 1 || !known || !strings.HasPrefix(s.Image, "sha256:") || !strings.HasPrefix(s.Digest, "sha256:") || s.Bridge == "" || s.BridgeGeneration == 0 || !s.Address.Is4() || s.User == "" || len(s.Cmd) == 0 || len(s.Cmd) > 64 || len(s.Env) > 64 || len(s.Binds) > 8 {
		return ErrContainer
	}
	for _, b := range s.Binds {
		if !filepath.IsAbs(b.Source) || filepath.Clean(b.Source) != b.Source || !filepath.IsAbs(b.Target) || filepath.Clean(b.Target) != b.Target || b.Target == "/" {
			return ErrContainer
		}
	}
	for _, v := range append(slices.Clone(s.Cmd), s.Env...) {
		if strings.ContainsRune(v, 0) {
			return ErrContainer
		}
	}
	return nil
}

// ContainerName is the cluster app's fixed container name. One generation
// exists at a time, so the name is the same across replacements.
func ContainerName(app string) string { return "sfc-cluster-app-" + app }

func journalKey(app string) string { return "cluster-app/" + app }

// Bridges is the network module's consumer side (network.Manager): the
// container holds a lease on its Bridge from create until removal.
type Bridges interface {
	Acquire(context.Context, string, string, uint64) (network.BridgeLease, error)
	InspectConsumer(context.Context, string, string, uint64) (network.BridgeLease, error)
	ReturnConsumer(string, string, uint64) error
}

// Owner keeps cluster app containers on this node: one journal entry per node
// app in state_dir/cluster-apps/journal.db, the same Apply/Remove journal the
// other native owners use. It creates, starts, replaces and removes the
// container. The Engine never restarts it (restart policy "no"): sfcd
// starts a container that exited itself (revive), after its own checks and
// in its own boot order, and RestoreApplied recreates one that was removed
// behind its back. See devel/refactor/18-sfcd-structure.md S9.
type Owner struct {
	journal *reconcile.Journal
	driver  *driver
	revives reviveBook
}

// OpenOwner opens the journal at path. c is this node's Engine connection.
func OpenOwner(path string, c *engine.Client, bridges Bridges) (*Owner, error) {
	if c == nil || c.API == nil || bridges == nil {
		return nil, ErrContainer
	}
	j, err := reconcile.OpenJournal(path)
	if err != nil {
		return nil, err
	}
	return &Owner{journal: j, driver: &driver{engine: c, bridges: bridges}}, nil
}

// Close closes the journal. It leaves containers as they are; Shutdown
// removes them first.
func (o *Owner) Close() error { return o.journal.Close() }

// Apps lists the cluster apps that have a journal entry.
func (o *Owner) Apps() []string {
	var out []string
	for _, key := range o.journal.Keys() {
		if app, ok := strings.CutPrefix(key, "cluster-app/"); ok {
			out = append(out, app)
		}
	}
	slices.Sort(out)
	return out
}

// Set records what app should be (nil: no container) and moves the
// container one journal step toward it. A step that waits (the Bridge is not
// ready, an Engine call failed) returns its error; the next call goes on.
func (o *Owner) Set(ctx context.Context, app string, spec *ContainerSpec) error {
	if _, known := Lookup(app); !known || spec != nil && (spec.App != app || spec.validate() != nil) {
		return ErrContainer
	}
	key := journalKey(app)
	r, err := o.journal.Read(key)
	if err != nil && !errors.Is(err, storage.ErrMissing) {
		return err
	}
	missing := errors.Is(err, storage.ErrMissing)
	current := r.State.Desired
	var want reconcile.Desired
	if spec == nil {
		if missing {
			return nil
		}
		want = reconcile.Desired{Revision: current.Revision + 1}
		if !current.Present {
			want = current
		}
	} else {
		raw, _ := json.Marshal(spec)
		want = reconcile.Desired{Revision: current.Revision + 1, Resource: reconcile.Resource{Present: true, Generation: r.State.GenerationFloor + 1, Spec: string(raw)}}
		if current.Present && current.Spec == string(raw) {
			want = current
		}
	}
	if missing || want != current {
		if err = o.journal.Desired(key, want, 1); err != nil {
			return err
		}
	}
	if err = o.journal.Step(ctx, key, o.driver); err != nil {
		return err
	}
	if spec != nil {
		// The container was there and is gone now (docker rm by hand): plan
		// its repair under the same generation, and run it.
		if err = o.journal.RestoreApplied(ctx, key, o.driver); err != nil {
			return err
		}
		if err = o.journal.Step(ctx, key, o.driver); err != nil {
			return err
		}
		return o.revive(ctx, app, time.Now())
	}
	return nil
}

// revive starts app's applied container again when it has stopped. Only the
// exact applied generation is started (its identity labels and spec must
// still match, with the Bridge lease held), and never before its backoff
// allows; each start is counted and its reason logged.
func (o *Owner) revive(ctx context.Context, app string, now time.Time) error {
	r, err := o.journal.Read(journalKey(app))
	if err != nil || r.State.Pending != nil || !r.State.Applied.Present || r.State.Applied != r.State.Desired.Resource {
		return nil
	}
	s, id, err := o.driver.parameters(journalKey(app), r.State.Applied)
	if err != nil {
		return err
	}
	got, err := o.driver.engine.API.ContainerInspect(ctx, id.Name, client.ContainerInspectOptions{})
	if cerrdefs.IsNotFound(err) {
		return nil // RestoreApplied plans the repair
	}
	if err != nil {
		return err
	}
	st := got.Container.State
	if st == nil || st.Running || st.Restarting || st.Paused {
		o.revives.running(app, st != nil && st.Running, now)
		return nil
	}
	lease, err := o.driver.bridges.InspectConsumer(ctx, s.Bridge, consumer(id), s.BridgeGeneration)
	if err != nil {
		return err
	}
	if !matches(got.Container, s, id, lease) {
		return ErrContainer
	}
	reason := exitReason(st)
	if !o.revives.due(app, now) {
		return nil
	}
	if _, err = o.driver.engine.API.ContainerStart(ctx, got.Container.ID, client.ContainerStartOptions{}); err != nil {
		o.revives.failed(app, now)
		return fmt.Errorf("cluster app %s: start after %s: %w", app, reason, err)
	}
	n := o.revives.record(app, reason, now)
	log.Printf("cluster app %s: container stopped (%s), started again (restart %d)", app, reason, n)
	return nil
}

func exitReason(st *container.State) string {
	switch {
	case st.OOMKilled:
		return "out of memory"
	case st.Status == container.StateCreated:
		return "never started"
	case st.Dead:
		return "dead"
	default:
		return "exit code " + strconv.Itoa(st.ExitCode)
	}
}

// reviveBook is the per-app restart count, last reason and backoff of revive.
// It is this daemon's memory only: a restart is a local fact, not cluster
// state (R14). The backoff doubles from reviveMin to reviveMax and resets
// once the container has kept running for reviveSettle.
type reviveBook struct {
	mu   sync.Mutex
	apps map[string]*reviveRow
}

type reviveRow struct {
	count         int
	reason        string
	next, upSince time.Time
	wait          time.Duration
}

const (
	reviveMin    = time.Second
	reviveMax    = 5 * time.Minute
	reviveSettle = 10 * time.Minute
)

func (b *reviveBook) row(app string) *reviveRow {
	if b.apps == nil {
		b.apps = map[string]*reviveRow{}
	}
	r := b.apps[app]
	if r == nil {
		r = &reviveRow{}
		b.apps[app] = r
	}
	return r
}

func (b *reviveBook) due(app string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !now.Before(b.row(app).next)
}

// record counts one start and returns the new count.
func (b *reviveBook) record(app, reason string, now time.Time) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.row(app)
	r.count++
	r.reason = reason
	r.wait = min(max(2*r.wait, reviveMin), reviveMax)
	r.next = now.Add(r.wait)
	r.upSince = time.Time{}
	return r.count
}

func (b *reviveBook) failed(app string, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.row(app)
	r.wait = min(max(2*r.wait, reviveMin), reviveMax)
	r.next = now.Add(r.wait)
}

func (b *reviveBook) running(app string, up bool, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.row(app)
	if !up {
		return
	}
	if r.upSince.IsZero() {
		r.upSince = now
	} else if now.Sub(r.upSince) >= reviveSettle {
		r.wait = 0
	}
}

func (b *reviveBook) stats(app string) (int, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.row(app)
	return r.count, r.reason
}

// Shutdown removes every cluster app container, returning its Bridge lease.
// The data directories stay.
func (o *Owner) Shutdown(ctx context.Context) error {
	var failed error
	for _, app := range o.Apps() {
		failed = errors.Join(failed, o.Set(ctx, app, nil))
	}
	return failed
}

// Status is what the Engine shows for a cluster app container right now.
type Status struct {
	ID, State string
	// Restarts counts this daemon's starts of a stopped container (revive);
	// LastRestart is why the last one stopped.
	Restarts    int
	LastRestart string
	// Address is the container's address on sfc-system ("" while it has
	// none, e.g. stopped).
	Address string
}

// Status inspects app's container. ok is false while there is none.
func (o *Owner) Status(ctx context.Context, app string) (Status, bool, error) {
	got, err := o.driver.engine.API.ContainerInspect(ctx, ContainerName(app), client.ContainerInspectOptions{})
	if cerrdefs.IsNotFound(err) {
		return Status{}, false, nil
	}
	if err != nil || got.Container.State == nil {
		return Status{}, false, err
	}
	restarts, reason := o.revives.stats(app)
	out := Status{ID: got.Container.ID, State: string(got.Container.State.Status), Restarts: restarts, LastRestart: reason}
	if n := got.Container.NetworkSettings; n != nil {
		for _, e := range n.Networks {
			if e != nil && e.IPAddress.IsValid() {
				out.Address = e.IPAddress.String()
			}
		}
	}
	return out, true, nil
}

// stopPolicy gives the cluster app the same default grace as a task.
var stopPolicy = engine.StopPolicy{GraceSeconds: engine.DefaultStopGrace, Signal: "SIGTERM"}

type driver struct {
	engine  *engine.Client
	bridges Bridges
}

func (d *driver) parameters(key string, target reconcile.Resource) (ContainerSpec, engine.Identity, error) {
	s, err := schema.Decode[ContainerSpec]([]byte(target.Spec))
	if err != nil || s.validate() != nil || key != journalKey(s.App) {
		return s, engine.Identity{}, ErrContainer
	}
	id, err := d.engine.Identity("container", key, target)
	if err != nil {
		return s, engine.Identity{}, err
	}
	id.Name = ContainerName(s.App)
	id.Labels["org.sfc.cluster-app"] = s.App
	return s, id, nil
}

// consumer names the container's Bridge lease; the generation keeps an old
// container's lease apart from its replacement's.
func consumer(id engine.Identity) string {
	return "cluster-app/" + id.Labels["org.sfc.cluster-app"] + "/" + id.Labels["org.sfc.generation"]
}

func (d *driver) Execute(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	if op.Kind == reconcile.Remove {
		return d.remove(ctx, key, op)
	}
	s, id, err := d.parameters(key, op.Target)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	_, err = d.engine.API.ContainerInspect(ctx, id.Name, client.ContainerInspectOptions{})
	if err == nil {
		return d.Recover(ctx, key, op)
	}
	if !cerrdefs.IsNotFound(err) {
		return reconcile.EffectUnknown, err
	}
	// Nothing below has reached the Engine until ContainerCreate: a failure
	// before it is positive evidence that this Apply did not happen.
	image, err := d.engine.API.ImageInspect(ctx, s.Image)
	switch {
	case cerrdefs.IsNotFound(err):
		err = errors.Join(ErrImageNotFound, err) // docker rmi; the caller loads it again
	case err == nil && image.ID != s.Image:
		err = ErrImageNotFound
	}
	if err == nil {
		err = d.create(ctx, s, id)
		if err == nil || !errors.Is(err, errNotCreated) {
			return d.Recover(ctx, key, op)
		}
	}
	if returnErr := d.bridges.ReturnConsumer(s.Bridge, consumer(id), s.BridgeGeneration); returnErr != nil {
		return reconcile.EffectUnknown, errors.Join(err, returnErr)
	}
	return reconcile.EffectNotApplied, err
}

// errNotCreated wraps a failure before ContainerCreate was sent.
var errNotCreated = errors.New("cluster app container not created")

// create borrows the Bridge (the same lease again on a retry) and creates the
// container. A failure that reached the Engine's create is not errNotCreated.
func (d *driver) create(ctx context.Context, s ContainerSpec, id engine.Identity) error {
	lease, err := d.bridges.Acquire(ctx, s.Bridge, consumer(id), s.BridgeGeneration)
	if err != nil {
		return errors.Join(errNotCreated, err)
	}
	if err = ctx.Err(); err != nil {
		return errors.Join(errNotCreated, err)
	}
	var mounts []mount.Mount
	for _, b := range s.Binds {
		mounts = append(mounts, mount.Mount{Type: mount.TypeBind, Source: b.Source, Target: b.Target, ReadOnly: b.ReadOnly})
	}
	config := &container.Config{Image: s.Image, Cmd: s.Cmd, Env: s.Env, User: s.User, Labels: id.Labels}
	host := &container.HostConfig{Mounts: mounts, NetworkMode: container.NetworkMode(lease.NetworkID), ReadonlyRootfs: true, RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyDisabled}, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"}}
	// The fixed address inside this server's pool: every server knows it
	// without a report.
	networking := &dockernet.NetworkingConfig{EndpointsConfig: map[string]*dockernet.EndpointSettings{lease.NetworkID: {IPAMConfig: &dockernet.EndpointIPAMConfig{IPv4Address: s.Address}}}}
	_, err = d.engine.API.ContainerCreate(ctx, client.ContainerCreateOptions{Name: id.Name, Config: config, HostConfig: host, NetworkingConfig: networking})
	if cerrdefs.IsConflict(err) {
		return nil // the name exists; Recover checks whose it is
	}
	return err
}

// Recover finishes the original Apply on the exact named container. The
// fixed name lets the Engine hold at most one container for it, so
// creating it again after an unanswered create cannot make a second one:
// a late original create and this one meet at the same name, and the
// labels show it is this generation's. This is why, unlike other native
// owners, Recover may send create again: the name, not the journal, keeps
// the effect single, and a name held by anything else stops it (Unknown).
func (d *driver) Recover(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	if op.Kind == reconcile.Remove {
		return d.remove(ctx, key, op)
	}
	s, id, err := d.parameters(key, op.Target)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	got, err := d.engine.API.ContainerInspect(ctx, id.Name, client.ContainerInspectOptions{})
	if cerrdefs.IsNotFound(err) {
		if err = d.create(ctx, s, id); err != nil {
			return reconcile.EffectUnknown, err
		}
		got, err = d.engine.API.ContainerInspect(ctx, id.Name, client.ContainerInspectOptions{})
	}
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	lease, err := d.bridges.InspectConsumer(ctx, s.Bridge, consumer(id), s.BridgeGeneration)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	if !matches(got.Container, s, id, lease) {
		return reconcile.EffectUnknown, ErrContainer
	}
	if st := got.Container.State; !st.Running && !st.Restarting {
		if _, err = d.engine.API.ContainerStart(ctx, got.Container.ID, client.ContainerStartOptions{}); err != nil {
			return reconcile.EffectUnknown, err
		}
	}
	return reconcile.EffectApplied, nil
}

func matches(got container.InspectResponse, s ContainerSpec, id engine.Identity, lease network.BridgeLease) bool {
	if got.Config == nil || got.HostConfig == nil || got.State == nil || got.ID == "" || !id.Matches(got.Name, got.Config.Labels) || got.Image != s.Image || got.Config.User != s.User || !slices.Equal(got.Config.Cmd, s.Cmd) || got.HostConfig.Privileged || got.HostConfig.NetworkMode != container.NetworkMode(lease.NetworkID) || got.HostConfig.RestartPolicy.Name != container.RestartPolicyDisabled || len(got.HostConfig.Binds) != 0 || len(got.HostConfig.Mounts) != len(s.Binds) {
		return false
	}
	// The Engine adds the image's own ENV after ours.
	for _, v := range s.Env {
		if !slices.Contains(got.Config.Env, v) {
			return false
		}
	}
	for i, b := range s.Binds {
		m := got.HostConfig.Mounts[i]
		if m.Type != mount.TypeBind || m.Source != b.Source || m.Target != b.Target || m.ReadOnly != b.ReadOnly {
			return false
		}
	}
	return true
}

// remove stops and removes the exact generation's container, then returns
// its Bridge lease. Removing an already removed container is the same
// result, so Execute and Recover share it.
func (d *driver) remove(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	s, id, err := d.parameters(key, op.Target)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	got, err := d.engine.API.ContainerInspect(ctx, id.Name, client.ContainerInspectOptions{})
	switch {
	case cerrdefs.IsNotFound(err):
	case err != nil:
		return reconcile.EffectUnknown, err
	case got.Container.Config == nil || !id.Matches(got.Container.Name, got.Container.Config.Labels):
		// Another generation or a foreign object holds the name.
		return reconcile.EffectUnknown, ErrContainer
	default:
		if got.Container.State != nil && got.Container.State.Running {
			if err = d.engine.StopContainer(ctx, got.Container.ID, stopPolicy); err != nil {
				return reconcile.EffectUnknown, err
			}
		}
		if _, err = d.engine.API.ContainerRemove(ctx, got.Container.ID, client.ContainerRemoveOptions{Force: true}); err != nil && !cerrdefs.IsNotFound(err) {
			return reconcile.EffectUnknown, err
		}
	}
	if err = d.bridges.ReturnConsumer(s.Bridge, consumer(id), s.BridgeGeneration); err != nil {
		return reconcile.EffectUnknown, err
	}
	return reconcile.EffectApplied, nil
}

// AppliedAbsent: the applied container is gone from the Engine.
func (d *driver) AppliedAbsent(ctx context.Context, key string, applied reconcile.Resource) (bool, error) {
	if _, _, err := d.parameters(key, applied); err != nil {
		return false, err
	}
	_, err := d.engine.API.ContainerInspect(ctx, ContainerName(strings.TrimPrefix(key, "cluster-app/")), client.ContainerInspectOptions{})
	if cerrdefs.IsNotFound(err) {
		return true, nil
	}
	return false, err
}

// Joining answers the engine asking whether a container may join this
// server's system bridge. handled is false for a container that is not a
// cluster app's (by name and label); the network's own answer applies to
// it. A cluster app's container may join only as the exact container the
// journal is creating or holds (identity labels and name), with exactly its
// fixed address.
func (o *Owner) Joining(name string, labels map[string]string, addresses []netip.Prefix) (handled, allow bool) {
	app := labels["org.sfc.cluster-app"]
	if app == "" && !strings.HasPrefix(strings.TrimPrefix(name, "/"), "sfc-cluster-app-") {
		return false, false
	}
	if _, known := Lookup(app); !known || o == nil || len(addresses) != 1 {
		return true, false
	}
	key := journalKey(app)
	r, err := o.journal.Read(key)
	if err != nil {
		return true, false
	}
	candidates := []reconcile.Resource{r.State.Applied}
	if p := r.State.Pending; p != nil && p.Kind != reconcile.Remove {
		candidates = append(candidates, p.Target)
	}
	for _, target := range candidates {
		if !target.Present {
			continue
		}
		s, id, err := o.driver.parameters(key, target)
		if err == nil && id.Matches(name, labels) && addresses[0].Addr() == s.Address {
			return true, true
		}
	}
	return true, false
}
