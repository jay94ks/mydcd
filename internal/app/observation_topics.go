// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/topiclast"
)

// Node observations travel on the SFCP Topic channel, family obs
// (devel/design/node-observation-topics.md): a server publishes its own
// reports under obs/<server>/<T-obs-src>[/…], and only servers that read
// them subscribe.
const (
	// observationTopicTTL is the obs family's message TTL (topic-space 2).
	observationTopicTTL = 150 * time.Second
	// observationLinger keeps a pattern subscribed after its last reader
	// (design 6-2).
	observationLinger = 150 * time.Second
	// observationQueryWait bounds how long a query waits for publishers
	// to sync; a later one is shown as waiting (design 6-1).
	observationQueryWait = 2 * time.Second
	// observationIdleInterval is the measuring round while nobody
	// subscribes to this server's reports (design 6-3).
	observationIdleInterval = 5 * time.Minute
	// observationAll is what readers subscribe to.
	observationAll = sfcp.TopicFamilyObservation + "/#"
)

// observationTopic is report's topic: obs/<node>/<T-obs-src>[/…].
func observationTopic(report observability.Report) (string, bool) {
	kind, rest, _ := strings.Cut(report.Source(), "/")
	abbr, ok := sfcp.TopicObservationSource[kind]
	if !ok || report.Node == "" {
		return "", false
	}
	segs := []string{sfcp.TopicFamilyObservation, report.Node, abbr}
	if kind == "disk" {
		disk, id, _ := strings.Cut(rest, "/")
		d, ok := sfcp.TopicObservationDisk[disk]
		if !ok {
			return "", false
		}
		segs = append(segs, d)
		rest = id
	}
	if rest != "" {
		segs = append(segs, strings.Split(rest, "/")...)
	}
	return sfcp.TopicName(segs...), true
}

var errObservationPeerDown = errors.New("no session to the server")

// observationTopics is this server's side of the obs family.
type observationTopics struct {
	self   string
	topics *sfcp.Topics
	store  *topiclast.Store
	cache  *topiclast.Cache

	mu       sync.Mutex
	interest map[string]int // "peer\x00pattern" of remote subscriptions reaching this server
	local    int            // readers on this server (queries, watches)
	kick     chan struct{}  // asks the measuring loop for a round now
	round    chan struct{}  // closed when a measuring round finishes
}

// startObservationTopics attaches the obs family to the mesh. It runs
// before the mesh listens.
func (r *Runtime) startObservationTopics(self string) error {
	t := r.Topics()
	// Publish: the second segment must be the sending server (nil rule);
	// subscribe: cluster members (nil rule).
	if err := t.ReserveTopic(sfcp.TopicFamilyObservation, sfcp.TopicACL{TTL: observationTopicTTL}); err != nil {
		return err
	}
	o := &observationTopics{self: self, topics: t, interest: map[string]int{}, kick: make(chan struct{}, 1), round: make(chan struct{})}
	t.OnInterest(o.noteInterest)
	o.store = topiclast.NewStore(t, topiclast.StoreOptions{
		Family:  sfcp.TopicFamilyObservation,
		MaxAge:  time.Duration(observability.MaxAge) * time.Millisecond,
		Publish: sfcp.PublishOptions{Replace: true, TTL: observationTopicTTL},
		Stale:   func(string) { o.measureNow() },
	})
	o.cache = topiclast.NewCache(r.dialObservations, topiclast.CacheOptions{
		Linger: observationLinger,
		Accept: func(m sfcp.Message, _ []byte, _ bool) bool { return r.acceptObservation(m) },
	})
	r.Mesh.OnPeerConnected(func(p sfcp.Peer) { o.cache.PeerUp(p.ID) })
	r.obsTopics = o
	return nil
}

// noteInterest counts remote subscriptions that can match this server's
// topics; a new one asks for a round when the values are old.
func (o *observationTopics) noteInterest(i sfcp.Interest) {
	segs := strings.Split(i.Pattern, "/")
	if len(segs) < 2 || segs[0] != sfcp.TopicFamilyObservation || segs[1] != o.self && segs[1] != "+" && segs[1] != "#" {
		return
	}
	k := i.PeerID + "\x00" + i.Pattern
	o.mu.Lock()
	idle := o.local == 0 && len(o.interest) == 0
	if i.Added {
		o.interest[k]++
	} else if o.interest[k] > 1 {
		o.interest[k]--
	} else {
		delete(o.interest, k)
	}
	o.mu.Unlock()
	// The first reader after an idle stretch gets a round at once: the
	// remembered values may be up to observationIdleInterval old, or
	// missing.
	if i.Added && idle {
		o.measureNow()
	}
}

// wanted reports whether someone reads this server's reports, so rounds
// run every observationInterval instead of observationIdleInterval.
func (o *observationTopics) wanted() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.local > 0 || len(o.interest) > 0
}

func (o *observationTopics) measureNow() {
	select {
	case o.kick <- struct{}{}:
	default:
	}
}

// roundDone is closed when the current measuring round finishes.
func (o *observationTopics) roundDone() <-chan struct{} {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.round
}

func (o *observationTopics) finishRound() {
	o.mu.Lock()
	close(o.round)
	o.round = make(chan struct{})
	o.mu.Unlock()
}

// want subscribes to every server's reports until release; while held it
// also counts as a reader of this server's own reports.
func (o *observationTopics) want(push bool) (release func()) {
	o.mu.Lock()
	o.local++
	idle := o.local == 1 && len(o.interest) == 0
	o.mu.Unlock()
	if idle {
		o.measureNow()
	}
	stop := o.cache.Want(observationAll, push)
	var once sync.Once
	return func() {
		once.Do(func() {
			stop()
			go func() {
				// The local reader lingers like the subscription does.
				timer := time.NewTimer(observationLinger)
				defer timer.Stop()
				<-timer.C
				o.mu.Lock()
				o.local--
				o.mu.Unlock()
			}()
		})
	}
}

// published records one of this server's stored reports: it is sent when
// due (content changed or observationResend passed) and some subscription
// matches, and otherwise only kept for new subscribers.
func (o *observationTopics) published(report observability.Report, raw []byte, due bool) {
	topic, ok := observationTopic(report)
	if !ok {
		return
	}
	at := time.UnixMilli(int64(report.At))
	if due {
		_, _ = o.store.Set(topic, raw, at)
	} else {
		o.store.Keep(topic, raw, at)
	}
}

// acceptObservation stores a received report: the topic must be the
// report's own and the publisher its server; the usual admission (member
// key, freshness, newer than stored) then applies.
func (r *Runtime) acceptObservation(m sfcp.Message) bool {
	if m.Binary {
		return false
	}
	report, err := observability.Decode(m.Data)
	if err != nil || report.Node != m.PublisherID {
		return false
	}
	if topic, ok := observationTopic(report); !ok || topic != m.Topic {
		return false
	}
	return r.storeNodeObservation(m.Publisher, m.Data) == nil
}

// dialObservations opens an obs subscription to the member called peer.
func (r *Runtime) dialObservations(ctx context.Context, peer string, o sfcp.SubscribeOptions) (topiclast.Sub, []uint8, error) {
	key, ok := r.observationPeerKey(peer)
	if !ok {
		return nil, nil, sfcp.ErrAdmission
	}
	p, ok := r.Mesh.Peer(sfcp.Identity(key))
	if !ok {
		return nil, nil, sfcp.ErrAdmission
	}
	// Only an existing session: the mesh keeps sessions to members and
	// PeerUp dials again when one appears, so a query never waits on a
	// dial to a server that is down.
	if !r.Mesh.Connected(sfcp.Identity(key)) {
		return nil, nil, errObservationPeerDown
	}
	call, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	s, err := r.Mesh.Dial(call, p)
	if err != nil {
		return nil, nil, err
	}
	sub, results, err := r.obsTopics.topics.Subscribe(ctx, s, o)
	if err != nil {
		return nil, nil, err
	}
	return sub, results, nil
}

func (r *Runtime) observationPeerKey(peer string) ([32]byte, bool) {
	r.obsPeersMu.Lock()
	defer r.obsPeersMu.Unlock()
	k, ok := r.obsPeers[peer]
	return k, ok
}

// refreshObservationPeers points the cache at the full members of the
// committed view other than this server.
func (r *Runtime) refreshObservationPeers(ctx context.Context) {
	o := r.obsTopics
	if o == nil {
		return
	}
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return
	}
	d, err := r.controlPolicy.Members(v.State)
	if err != nil {
		return
	}
	peers := map[string][32]byte{}
	var ids []string
	for _, entry := range d.Entries {
		key, err := identity.ParseKey(entry.CurrentPeer().Key)
		if err != nil || key == r.Identity.Public || !membership.FullMember(entry) {
			continue
		}
		peers[entry.Peer.ID] = key
		ids = append(ids, entry.Peer.ID)
	}
	r.obsPeersMu.Lock()
	r.obsPeers = peers
	r.obsPeersMu.Unlock()
	o.cache.SetPeers(ids)
	if a := r.almTopics; a != nil {
		a.cache.SetPeers(ids)
	}
}

// awaitObservations makes the stored reports current before a query reads
// them: it subscribes (or keeps the subscription), waits up to
// observationQueryWait for every server to sync, and, when this server's
// own rounds were idle, for one fresh round. It returns the servers that
// did not sync in time; their reports may be missing ("대기 중").
func (r *Runtime) awaitObservations(ctx context.Context) []string {
	o := r.obsTopics
	if o == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, observationQueryWait)
	defer cancel()
	idle := !o.wanted()
	round := o.roundDone()
	r.refreshObservationPeers(ctx)
	release := o.want(false)
	defer release()
	synced := o.cache.Wait(ctx, observationAll)
	if idle {
		select {
		case <-round:
		case <-ctx.Done():
		}
	}
	var waiting []string
	for peer, ok := range synced {
		if !ok {
			waiting = append(waiting, peer)
		}
	}
	return waiting
}
