// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/eventbus"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/topiclast"
)

// Alarms (design 4.8): a node sends a short alarm/<name> notice and chooses
// its reach. A node may reach other nodes (Scope.Nodes), all nodes
// (AllNodes) and the users watching through the web daemon or the CLI (Web,
// optionally narrowed to one Tenant). Only a user may address one user.
// Delivery is at most once: nothing is stored or resent.

var errAlarm = errors.New("invalid alarm")

// validNodeAlarm checks an alarm a node sends or receives from a node.
func validNodeAlarm(e eventbus.Event) bool {
	s := e.Scope
	return eventbus.IsAlarm(e.Topic) && len(e.Kind) <= 64 && len(e.Note) <= eventbus.MaxAlarmNote && s.User == "" && len(s.Nodes) <= 64 && (s.AllNodes || s.Web || len(s.Nodes) != 0)
}

// The event's Tenant is the Scope's, so a watcher needs Read on that tenant
// (ManageCluster when none is named).

// alarmReaches reports whether node is in the alarm's reach.
func alarmReaches(s eventbus.Scope, node string) bool {
	return s.AllNodes || s.Web || slices.Contains(s.Nodes, node)
}

// Alarms travel on the SFCP Topic channel, family alm
// (devel/design/sfcp-topic-space.md 2): a server publishes its own alarms
// as alm/<server>/<name>, every server keeps a subscription to alm/# on
// every other full member, and a publisher hands each alarm only to the
// subscriptions of the servers in its reach (PublishTo).
const (
	// alarmTopicTTL is the alm family's message TTL (topic-space 2).
	alarmTopicTTL = 60 * time.Second
	// alarmAll is what every server subscribes to.
	alarmAll = sfcp.TopicFamilyAlarm + "/#"
)

// alarmTopics is this server's side of the alm family.
type alarmTopics struct {
	self   string
	topics *sfcp.Topics
	bus    *eventbus.Bus
	cache  *topiclast.Cache

	mu   sync.Mutex
	subs map[string]map[sfcp.Interest]struct{} // peer ID -> its alm subscriptions here
}

// startAlarmTopics attaches the alm family to the mesh and keeps alm/#
// subscribed on every full member. It runs before the mesh listens, after
// startObservationTopics (which owns the member list).
func (r *Runtime) startAlarmTopics(self string) error {
	t := r.Topics()
	if err := t.ReserveTopic(sfcp.TopicFamilyAlarm, sfcp.TopicACL{TTL: alarmTopicTTL}); err != nil {
		return err
	}
	a := newAlarmTopics(self, t, r.bus, r.dialAlarms)
	r.Mesh.OnPeerConnected(func(p sfcp.Peer) {
		a.cache.PeerUp(p.ID)
		// A member that joined after the last refresh is subscribed to
		// as soon as it connects, not at the next measuring round.
		if _, known := r.observationPeerKey(p.ID); !known && p.Member {
			go func() {
				ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
				defer cancel()
				r.refreshObservationPeers(ctx)
			}()
		}
	})
	r.almTopics = a
	return nil
}

func newAlarmTopics(self string, t *sfcp.Topics, bus *eventbus.Bus, dial topiclast.Dialer) *alarmTopics {
	a := &alarmTopics{self: self, topics: t, bus: bus, subs: map[string]map[sfcp.Interest]struct{}{}}
	t.OnInterest(a.noteInterest)
	// Alarms are events, not values: accept keeps nothing.
	a.cache = topiclast.NewCache(dial, topiclast.CacheOptions{Accept: a.accept})
	a.cache.Want(alarmAll, false)
	return a
}

// noteInterest tracks the alm subscriptions other servers hold here.
func (a *alarmTopics) noteInterest(i sfcp.Interest) {
	if i.Pattern != sfcp.TopicFamilyAlarm && !strings.HasPrefix(i.Pattern, sfcp.TopicFamilyAlarm+"/") {
		return
	}
	added := i.Added
	i.Added = true
	a.mu.Lock()
	defer a.mu.Unlock()
	if added {
		if a.subs[i.PeerID] == nil {
			a.subs[i.PeerID] = map[sfcp.Interest]struct{}{}
		}
		a.subs[i.PeerID][i] = struct{}{}
		return
	}
	delete(a.subs[i.PeerID], i)
	if len(a.subs[i.PeerID]) == 0 {
		delete(a.subs, i.PeerID)
	}
}

// alarmTopicName is e's topic on the channel: alm/<server>/<name>.
func alarmTopicName(server, eventTopic string) string {
	return sfcp.TopicName(sfcp.TopicFamilyAlarm, server, strings.TrimPrefix(eventTopic, eventbus.TopicAlarmPrefix))
}

// SendAlarm publishes e on this node when it is in reach and hands it to
// the alm subscription of every other server in reach. It returns the
// first delivery error; the alarm still went wherever it could. A server
// without a subscription here (down, or not yet subscribed) misses it.
func (r *Runtime) SendAlarm(_ context.Context, e eventbus.Event) error {
	if r.almTopics == nil {
		return errAlarm
	}
	return r.almTopics.send(e)
}

func (a *alarmTopics) send(e eventbus.Event) error {
	e.Node, e.Changed, e.Tenant = a.self, false, e.Scope.Tenant
	if !validNodeAlarm(e) {
		return errAlarm
	}
	if alarmReaches(e.Scope, a.self) {
		a.bus.Publish(e)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	topic := alarmTopicName(a.self, e.Topic)
	a.mu.Lock()
	var targets [][]sfcp.Interest
	for peer, subs := range a.subs {
		if peer == a.self || !alarmReaches(e.Scope, peer) {
			continue
		}
		var list []sfcp.Interest
		for i := range subs {
			list = append(list, i)
		}
		targets = append(targets, list)
	}
	a.mu.Unlock()
	var errs []error
	for _, list := range targets {
		// One delivery per server: the first of its subscriptions that
		// still matches takes it.
		for _, i := range list {
			err := a.topics.PublishTo(i, topic, raw, sfcp.PublishOptions{TTL: alarmTopicTTL})
			if errors.Is(err, sfcp.ErrTopicGone) {
				continue
			}
			if err != nil {
				errs = append(errs, err)
			}
			break
		}
	}
	return errors.Join(errs...)
}

// accept publishes an alarm another member sent, under that member's node
// name, when this node is in its reach. It keeps nothing.
func (a *alarmTopics) accept(m sfcp.Message, _ []byte, _ bool) bool {
	segs := strings.Split(m.Topic, "/")
	if m.Binary || len(segs) != 3 || segs[0] != sfcp.TopicFamilyAlarm || segs[1] != m.PublisherID {
		return false
	}
	var e eventbus.Event
	if sfcp.StrictJSON(m.Data, &e) != nil || alarmTopicName(m.PublisherID, e.Topic) != m.Topic {
		return false
	}
	e.Node, e.Changed, e.Tenant = m.PublisherID, false, e.Scope.Tenant
	if validNodeAlarm(e) && alarmReaches(e.Scope, a.self) {
		a.bus.Publish(e)
	}
	return false
}

// dialAlarms opens an alm subscription to the member called peer, over an
// existing session only (like dialObservations).
func (r *Runtime) dialAlarms(ctx context.Context, peer string, o sfcp.SubscribeOptions) (topiclast.Sub, []uint8, error) {
	key, ok := r.observationPeerKey(peer)
	if !ok {
		return nil, nil, sfcp.ErrAdmission
	}
	p, ok := r.Mesh.Peer(sfcp.Identity(key))
	if !ok {
		return nil, nil, sfcp.ErrAdmission
	}
	if !r.Mesh.Connected(sfcp.Identity(key)) {
		return nil, nil, errObservationPeerDown
	}
	call, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	s, err := r.Mesh.Dial(call, p)
	if err != nil {
		return nil, nil, err
	}
	sub, results, err := r.almTopics.topics.Subscribe(ctx, s, o)
	if err != nil {
		return nil, nil, err
	}
	return sub, results, nil
}
