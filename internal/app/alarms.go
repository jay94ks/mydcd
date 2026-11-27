// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/eventbus"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
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

// SendAlarm publishes e on this node when it is in reach and sends it to
// every other full member in reach. It returns the first delivery error;
// the alarm still went wherever it could.
func (r *Runtime) SendAlarm(ctx context.Context, e eventbus.Event) error {
	self := r.Engine().ObservedNodeID()
	e.Node, e.Changed, e.Tenant = self, false, e.Scope.Tenant
	if !validNodeAlarm(e) {
		return errAlarm
	}
	if alarmReaches(e.Scope, self) {
		r.bus.Publish(e)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return err
	}
	d, err := r.controlPolicy.Members(v.State)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	for _, entry := range d.Entries {
		key, keyErr := identity.ParseKey(entry.CurrentPeer().Key)
		if keyErr != nil || key == r.Identity.Public || !membership.FullMember(entry) || !alarmReaches(e.Scope, entry.Peer.ID) {
			continue
		}
		peer, known := r.Mesh.Peer(sfcp.Identity(key))
		if !known {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			call, stop := context.WithTimeout(ctx, 2*time.Second)
			defer stop()
			session, err := r.Mesh.Dial(call, peer)
			if err == nil {
				err = session.Report(call, sfcp.KindAlarm, raw)
			}
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// receiveAlarm publishes an alarm another member sent, under that member's
// node name, when this node is in its reach.
func (r *Runtime) receiveAlarm(s *sfcp.Session, raw []byte) error {
	var e eventbus.Event
	if sfcp.StrictJSON(raw, &e) != nil || !s.Peer().Member {
		return sfcp.ErrFrame
	}
	e.Node, e.Changed, e.Tenant = s.Peer().ID, false, e.Scope.Tenant
	if !validNodeAlarm(e) {
		return errAlarm
	}
	if alarmReaches(e.Scope, r.Engine().ObservedNodeID()) {
		r.bus.Publish(e)
	}
	return nil
}
