// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/loginlog"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// Each server keeps the logins it judged (loginlog). A user's recent logins
// are this server's records plus every other member's, read over SFCP and
// merged newest first. A member that does not answer is named in Missing.

func (r *Runtime) recordLogin(rec loginlog.Record) {
	r.mu.RLock()
	store := r.logins
	r.mu.RUnlock()
	if store == nil {
		return
	}
	if err := store.Add(rec, time.Now()); err != nil {
		log.Printf("login record not kept: %v", err)
	}
}

func (r *Runtime) loginRecords(ctx context.Context, view cluster.View, session access.Session, q loginlog.Query) (loginlog.Page, error) {
	if q.User != session.User || !q.Valid() {
		return loginlog.Page{}, loginlog.ErrInvalid
	}
	r.mu.RLock()
	store := r.logins
	r.mu.RUnlock()
	members, err := r.controlPolicy.Members(view.State)
	if err != nil {
		return loginlog.Page{}, err
	}
	raw, _ := json.Marshal(q)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	pages := []loginlog.Page{}
	add := func(p loginlog.Page) {
		mu.Lock()
		pages = append(pages, p)
		mu.Unlock()
	}
	for _, entry := range members.Entries {
		if !membership.FullMember(entry) {
			continue
		}
		node := entry.Peer.ID
		key, err := identity.ParseKey(entry.CurrentPeer().Key)
		if err != nil {
			add(loginlog.Page{Missing: []string{node}})
			continue
		}
		if key == r.Identity.Public {
			if store == nil {
				add(loginlog.Page{Missing: []string{node}})
				continue
			}
			p, err := store.Page(q, time.Now())
			if err != nil {
				p = loginlog.Page{Missing: []string{node}}
			}
			add(p)
			continue
		}
		peer, ok := r.Mesh.Peer(sfcp.Identity(key))
		if !ok || !peer.Member || peer.ID != node {
			add(loginlog.Page{Missing: []string{node}})
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			add(r.peerLoginRecords(ctx, peer, node, q, raw))
		}()
	}
	wg.Wait()
	return loginlog.Merge(pages, q.Limit), nil
}

func (r *Runtime) peerLoginRecords(ctx context.Context, peer sfcp.Peer, node string, q loginlog.Query, raw []byte) loginlog.Page {
	missing := loginlog.Page{Missing: []string{node}}
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.commandIdentity(), r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "login-records-observe", Input: raw})
	if err != nil {
		return missing
	}
	return peerLoginPage(reply.Data, node, q)
}

// peerLoginPage accepts a member's answer only as its own records of the
// asked user, within the asked size and order; anything else counts the
// member as missing.
func peerLoginPage(data []byte, node string, q loginlog.Query) loginlog.Page {
	missing := loginlog.Page{Missing: []string{node}}
	p, err := schema.Decode[loginlog.Page](data)
	if err != nil || len(p.Items) > q.Limit || len(p.Missing) != 0 {
		return missing
	}
	after, has, _ := loginlog.ParseCursor(q.After)
	for i, rec := range p.Items {
		if !rec.Valid() || rec.User != q.User || rec.Node != node || has && !loginlog.Before(loginlog.Of(rec), after) || i > 0 && !loginlog.Before(loginlog.Of(rec), loginlog.Of(p.Items[i-1])) {
			return missing
		}
	}
	if p.Items == nil {
		p.Items = []loginlog.Record{}
	}
	return p
}

// loginRecordsObserve answers a member's read of this server's own records.
// Only a current member may ask; the asking server checked the session.
func (r *Runtime) loginRecordsObserve(key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, sfcp.ErrAdmission
	}
	members, err := r.controlPolicy.Members(v.State)
	if err != nil {
		return nil, sfcp.ErrAdmission
	}
	r.mu.RLock()
	store := r.logins
	r.mu.RUnlock()
	return loginRecordsAnswer(members, store, caller, input, time.Now())
}

func loginRecordsAnswer(members membership.Directory, store *loginlog.Store, caller [32]byte, input []byte, now time.Time) (json.RawMessage, error) {
	if !members.MemberKey(caller) || store == nil {
		return nil, sfcp.ErrAdmission
	}
	q, err := schema.Decode[loginlog.Query](input)
	if err != nil || !q.Valid() {
		return nil, sfcp.ErrAdmission
	}
	p, err := store.Page(q, now)
	if err != nil {
		return nil, err
	}
	return json.Marshal(p)
}
