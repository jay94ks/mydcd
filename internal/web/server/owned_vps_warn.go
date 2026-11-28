// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"strconv"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// Owned VPS subscription notices (devel/design/vps-hostinger.md §3): 14, 3
// and 1 days before the subscription ends, the operator who attached the
// server is told the end date. Renewal stays in the vendor's panel; a
// renewal moves the end date and the notices start over.

const ownedWarnEvery = time.Hour

var ownedWarnDays = []int{1, 3, 14}

// ownedWarnPoll runs one round as ws (the watcher's automation session).
func (s *Server) ownedWarnPoll(ctx context.Context, ws *webSession) {
	now := s.now()
	s.vpsDNS.mu.Lock()
	due := now.Sub(s.vpsDNS.warned) >= ownedWarnEvery
	if due {
		s.vpsDNS.warned = now
	}
	s.vpsDNS.mu.Unlock()
	if !due {
		return
	}
	var owned userauth.OwnedVPSReply
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		owned, err = c.QueryOwnedVPS(ctx, true)
		return err
	})
	if err != nil || owned.Status == nil {
		return // no leader status now; the next round tries again
	}
	s.ownedWarn(now, owned.Page.Servers, owned.Status.Servers)
}

func (s *Server) ownedWarn(now time.Time, servers []control.OwnedVPS, status []control.OwnedVPSServerStatus) {
	attached := map[string]control.OwnedVPS{}
	for _, v := range servers {
		attached[v.Name] = v
	}
	if warns, err := s.opt.Store.ListOwnedVPSWarns(); err == nil {
		for _, w := range warns {
			if _, ok := attached[w.Server]; !ok {
				_ = s.opt.Store.DeleteOwnedVPSWarn(w.Server)
			}
		}
	}
	for _, st := range status {
		v, ok := attached[st.Name]
		if !ok || st.ExpiresAt == 0 {
			continue
		}
		left := time.Unix(st.ExpiresAt, 0).Sub(now)
		days := ownedWarnDue(left)
		if days == 0 {
			continue
		}
		w, err := s.opt.Store.GetOwnedVPSWarn(st.Name)
		if err == nil && w.ExpiresAt == st.ExpiresAt && w.Days <= days {
			continue // already told at this threshold or a nearer one
		}
		if err = s.opt.Store.PutOwnedVPSWarn(&store.OwnedVPSWarn{Server: st.Name, ExpiresAt: st.ExpiresAt, Days: days}); err != nil {
			s.log.Error("owned vps: notice state", "err", err)
			continue
		}
		s.notify(ownedWarnNotice(v, st, days))
	}
}

// ownedWarnDue is the nearest threshold left is within (0 = none yet, or
// already over).
func ownedWarnDue(left time.Duration) int {
	if left <= 0 {
		return 0
	}
	for _, d := range ownedWarnDays {
		if left <= time.Duration(d)*24*time.Hour {
			return d
		}
	}
	return 0
}

func ownedWarnNotice(v control.OwnedVPS, st control.OwnedVPSServerStatus, days int) *store.Notification {
	end := time.Unix(st.ExpiresAt, 0).UTC().Format("2006-01-02")
	body := append([]string{"owned-subscription.body"}, bodyIf(st.AutoRenew, "owned-subscription.auto")...)
	severity := "warning"
	if v.Voter {
		severity = "error"
		body = append(body, "owned-subscription.voter")
	}
	return &store.Notification{User: v.AttachedBy, Kind: NotifyVPSSubscription, Severity: severity, Action: true,
		Text: notice("owned-subscription", map[string]string{"vps": v.Name, "days": strconv.Itoa(days), "end": end}, body...), Link: "/nodes/owned-vps"}
}
