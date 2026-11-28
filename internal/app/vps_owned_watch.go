// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"log"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/vps"
)

// The leader's watch of running owned VPS servers (devel/design/
// vps-hostinger.md §4, §5). Readings stay in leader memory; only the hold,
// its end and an expiry are committed (owned-vps-report).

const (
	ownedWatchEvery   = 15 * time.Minute
	ownedSubscription = 24 * time.Hour
	// ownedHoldLead is how long before the allowance runs out the hold
	// begins, so DNS caches drain first; ownedHoldShare is the share of
	// the allowance after which it begins anyway.
	ownedHoldLead  = 6 * time.Hour
	ownedHoldShare = 0.95
)

type ownedReading struct {
	at              time.Time
	month           string
	usedMB, monthMB int64
}

type ownedWatch struct {
	mu       sync.Mutex
	last     time.Time
	prev     map[string]ownedReading
	rows     map[string]control.OwnedVPSServerStatus
	subAt    map[string]time.Time
	notFound map[string]int
}

func newOwnedWatch() *ownedWatch {
	w := &ownedWatch{}
	w.reset()
	return w
}

func (w *ownedWatch) reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.last, w.prev, w.rows, w.subAt, w.notFound = time.Time{}, map[string]ownedReading{}, map[string]control.OwnedVPSServerStatus{}, map[string]time.Time{}, map[string]int{}
}

func (w *ownedWatch) due(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.last.IsZero() && now.Sub(w.last) < ownedWatchEvery {
		return false
	}
	w.last = now
	return true
}

func (w *ownedWatch) status(leader string) control.OwnedVPSStatus {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := control.OwnedVPSStatus{Leader: leader, Servers: []control.OwnedVPSServerStatus{}}
	for _, st := range w.rows {
		out.Servers = append(out.Servers, st)
	}
	slices.SortFunc(out.Servers, func(a, b control.OwnedVPSServerStatus) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// ownedRunningAny reports whether any owned VPS runs.
func ownedRunningAny(p control.Policy, s state.State) bool {
	c, err := p.OwnedVPS(s)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(c.Servers, func(v control.OwnedVPS) bool { return v.Phase == control.OwnedRunning })
}

// ownedJudge decides one running server from this and the previous
// reading: "" (nothing), limiting (with the hold) or restored.
func ownedJudge(v control.OwnedVPS, now ownedReading, prev *ownedReading) (string, *control.OwnedLimit, int64) {
	reach := int64(0)
	if prev != nil && prev.month == now.month && now.at.After(prev.at) && now.usedMB > prev.usedMB && now.monthMB > now.usedMB {
		perSec := float64(now.usedMB-prev.usedMB) / now.at.Sub(prev.at).Seconds()
		reach = now.at.Unix() + int64(float64(now.monthMB-now.usedMB)/perSec)
	}
	if now.monthMB <= 0 {
		return "", nil, reach // the vendor reports no allowance
	}
	near := float64(now.usedMB) >= ownedHoldShare*float64(now.monthMB)
	if v.Limit != nil {
		// The vendor's month reset: the hold's month is over and use is
		// low again.
		if now.month > v.Limit.Month && !near {
			return control.OwnedRestoredReport, nil, reach
		}
		return "", nil, reach
	}
	if v.Restored != nil && v.Restored.By != "" && v.Restored.Month == now.month {
		return "", nil, reach // an operator ended this month's hold
	}
	soon := reach != 0 && reach-now.at.Unix() <= int64(ownedHoldLead/time.Second)
	if !near && !soon {
		return "", nil, reach
	}
	held := reach
	if now.usedMB >= now.monthMB {
		held = 0
	}
	return control.OwnedLimiting, &control.OwnedLimit{At: now.at.Unix(), Month: now.month, Mode: v.Protect, UsedMB: now.usedMB, MonthMB: now.monthMB, ReachAt: held}, reach
}

// ownedWatchRound reads every running owned VPS and commits what changed.
func (r *Runtime) ownedWatchRound(ctx context.Context, w *ownedWatch, now time.Time) error {
	v, err := r.currentView(ctx)
	if err != nil {
		return err
	}
	owned, err := r.controlPolicy.OwnedVPS(v.State)
	if err != nil {
		return err
	}
	accounts, err := r.controlPolicy.VPS(v.State)
	if err != nil {
		return err
	}
	members, err := r.controlPolicy.Members(v.State)
	if err != nil || !members.VoterKey(r.commandIdentity().Public) {
		return err
	}
	running := map[string]bool{}
	for _, server := range owned.Servers {
		if server.Phase != control.OwnedRunning {
			continue
		}
		running[server.Name] = true
		account, ok := accounts.Account(server.Account)
		if !ok {
			continue
		}
		report, err := r.ownedRead(ctx, w, account, server, now)
		if err != nil {
			log.Printf("owned-vps: read of %s failed: %s", server.Name, vpsLogCause(err))
			continue
		}
		if report.Action == "" {
			continue
		}
		after, err := r.currentView(ctx)
		if err != nil {
			return err
		}
		if err := r.reportOwnedVPS(ctx, after.State, report); err != nil {
			return err
		}
	}
	w.mu.Lock()
	for name := range w.rows {
		if !running[name] {
			delete(w.rows, name)
			delete(w.prev, name)
		}
	}
	w.mu.Unlock()
	return nil
}

// ownedRead reads one server and returns the report to commit (Action "" =
// none). The status row keeps what was read, or the failure.
func (r *Runtime) ownedRead(ctx context.Context, w *ownedWatch, account control.VPSAccount, server control.OwnedVPS, now time.Time) (control.OwnedVPSReport, error) {
	none := control.OwnedVPSReport{Server: server.Name}
	fail := func(err error) (control.OwnedVPSReport, error) {
		w.mu.Lock()
		st := w.rows[server.Name]
		st.Name, st.Failure, st.FailureAt = server.Name, vpsFailureCode(err), now.Unix()
		w.rows[server.Name] = st
		w.mu.Unlock()
		return none, err
	}
	p, err := r.ownedProvider(account)
	if err != nil {
		return fail(err)
	}
	inst, err := p.Instance(ctx, server.InstanceID)
	if vps.KindOf(err) == vps.KindNotFound {
		// Twice in a row: the subscription ended and the VM is gone.
		w.mu.Lock()
		w.notFound[server.Name]++
		gone := w.notFound[server.Name] >= 2
		w.mu.Unlock()
		if gone {
			return control.OwnedVPSReport{Server: server.Name, Action: control.OwnedExpired}, nil
		}
		return fail(err)
	}
	if err != nil {
		return fail(err)
	}
	month := control.OwnedMonthOf(now)
	t := now.UTC()
	traffic, err := p.MonthTraffic(ctx, server.InstanceID, t.Year(), int(t.Month()))
	if err != nil && vps.KindOf(err) != vps.KindEmpty {
		return fail(err)
	}
	reading := ownedReading{at: now, month: month, usedMB: traffic.TotalMB, monthMB: inst.IncludedGB * 1024}

	w.mu.Lock()
	delete(w.notFound, server.Name)
	prev, hadPrev := w.prev[server.Name]
	w.prev[server.Name] = reading
	st := w.rows[server.Name]
	subDue := now.Sub(w.subAt[server.Name]) >= ownedSubscription
	if subDue {
		w.subAt[server.Name] = now
	}
	w.mu.Unlock()

	if subDue {
		if sub, err := p.Subscription(ctx, server.InstanceID); err == nil {
			st.SubscriptionStatus, st.AutoRenew, st.Currency, st.RenewalCost = sub.Status, sub.AutoRenew, sub.Currency, sub.RenewalCost
			st.ExpiresAt = 0
			if !sub.ExpiresAt.IsZero() {
				st.ExpiresAt = sub.ExpiresAt.Unix()
			}
		} else if vps.KindOf(err) != vps.KindEmpty {
			log.Printf("owned-vps: subscription of %s failed: %s", server.Name, vpsLogCause(err))
		}
	}
	var prevPtr *ownedReading
	if hadPrev {
		prevPtr = &prev
	}
	action, limit, reach := ownedJudge(server, reading, prevPtr)
	st.Name, st.UpdatedAt, st.UsedMB, st.MonthMB, st.ReachAt, st.Failure, st.FailureAt = server.Name, now.Unix(), reading.usedMB, reading.monthMB, reach, "", 0
	st.Plan, st.Zone, st.Image, st.InstanceStatus = inst.Flavor, inst.Zone, inst.Image, string(inst.Status)
	w.mu.Lock()
	w.rows[server.Name] = st
	w.mu.Unlock()
	return control.OwnedVPSReport{Server: server.Name, Action: action, Limit: limit}, nil
}

// readOwnedVPSStatus asks the leader for its owned VPS readings.
func (r *Runtime) readOwnedVPSStatus(ctx context.Context) (control.OwnedVPSStatus, error) {
	reply, err := r.appCall(ctx, "owned-vps-status", nil)
	if err != nil {
		return control.OwnedVPSStatus{}, err
	}
	var out control.OwnedVPSStatus
	if reply.Code != "ok" || json.Unmarshal(reply.Data, &out) != nil {
		return control.OwnedVPSStatus{}, errNoAppLeader
	}
	return out, nil
}
