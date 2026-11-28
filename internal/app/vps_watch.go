// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/vps"
)

// The leader's 10-minute cost watch (devel/design/vps-nodes.md §6). Every
// reading stays in leader memory: a new leader reads the provider again and
// only loses the recent rate, so a projection waits for an hour of its own
// readings before it may stop a server.

const (
	vpsWatchEvery = 10 * time.Minute
	// vpsSampleKeep keeps the readings recentRate needs (six hours) and the
	// hour Judgeable needs.
	vpsSampleKeep = 6*time.Hour + vpsWatchEvery
	// vpsFlavorTTL is how long a flavor's prices are reused.
	vpsFlavorTTL = 24 * time.Hour
)

type vpsFlavorRead struct {
	flavor vps.Flavor
	at     time.Time
}

type vpsWatch struct {
	// owned is the owned VPS readings (vps_owned_watch.go), its own lock.
	owned    *ownedWatch
	mu       sync.Mutex
	last     time.Time // the last round
	month    string
	samples  map[string][]vps.Sample
	servers  map[string]control.VPSServerStatus
	accounts map[string]control.VPSAccountStatus
	flavors  map[string]vpsFlavorRead // account/flavor
	// tx is each VPS server's own 1-minute counts (§6a), by server.
	tx        map[string]*vpsTXState
	guardLast time.Time
}

// vpsTXState is what the leader knows of one server's own counting.
type vpsTXState struct {
	seen      bool
	boot      string
	counter   uint64
	total     int64 // monotonic since the leader first heard from it
	points    []vps.TXPoint
	history   []vps.TXBucket
	historyAt time.Time
	// The anchor ties the count to the vendor's month: at the last
	// provider read the vendor reported anchorGB and the count was
	// anchorBytes.
	anchored    bool
	anchorGB    float64
	anchorBytes int64
}

// vpsTXKeep is how long readings are kept: the longest average plus two
// windows.
const vpsTXKeep = time.Duration(vps.MaxGuardAverageMin+2*vps.MaxGuardWindowMin) * time.Minute

func newVPSWatch() *vpsWatch {
	return &vpsWatch{samples: map[string][]vps.Sample{}, servers: map[string]control.VPSServerStatus{}, accounts: map[string]control.VPSAccountStatus{}, flavors: map[string]vpsFlavorRead{}, tx: map[string]*vpsTXState{}, owned: newOwnedWatch()}
}

// observeTX counts a server's counter reading; true asks it for its
// history (none yet, or a day old).
func (w *vpsWatch) observeTX(name, boot string, counter uint64, now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	st := w.tx[name]
	if st == nil {
		st = &vpsTXState{}
		w.tx[name] = st
	}
	var delta uint64
	switch {
	case !st.seen:
	case st.boot != boot || counter < st.counter:
		delta = counter
	default:
		delta = counter - st.counter
	}
	st.seen, st.boot, st.counter = true, boot, counter
	st.total += int64(min(delta, math.MaxInt64/4))
	st.points = append(st.points, vps.TXPoint{At: now, Bytes: st.total})
	for len(st.points) > 0 && now.Sub(st.points[0].At) > vpsTXKeep {
		st.points = st.points[1:]
	}
	return st.historyAt.IsZero() || now.Sub(st.historyAt) > 24*time.Hour
}

func (w *vpsWatch) setHistory(name string, buckets []vps.TXBucket, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	st := w.tx[name]
	if st == nil {
		st = &vpsTXState{}
		w.tx[name] = st
	}
	st.history, st.historyAt = buckets, now
}

// anchor ties a server's count to the vendor's month total.
func (w *vpsWatch) anchor(name string, usedGB float64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if st := w.tx[name]; st != nil && st.seen {
		st.anchored, st.anchorGB, st.anchorBytes = true, usedGB, st.total
	}
}

// guardDue reports whether the 1-minute guard should run at now.
func (w *vpsWatch) guardDue(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.guardLast.IsZero() && now.Sub(w.guardLast) < vpsTrafficEvery {
		return false
	}
	w.guardLast = now
	return true
}

// due reports whether a round should run at now, and marks it started.
func (w *vpsWatch) due(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.last.IsZero() && now.Sub(w.last) < vpsWatchEvery {
		return false
	}
	w.last = now
	if m := vps.MonthOf(now); m != w.month {
		// A new billing month starts every count again.
		w.month, w.samples = m, map[string][]vps.Sample{}
	}
	return true
}

// reset drops everything when this server stops leading: the next leader
// term starts from fresh readings.
func (w *vpsWatch) reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.last, w.month, w.guardLast, w.tx = time.Time{}, "", time.Time{}, map[string]*vpsTXState{}
	w.samples, w.servers, w.accounts, w.flavors = map[string][]vps.Sample{}, map[string]control.VPSServerStatus{}, map[string]control.VPSAccountStatus{}, map[string]vpsFlavorRead{}
	w.owned.reset()
}

func (w *vpsWatch) status(leader string) control.VPSStatus {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := control.VPSStatus{Leader: leader, Servers: []control.VPSServerStatus{}, Accounts: []control.VPSAccountStatus{}}
	for _, s := range w.servers {
		out.Servers = append(out.Servers, s)
	}
	for _, a := range w.accounts {
		out.Accounts = append(out.Accounts, a)
	}
	slices.SortFunc(out.Servers, func(a, b control.VPSServerStatus) int { return compareString(a.Name, b.Name) })
	slices.SortFunc(out.Accounts, func(a, b control.VPSAccountStatus) int { return compareString(a.Name, b.Name) })
	return out
}

func compareString(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// keep forgets servers that are no longer shown (running, or stopped this
// month and still billed) and the own counts of servers not running.
func (w *vpsWatch) keep(shown, running map[string]bool, accounts map[string]bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for name := range w.servers {
		if !shown[name] {
			delete(w.servers, name)
			delete(w.samples, name)
		}
	}
	for name := range w.tx {
		if !running[name] {
			delete(w.tx, name)
		}
	}
	for name := range w.accounts {
		if !accounts[name] {
			delete(w.accounts, name)
		}
	}
}

// vpsReading is one server's provider reads for a round.
type vpsReading struct {
	instance vps.Instance
	flavor   vps.Flavor
	traffic  vps.Traffic
}

// readVPSServer reads what Project needs for one running server.
func (w *vpsWatch) readVPSServer(ctx context.Context, p vps.ManagedProvider, account string, server control.VPSServer, now time.Time) (vpsReading, error) {
	inst, err := p.Instance(ctx, server.InstanceID)
	if err != nil {
		return vpsReading{}, err
	}
	key := account + "/" + server.Flavor
	w.mu.Lock()
	cached, ok := w.flavors[key]
	w.mu.Unlock()
	if !ok || now.Sub(cached.at) > vpsFlavorTTL {
		f, err := p.Flavor(ctx, server.Flavor)
		if err != nil {
			return vpsReading{}, err
		}
		cached = vpsFlavorRead{flavor: f, at: now}
		w.mu.Lock()
		w.flavors[key] = cached
		w.mu.Unlock()
	}
	k := now.In(time.FixedZone("KST", 9*3600))
	traffic, err := p.MonthTraffic(ctx, server.InstanceID, k.Year(), int(k.Month()))
	if vps.KindOf(err) == vps.KindEmpty {
		traffic, err = vps.Traffic{Year: k.Year(), Month: int(k.Month())}, nil // no traffic this month yet
	}
	if err != nil {
		return vpsReading{}, err
	}
	return vpsReading{instance: inst, flavor: cached.flavor, traffic: traffic}, nil
}

// project adds the reading to the server's samples and returns its status.
func (w *vpsWatch) project(server control.VPSServer, account control.VPSAccount, r vpsReading, now time.Time) (control.VPSServerStatus, vps.Estimate) {
	w.mu.Lock()
	samples := w.samples[server.Name]
	var recent int64
	if n := len(samples); n > 0 && r.traffic.TotalMB >= samples[n-1].MB {
		recent = r.traffic.TotalMB - samples[n-1].MB
	}
	samples = append(samples, vps.Sample{At: now, MB: r.traffic.TotalMB})
	for len(samples) > 0 && now.Sub(samples[0].At) > vpsSampleKeep {
		samples = samples[1:]
	}
	w.samples[server.Name] = samples
	recentCopy := slices.Clone(samples)
	w.mu.Unlock()
	e := vps.Project(vps.CostInput{Now: now, Started: r.instance.Started, Flavor: r.flavor, IncludedGB: r.instance.IncludedGB, IncludedPeriod: r.instance.TrafficPeriod,
		IncludedMaxGB: r.instance.IncludedMaxGB, OverageKRWPerGB: account.OverageKRWPerGB, OverageTiers: vendorTiers(account.Vendor), Traffic: r.traffic, Recent: recentCopy})
	st := control.VPSServerStatus{Name: server.Name, UpdatedAt: now.Unix(), CapKRW: server.CapKRW, SoFarKRW: e.SoFarKRW, ProjectedKRW: max(e.ProjectedKRW, e.SoFarKRW),
		BaseSoFarKRW: e.BaseSoFarKRW, BaseMonthKRW: e.BaseMonthKRW, TrafficSoFarKRW: e.TrafficSoFarKRW, TrafficMonthKRW: e.TrafficMonthKRW,
		UsedGB: e.UsedGB, ProjectedGB: e.ProjectedGB, RecentMB: recent, Judgeable: e.Judgeable, Over: e.Over(server.CapKRW),
		IncludedGB: r.instance.IncludedGB, IncludedPeriod: r.instance.TrafficPeriod,
		IncludedMonthGB: e.IncludedGB, IncludedMaxGB: r.instance.IncludedMaxGB, TodayMB: vps.TodayMB(r.traffic, now)}
	for _, d := range vps.LastDays(r.traffic, now, 7) {
		st.Daily = append(st.Daily, control.VPSTrafficDay{Day: d.Day, MB: d.MB})
	}
	return st, e
}

// setStoppedServer keeps a powered-off server's month, without a guard.
func (w *vpsWatch) setStoppedServer(st control.VPSServerStatus) {
	w.mu.Lock()
	defer w.mu.Unlock()
	st.Guard = nil
	w.servers[st.Name] = st
}

func (w *vpsWatch) setServer(st control.VPSServerStatus) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if st.Guard == nil {
		st.Guard = w.servers[st.Name].Guard // the guard's last minute stays
	}
	w.servers[st.Name] = st
}

// failServer keeps the last good numbers and adds the failure.
func (w *vpsWatch) failServer(name string, code string, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	st := w.servers[name]
	st.Name, st.Failure, st.FailureAt = name, code, now.Unix()
	w.servers[name] = st
}

func (w *vpsWatch) setAccount(a control.VPSAccountStatus) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if a.Failure != "" {
		old := w.accounts[a.Name]
		old.Name, old.Failure, old.FailureAt, old.OursKRW = a.Name, a.Failure, a.FailureAt, a.OursKRW
		a = old
	}
	w.accounts[a.Name] = a
}

// vpsWatchRound reads every running server and stops one that crosses its
// cap (when its CapAction says so). It reports at most one cap stop per
// round; the next round sees the new root revision.
func (r *Runtime) vpsWatchRound(ctx context.Context, w *vpsWatch, now time.Time) error {
	v, err := r.currentView(ctx)
	if err != nil {
		return err
	}
	catalog, err := r.controlPolicy.VPS(v.State)
	if err != nil {
		return err
	}
	members, err := r.controlPolicy.Members(v.State)
	if err != nil || !members.VoterKey(r.commandIdentity().Public) {
		return err
	}
	shown, running, accounts := map[string]bool{}, map[string]bool{}, map[string]bool{}
	ours := map[string]int64{}
	providers := map[string]vps.ManagedProvider{}
	var stop *vpsOutcome
	stopServer := ""
	for _, server := range catalog.Servers {
		if !vpsWatched(server.Phase) {
			continue
		}
		shown[server.Name] = true
		on := server.Phase == control.VPSRunning
		running[server.Name] = on
		account, ok := catalog.Account(server.Account)
		if !ok {
			continue
		}
		accounts[account.Name] = true
		p, ok := providers[account.Name]
		if !ok {
			vendor, found := vps.LookupManaged(account.Vendor)
			if !found {
				continue
			}
			cred, err := r.vpsCredential(account)
			if err != nil {
				return err
			}
			p = vendor.New(cred, r.vpsEnv)
			providers[account.Name] = p
		}
		reading, err := w.readVPSServer(ctx, p, account.Name, server, now)
		if err != nil {
			// That round is not judged (§6).
			w.failServer(server.Name, vpsFailureCode(err), now)
			continue
		}
		st, e := w.project(server, account, reading, now)
		if v, ok := vps.LookupManaged(account.Vendor); ok {
			st.TrafficCounting = v.TrafficCounting
		}
		ours[account.Name] += st.SoFarKRW
		if !on {
			// A stopped server still counts this month; only a running
			// one is judged.
			st.Over = false
			w.setStoppedServer(st)
			continue
		}
		w.anchor(server.Name, st.UsedGB)
		if st.Over && server.CapAction == control.VPSCapStopAction && stop == nil {
			if control.VPSVoterSpare(members, server.Name) {
				stop = &vpsOutcome{Action: control.VPSCapped, Cap: &control.VPSCapStop{CapKRW: server.CapKRW, SoFarKRW: e.SoFarKRW, ProjectedKRW: max(e.ProjectedKRW, e.SoFarKRW)}}
				stopServer = server.Name
			} else {
				st.CapBlocked = true
			}
		}
		w.setServer(st)
	}
	for name := range accounts {
		bill, err := providers[name].LiveBill(ctx)
		if vps.KindOf(err) == vps.KindEmpty {
			bill, err = vps.Bill{}, nil // nothing billed yet
		}
		if err != nil {
			w.setAccount(control.VPSAccountStatus{Name: name, OursKRW: ours[name], Failure: vpsFailureCode(err), FailureAt: now.Unix()})
			continue
		}
		w.setAccount(control.VPSAccountStatus{Name: name, BillKRW: bill.KRW, OursKRW: ours[name], UpdatedAt: now.Unix()})
	}
	w.keep(shown, running, accounts)
	if stop != nil {
		return r.reportVPS(ctx, v.State, stopServer, *stop)
	}
	return nil
}

// vpsFailureCode is the fixed code shown for a failed provider read.
func vpsFailureCode(err error) string {
	switch vps.KindOf(err) {
	case vps.KindAuth:
		return "PROVIDER_AUTH"
	case vps.KindNotFound:
		return "INSTANCE_NOT_FOUND"
	case vps.KindIPDenied:
		return "PROVIDER_IP_DENIED"
	case vps.KindTransport:
		return "PROVIDER_UNREACHABLE"
	}
	return "PROVIDER_ERROR"
}

// vpsWatched reports whether the watch reads a server in phase: running,
// or powered off but still billed this month (the screen shows its month).
func vpsWatched(phase string) bool {
	switch phase {
	case control.VPSRunning, control.VPSStopping, control.VPSStopped, control.VPSCapped:
		return true
	}
	return false
}

// vpsRunningAny reports whether any server is watched (the watch needs the
// provider then).
func vpsRunningAny(p control.Policy, s state.State) bool {
	catalog, err := p.VPS(s)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(catalog.Servers, func(v control.VPSServer) bool { return vpsWatched(v.Phase) })
}

func (r *Runtime) vpsWatchStatus() control.VPSStatus {
	if r.vpsWatcher == nil {
		return newVPSWatch().status(r.installation.record.Root.Self.ID)
	}
	return r.vpsWatcher.status(r.installation.record.Root.Self.ID)
}

// readVPSStatus asks the leader for its watch (directly when this is it).
func (r *Runtime) readVPSStatus(ctx context.Context) (control.VPSStatus, error) {
	reply, err := r.appCall(ctx, "vps-status", nil)
	if err != nil {
		return control.VPSStatus{}, err
	}
	var out control.VPSStatus
	if reply.Code != "ok" || json.Unmarshal(reply.Data, &out) != nil {
		return control.VPSStatus{}, errNoAppLeader
	}
	return out, nil
}

// vendorTiers is the vendor's published overage price, if any.
func vendorTiers(id string) []vps.OverageTier {
	v, _ := vps.Lookup(id)
	return v.OverageTiers
}
