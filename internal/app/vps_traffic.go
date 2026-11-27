// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/vps"
)

// The early traffic guard (devel/design/vps-nodes.md §6a). Every VPS server
// counts its own outgoing bytes each minute and tells the leader over SFCP
// (never Raft); it also keeps a month of 5-minute buckets for the pattern
// forecast and hands them to the leader when asked. The leader forecasts
// the next 21 minutes each minute and stops a server whose traffic would
// cross its cap within them.

const vpsTrafficEvery = time.Minute

// vpsTrafficReport is the "vps-traffic" input: the interface counter since
// boot. The leader turns counters into a monotonic count.
type vpsTrafficReport struct {
	Boot    string
	Counter uint64
}

// vpsTrafficReply asks for the history when the leader has none (new
// leader) or a day old one.
type vpsTrafficReply struct {
	History bool `json:",omitempty"`
}

// vpsTrafficHistory is the "vps-traffic-history" input: buckets from Start,
// one per vps.GuardBucket, -1 where nothing was counted.
type vpsTrafficHistory struct {
	Start int64
	Bytes []int64
}

// vpsTXRecorder is the node's own month of buckets, kept in a file under
// the state directory.
type vpsTXRecorder struct {
	mu      sync.Mutex
	path    string
	loaded  bool
	Boot    string
	Counter uint64
	Buckets map[int64]int64 // bucket start (unix) → bytes
}

func newVPSTXRecorder(stateDir string) *vpsTXRecorder {
	return &vpsTXRecorder{path: filepath.Join(stateDir, "vps-traffic.json"), Buckets: map[int64]int64{}}
}

func (t *vpsTXRecorder) load() {
	if t.loaded {
		return
	}
	t.loaded = true
	raw, err := os.ReadFile(t.path)
	if err != nil {
		return
	}
	var saved vpsTXRecorder
	if json.Unmarshal(raw, &saved) == nil && saved.Buckets != nil {
		t.Boot, t.Counter, t.Buckets = saved.Boot, saved.Counter, saved.Buckets
	}
}

// add counts a counter reading at now into the buckets and drops buckets
// older than a month. It returns whether a new bucket started (save then).
func (t *vpsTXRecorder) add(boot string, counter uint64, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.load()
	var delta uint64
	switch {
	case t.Boot == "":
	case t.Boot != boot || counter < t.Counter:
		delta = counter // rebooted or reset: everything since then is new
	default:
		delta = counter - t.Counter
	}
	t.Boot, t.Counter = boot, counter
	start := now.Truncate(vps.GuardBucket).Unix()
	_, existed := t.Buckets[start]
	t.Buckets[start] += int64(min(delta, math.MaxInt64/2))
	cut := now.AddDate(0, 0, -vps.GuardHistoryDays-1).Unix()
	for k := range t.Buckets {
		if k < cut {
			delete(t.Buckets, k)
		}
	}
	return !existed
}

func (t *vpsTXRecorder) save() error {
	t.mu.Lock()
	raw, err := json.Marshal(t)
	t.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := t.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, t.path)
}

// history packs the buckets for the leader.
func (t *vpsTXRecorder) history() vpsTrafficHistory {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.Buckets) == 0 {
		return vpsTrafficHistory{}
	}
	keys := make([]int64, 0, len(t.Buckets))
	for k := range t.Buckets {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	step := int64(vps.GuardBucket.Seconds())
	out := vpsTrafficHistory{Start: keys[0]}
	for k := keys[0]; k <= keys[len(keys)-1]; k += step {
		n, ok := t.Buckets[k]
		if !ok {
			n = -1
		}
		out.Bytes = append(out.Bytes, n)
	}
	return out
}

// vpsTrafficLoop runs on every server; only a running VPS server reports.
func (r *Runtime) vpsTrafficLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(vpsTrafficEvery)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
		}
		ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
		if err := r.vpsTrafficStep(ctx, time.Now()); err != nil && !errors.Is(err, errNotVPSServer) {
			log.Printf("vps: traffic: %s", vpsLogCause(err))
		}
		cancel()
	}
}

var errNotVPSServer = errors.New("not a running VPS server")

func (r *Runtime) vpsTrafficStep(ctx context.Context, now time.Time) error {
	if r.vpsTX == nil {
		return errNotVPSServer
	}
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return err
	}
	catalog, err := r.controlPolicy.VPS(v.State)
	if err != nil {
		return err
	}
	self := r.installation.record.Root.Self.ID
	i := slices.IndexFunc(catalog.Servers, func(s control.VPSServer) bool { return s.Name == self && s.Phase == control.VPSRunning })
	if i < 0 {
		return errNotVPSServer
	}
	rx := false
	if a, ok := catalog.Account(catalog.Servers[i].Account); ok {
		if vendor, ok := vps.Lookup(a.Vendor); ok {
			rx = vendor.TrafficCounting == vps.CountRXTX
		}
	}
	counter, err := readInterfaceCounter(rx)
	if err != nil {
		return err
	}
	boot := readBootID()
	if r.vpsTX.add(boot, counter, now) {
		if err := r.vpsTX.save(); err != nil {
			log.Printf("vps: traffic history: %v", err)
		}
	}
	raw, _ := json.Marshal(vpsTrafficReport{Boot: boot, Counter: counter})
	reply, err := r.appCall(ctx, "vps-traffic", raw)
	if err != nil {
		return err
	}
	var want vpsTrafficReply
	if reply.Code != "ok" || json.Unmarshal(reply.Data, &want) != nil || !want.History {
		return nil
	}
	raw, _ = json.Marshal(r.vpsTX.history())
	_, err = r.appCall(ctx, "vps-traffic-history", raw)
	return err
}

// readInterfaceCounter reads the bytes sent (and received, when the vendor
// counts both) on the default route's interface.
func readInterfaceCounter(rx bool) (uint64, error) {
	dev, err := defaultRouteInterface()
	if err != nil {
		return 0, err
	}
	read := func(name string) (uint64, error) {
		raw, err := os.ReadFile(filepath.Join("/sys/class/net", dev, "statistics", name))
		if err != nil {
			return 0, err
		}
		return strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	}
	n, err := read("tx_bytes")
	if err != nil || !rx {
		return n, err
	}
	m, err := read("rx_bytes")
	return n + m, err
}

func defaultRouteInterface() (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) > 2 && fields[1] == "00000000" && !strings.ContainsAny(fields[0], "/.") {
			return fields[0], nil
		}
	}
	return "", errors.New("no default route")
}

func readBootID() string {
	raw, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(raw))
}

// vpsTrafficCaller is the running VPS server a node key belongs to.
func (r *Runtime) vpsTrafficCaller(key string, v cluster.View) (string, error) {
	if !r.Engine().IsLeader() {
		return "", sfcp.ErrAdmission
	}
	k, err := identity.ParseKey(key)
	if err != nil {
		return "", sfcp.ErrAdmission
	}
	members, err := r.controlPolicy.Members(v.State)
	if err != nil {
		return "", err
	}
	name := ""
	for _, e := range members.Entries {
		if e.CurrentPeer().Key == hex.EncodeToString(k[:]) {
			name = e.Peer.ID
		}
	}
	catalog, err := r.controlPolicy.VPS(v.State)
	if err != nil {
		return "", err
	}
	if name == "" || !slices.ContainsFunc(catalog.Servers, func(s control.VPSServer) bool { return s.Name == name && s.Phase == control.VPSRunning }) {
		return "", sfcp.ErrAdmission
	}
	return name, nil
}

func (r *Runtime) nodeReadVpsTraffic(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	name, err := r.vpsTrafficCaller(key, v)
	if err != nil {
		return nil, err
	}
	var q vpsTrafficReport
	if json.Unmarshal(input, &q) != nil || len(q.Boot) > 64 {
		return nil, sfcp.ErrAdmission
	}
	return json.Marshal(vpsTrafficReply{History: r.vpsWatcher.observeTX(name, q.Boot, q.Counter, time.Now())})
}

func (r *Runtime) nodeReadVpsTrafficHistory(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	name, err := r.vpsTrafficCaller(key, v)
	if err != nil {
		return nil, err
	}
	var q vpsTrafficHistory
	limit := vps.GuardHistoryDays * 24 * 12 * 2
	if json.Unmarshal(input, &q) != nil || len(q.Bytes) > limit {
		return nil, sfcp.ErrAdmission
	}
	var buckets []vps.TXBucket
	for i, n := range q.Bytes {
		if n >= 0 {
			buckets = append(buckets, vps.TXBucket{Start: time.Unix(q.Start+int64(i)*int64(vps.GuardBucket.Seconds()), 0), Bytes: n})
		}
	}
	r.vpsWatcher.setHistory(name, buckets, time.Now())
	return json.Marshal(struct{}{})
}

func init() {
	defineNodeRead((*Runtime).nodeReadVpsTraffic, false, "vps-traffic")
	defineNodeRead((*Runtime).nodeReadVpsTrafficHistory, false, "vps-traffic-history")
}

// vpsGuardRound judges every running server from its own counts and stops
// at most one whose traffic is expected to cross its cap within the
// horizon (when its CapAction says so).
func (r *Runtime) vpsGuardRound(ctx context.Context, w *vpsWatch, now time.Time) error {
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
	for _, server := range catalog.Servers {
		if server.Phase != control.VPSRunning {
			continue
		}
		account, ok := catalog.Account(server.Account)
		if !ok {
			continue
		}
		st, g, ok := w.judgeGuard(server, account, now)
		if !ok {
			continue
		}
		if g.Soon && server.CapAction == control.VPSCapStopAction {
			if !control.VPSVoterSpare(members, server.Name) {
				w.setGuard(server.Name, g, true)
				continue
			}
			w.setGuard(server.Name, g, false)
			stop := vpsOutcome{Action: control.VPSCapped, Cap: &control.VPSCapStop{CapKRW: server.CapKRW, SoFarKRW: st.SoFarKRW,
				ProjectedKRW: max(st.ProjectedKRW, st.SoFarKRW, server.CapKRW+1), Reason: control.VPSCapTrafficSoon}}
			return r.reportVPS(ctx, v.State, server.Name, stop)
		}
		w.setGuard(server.Name, g, false)
	}
	return nil
}

// judgeGuard forecasts one server; false until the 10-minute watch read
// its month and the server reported a window of counts.
func (w *vpsWatch) judgeGuard(server control.VPSServer, account control.VPSAccount, now time.Time) (control.VPSServerStatus, control.VPSGuardStatus, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	st, ok := w.servers[server.Name]
	tx := w.tx[server.Name]
	if !ok || tx == nil || !tx.anchored || len(tx.points) == 0 {
		return st, control.VPSGuardStatus{}, false
	}
	f := account.Guard.Settings().Forecast(tx.points, tx.history, now)
	if !f.Ready {
		return st, control.VPSGuardStatus{}, false
	}
	mbps := func(bps float64) float64 { return bps * 8 / 1e6 }
	g := control.VPSGuardStatus{At: now.Unix(), RateMbps: mbps(f.RateBps), PrevMbps: mbps(f.PrevBps), AverageMbps: mbps(f.AverageBps),
		ForecastGB: vps.GB(f.Bytes), PatternGB: vps.GB(f.PatternBytes), PatternDays: f.PatternDays, PatternUsed: f.PatternUsed}
	g.MonthGB = max(st.UsedGB, tx.anchorGB+vps.GB(float64(tx.total-tx.anchorBytes)))
	tiers := vendorTiers(account.Vendor)
	if len(tiers) == 0 && account.OverageKRWPerGB > 0 {
		tiers = []vps.OverageTier{{KRWPerGB: account.OverageKRWPerGB}}
	}
	allowed := vps.AllowedGB(server.CapKRW, st.BaseMonthKRW, st.IncludedMonthGB, tiers)
	if server.CapKRW <= 0 || math.IsInf(allowed, 1) {
		g.Unlimited = true
		return st, g, true
	}
	g.RemainingGB = max(0, allowed-g.MonthGB)
	g.Soon = g.ForecastGB >= g.RemainingGB
	if pace := g.ForecastGB / vps.GuardHorizon.Seconds(); pace > 0 {
		g.SoonAt = now.Add(time.Duration(g.RemainingGB / pace * float64(time.Second))).Unix()
	}
	return st, g, true
}

func (w *vpsWatch) setGuard(name string, g control.VPSGuardStatus, blocked bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	st, ok := w.servers[name]
	if !ok {
		return
	}
	st.Guard = &g
	if g.Soon {
		st.Over = true
		st.CapBlocked = st.CapBlocked || blocked
	}
	w.servers[name] = st
}
