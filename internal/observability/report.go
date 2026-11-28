// SPDX-License-Identifier: Apache-2.0

// Package observability contains public measurements, never admission or
// execution authority. Node reports use the existing authenticated SFCP path.
package observability

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/schema"
)

const MaxAge = uint64(120_000) // report timestamps/freshness use Unix milliseconds
const MaxReportBytes = 60 << 10

var ErrReport = errors.New("invalid node observation")

type Host struct {
	RuntimeEnabled bool
	Version        string
	// Features are the names of the build's features (buildinfo feature
	// table of its major); empty for the major's baseline.
	Features    []string `json:",omitempty"`
	CPUCapacity uint64   // nanocores, physical host logical processors
	CPUUsed     *uint64  `json:",omitempty"`
	// CPUSteal is CPU time the hypervisor gave other guests while this
	// server had work (shared VPS), in nanocores. It is not in CPUUsed.
	CPUSteal                *uint64 `json:",omitempty"`
	MemoryTotal, MemoryUsed *uint64 `json:",omitempty"`
	ModuleReady             bool
	// Unready says why ModuleReady is false, in fixed codes only: the error
	// text may hold secrets and stays in the daemon log.
	Unready *Unready `json:",omitempty"`
	// TunnelWaits names managed TUN networks whose path this server cannot
	// open yet, with a fixed-format reason (never peer data or secrets).
	TunnelWaits []TunnelWait `json:",omitempty"`
	// ClusterApps are the cluster apps this server's node.yaml turns on
	// (devel/design/cluster-apps.md), with their container's state.
	ClusterApps []ClusterApp `json:",omitempty"`
	// Build says whether this server runs image builds. Absent means an
	// older daemon that did not say.
	Build *Build `json:",omitempty"`
}

// Unready is why a server is not ready. Reason is one of UnreadyReasons;
// Steps are the reconciliation steps that failed (MODULE_PASS_FAILED),
// and Since is when the failure began (Unix milliseconds; 0 when not
// tracked, as for HOST_READ_FAILED).
type Unready struct {
	Reason string
	Steps  []string `json:",omitempty"`
	Since  uint64
}

// UnreadyReasons: a reconciliation pass (or the event log it writes)
// failed, or the host could not be read.
var UnreadyReasons = []string{"MODULE_PASS_FAILED", "HOST_READ_FAILED"}

func (u Unready) valid() bool {
	if !slices.Contains(UnreadyReasons, u.Reason) || len(u.Steps) > 32 {
		return false
	}
	for _, step := range u.Steps {
		if !validStep(step) {
			return false
		}
	}
	return true
}

// validStep: a step name such as "node-storage" (lowercase, digits, '-').
func validStep(s string) bool {
	if s == "" || len(s) > 48 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// Build is one server's image build capability. Reason is empty when
// Enabled, otherwise one of BuildReasons.
type Build struct {
	Enabled bool
	Reason  string `json:",omitempty"`
}

// BuildReasons are the fixed codes for a server that does not build:
// its engine serves no build API (Seafield features.buildkit: false), or
// its workload module is off.
var BuildReasons = []string{"ENGINE_BUILD_OFF", "WORKLOAD_OFF"}

func (b Build) valid() bool {
	if b.Enabled {
		return b.Reason == ""
	}
	return slices.Contains(BuildReasons, b.Reason)
}

type TunnelWait struct {
	Tenant, Network, Reason string
}

// ClusterApp is one cluster app on this server. State is one of ClusterAppStates;
// Reason is a fixed code (ClusterAppReasons), never Docker or provider text.
// Control is the image's control policy ("node-config": only node.yaml
// brings it up or down; any short id, so a new policy does not invalidate
// the report). Address is its sfc-system address.
type ClusterApp struct {
	Name, Control, Digest, State string
	// Image is the image's repository name (sfc/web) and Version the
	// release that built it ("" when the build did not pin one).
	Image    string           `json:",omitempty"`
	Version  string           `json:",omitempty"`
	Ports    []ClusterAppPort `json:",omitempty"`
	Address  string           `json:",omitempty"`
	Reason   string           `json:",omitempty"`
	Restarts uint64           `json:",omitempty"`
	// RunningOn: the server that runs this cluster app, when it is not
	// this one (State refused: only one server in the cluster runs it).
	RunningOn string `json:",omitempty"`
}

// ClusterAppPort is one port a cluster app listens on in its container.
type ClusterAppPort struct {
	Name     string
	Port     uint16
	Protocol string
}

// ClusterAppStates are the states a cluster app reports. image-not-found and
// image-mismatch say the cluster app image package is missing or broken;
// refused says another server runs it (RunningOn).
var ClusterAppStates = []string{"starting", "running", "restarting", "stopping", "exited", "failed", "image-not-found", "image-mismatch", "refused", "unknown"}

func (a ClusterApp) valid() bool {
	ok := lifecycle.ValidID(a.Name) && lifecycle.ValidID(a.Control) && len(a.Digest) <= 80 && !strings.ContainsAny(a.Digest, "\x00\r\n ") && slices.Contains(ClusterAppStates, a.State) && len(a.Reason) <= 64 && !strings.ContainsAny(a.Reason, "\x00\r\n") && (a.RunningOn == "" || a.State == "refused" && lifecycle.ValidID(a.RunningOn))
	ok = ok && len(a.Image) <= 128 && !strings.ContainsAny(a.Image, "\x00\r\n ") && len(a.Version) <= 64 && !strings.ContainsAny(a.Version, "\x00\r\n ") && len(a.Ports) <= 8
	for _, p := range a.Ports {
		ok = ok && lifecycle.ValidID(p.Name) && p.Port != 0 && (p.Protocol == "tcp" || p.Protocol == "udp")
	}
	if a.Address != "" {
		addr, err := netip.ParseAddr(a.Address)
		ok = ok && err == nil && addr.String() == a.Address
	}
	return ok
}

type Disk struct {
	// Source selects one approved path; ID identifies the filesystem. Readers
	// filter approved sources before combining shared-filesystem measurements.
	Source, ID, Mount, Device, Filesystem    string
	RootID                                   string `json:",omitempty"`
	RootGeneration, RootRevision             uint64 `json:",omitempty"`
	Total, Used, Free, Available, InodesFree uint64
}

type Usage struct {
	Tenant               string
	Containers, Problems uint64
	CPUUsed, MemoryUsed  *uint64 `json:",omitempty"`
	Complete             bool    // every selected native was inspected; partial is not zero
}

// Task is diagnostic evidence of an exact original native. It never replaces
// the lifecycle's approved Start/Exit witness or authorizes another Start.
type Task struct {
	Tenant, App, Deployment, Key, Native string
	Generation, Revision                 uint64
	Fact                                 containerops.TaskFact
	StartedAt                            string `json:",omitempty"`
	ExitCode                             *int64 `json:",omitempty"`
}

// RegistryPull is the last actual pull outcome for one tenant/authority on a
// node. CompletedAt is the original completion time; envelope At may be a later
// replication sample. Sequence orders completions even in the same millisecond.
type RegistryPull struct {
	Tenant, Authority, Source, Stage, Code string
	CompletedAt, Sequence                  uint64
}

func (p RegistryPull) Valid(at uint64) bool {
	return lifecycle.ValidID(p.Tenant) && lifecycle.ValidID(p.Source) && p.Sequence > 0 && p.CompletedAt > 0 && p.CompletedAt <= at && registryAuthority(p.Authority) && (registryclient.PullOutcome{Stage: p.Stage, Code: p.Code}).Valid()
}
func registryAuthority(raw string) bool {
	_, authority, _, err := registryclient.Normalize(raw + "/sfc-observation:check")
	return err == nil && authority == raw
}

// VolumeUsage is the owner's last bounded scan of one converged volume
// (volumes.Usage without host facts). Binding is the volume's native
// binding digest (control.VolumeNativeDigest), so a reader matches the exact
// registered materialization. ScannedAt is the scan time; envelope At may be
// a later republish of the same sample. It never grants a read or a quota.
type VolumeUsage struct {
	Key                          string
	Binding                      [32]byte
	Entries, Files, Directories  uint64
	LogicalBytes, AllocatedBytes uint64
	ScannedAt                    uint64
}

// VolumeUsageMaxAge: a scan older than this is not shown (Unix ms).
const VolumeUsageMaxAge = uint64(30 * 60_000)

func (v VolumeUsage) valid(at uint64) bool {
	return v.Key != "" && len(v.Key) <= 512 && !strings.ContainsAny(v.Key, "\x00\r\n") && v.Binding != ([32]byte{}) && v.Entries > 0 && v.Entries <= 1_000_000 && v.Directories > 0 && v.Files <= v.Entries && v.Directories <= v.Entries-v.Files && v.AllocatedBytes%512 == 0 && v.ScannedAt > 0 && v.ScannedAt <= at
}

type Outage struct{ StartedAt, EndedAt uint64 }

type Link struct {
	Outages                       []Outage `json:",omitempty"`
	ID, Peer, State               string
	RTTMillis, LossPct            *float64 `json:",omitempty"`
	Measurement                   string
	LastHandshakeAt, LastChangeAt uint64
	Samples                       uint64
	// Dialer is the node that opened the SFCP session now carrying the
	// pair's traffic (this node or Peer); empty while the link is down.
	Dialer string `json:",omitempty"`
	// Via is the member whose transit session carries the pair's traffic;
	// empty when the link is direct (devel/design/sfcp-transit.md).
	Via string `json:",omitempty"`
}

type Consensus struct {
	LogKnown, LogBytesKnown, SnapshotKnown            bool
	Role, Leader                                      string
	Term, LastIndex, CommitIndex, AppliedIndex        uint64
	SnapshotIndex, SnapshotBytes, SnapshotAt          uint64
	LogFirstIndex, LogLastIndex, LogEntries, LogBytes uint64
	SnapshotIntervalMillis, TrailingLogs              uint64
}

type Report struct {
	Kind         string
	Schema       uint8
	Cluster      [32]byte
	Node         string
	Key          [32]byte
	Index, At    uint64
	Host         *Host         `json:",omitempty"`
	Disk         *Disk         `json:",omitempty"`
	Usage        *Usage        `json:",omitempty"`
	Link         *Link         `json:",omitempty"`
	Consensus    *Consensus    `json:",omitempty"`
	Task         *Task         `json:",omitempty"`
	RegistryPull *RegistryPull `json:",omitempty"`
	Volume       *VolumeUsage  `json:",omitempty"`
	Devices      *Devices      `json:",omitempty"`
	Signature    []byte
}

func SigningBytes(r Report) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-node-observation-1\x00"), raw...)
}

func (r Report) Valid() bool {
	if r.Kind != "node-observation" || r.Schema != 1 || r.Cluster == ([32]byte{}) || !lifecycle.ValidID(r.Node) || r.Key == ([32]byte{}) || r.At == 0 || r.Index == 0 {
		return false
	}
	count := 0
	if d := r.Devices; d != nil {
		count++
		if !d.valid() {
			return false
		}
	}
	if v := r.Volume; v != nil {
		count++
		if !v.valid(r.At) {
			return false
		}
	}
	if p := r.RegistryPull; p != nil {
		count++
		if !p.Valid(r.At) {
			return false
		}
	}
	if task := r.Task; task != nil {
		count++
		if !lifecycle.ValidID(task.Tenant) || !lifecycle.ValidID(task.App) || !lifecycle.ValidID(task.Deployment) || !strings.HasPrefix(task.Key, "workload/task/"+task.Tenant+"/"+task.App+"/") || len(task.Key) > 512 || strings.ContainsAny(task.Key+task.Native+task.StartedAt, "\x00\r\n") || task.Generation == 0 || task.Revision < task.Generation || task.Native == "" || len(task.Native) > 256 || len(task.StartedAt) > 64 || !task.Fact.Valid(r.At/1000) || task.ExitCode != nil && task.Fact.State != "exited" {
			return false
		}
	}
	if h := r.Host; h != nil {
		count++
		if !validFeatureNames(h.Features) {
			return false
		}
		if len(h.ClusterApps) > 16 {
			return false
		}
		for i, a := range h.ClusterApps {
			if !a.valid() || i > 0 && a.Name <= h.ClusterApps[i-1].Name {
				return false
			}
		}
		if len(h.TunnelWaits) > 32 || h.Build != nil && !h.Build.valid() || h.Unready != nil && (h.ModuleReady || !h.Unready.valid()) {
			return false
		}
		for _, w := range h.TunnelWaits {
			if !lifecycle.ValidID(w.Tenant) || !lifecycle.ValidID(w.Network) || w.Reason == "" || len(w.Reason) > 256 || strings.ContainsAny(w.Reason, "\x00\r\n") {
				return false
			}
		}
		if h.Version == "" || len(h.Version) > 64 || strings.ContainsAny(h.Version, "\x00\r\n") || h.CPUUsed != nil && *h.CPUUsed > h.CPUCapacity || h.CPUSteal != nil && (*h.CPUSteal > h.CPUCapacity || h.CPUUsed != nil && *h.CPUUsed > h.CPUCapacity-*h.CPUSteal) || (h.MemoryTotal == nil) != (h.MemoryUsed == nil) || h.MemoryTotal != nil && (*h.MemoryTotal == 0 || *h.MemoryUsed > *h.MemoryTotal) {
			return false
		}
	}
	if d := r.Disk; d != nil {
		count++
		if strings.HasPrefix(d.Source, "root/") != (d.RootID != "") {
			return false
		}
		if d.Source != "system" && d.Source != "container-runtime" && d.Source != "root/"+d.RootID || d.RootID != "" && (!lifecycle.ValidID(d.RootID) || d.RootGeneration == 0 || d.RootRevision < d.RootGeneration) || d.RootID == "" && (d.RootGeneration != 0 || d.RootRevision != 0) || len(d.ID) != 64 || d.Mount == "" || len(d.Mount) > 4096 || len(d.Device) > 4096 || len(d.Filesystem) > 64 || d.Total == 0 || d.Free > d.Total || d.Used != d.Total-d.Free || d.Available > d.Free || strings.ContainsAny(d.ID+d.Mount+d.Device+d.Filesystem, "\x00\r\n") {
			return false
		}
		if raw, err := hex.DecodeString(d.ID); err != nil || hex.EncodeToString(raw) != d.ID {
			return false
		}
	}
	if u := r.Usage; u != nil {
		count++
		if !lifecycle.ValidID(u.Tenant) || u.Problems > u.Containers || !u.Complete && (u.CPUUsed != nil || u.MemoryUsed != nil) {
			return false
		}
	}
	if l := r.Link; l != nil {
		count++
		if !lifecycle.ValidID(l.Peer) || l.Peer == r.Node || l.ID != PairID(r.Node, l.Peer) || l.State != "up" && l.State != "degraded" && l.State != "down" || l.LastHandshakeAt > r.At || l.LastChangeAt > r.At || l.LastChangeAt == 0 || l.Measurement == "" || len(l.Measurement) > 64 || l.Dialer != "" && l.Dialer != r.Node && l.Dialer != l.Peer || l.Via != "" && (!lifecycle.ValidID(l.Via) || l.Via == r.Node || l.Via == l.Peer || l.Dialer == "") {
			return false
		}
		for _, n := range []*float64{l.RTTMillis, l.LossPct} {
			if n != nil && (math.IsInf(*n, 0) || math.IsNaN(*n) || *n < 0) {
				return false
			}
		}
		if len(l.Outages) > 8 {
			return false
		}
		for _, o := range l.Outages {
			if o.StartedAt == 0 || o.StartedAt > r.At || o.EndedAt != 0 && (o.EndedAt < o.StartedAt || o.EndedAt > r.At) {
				return false
			}
		}
		if l.LossPct != nil && *l.LossPct > 100 {
			return false
		}
	}
	if c := r.Consensus; c != nil {
		count++
		if c.Role != "leader" && c.Role != "follower" && c.Role != "candidate" && c.Role != "non-voter" || c.Leader != "" && !lifecycle.ValidID(c.Leader) || c.CommitIndex > c.LastIndex || c.AppliedIndex > c.CommitIndex || c.SnapshotAt > r.At || c.LogFirstIndex > c.LogLastIndex && c.LogLastIndex != 0 {
			return false
		}
	}
	raw, err := json.Marshal(r)
	return count == 1 && err == nil && len(raw) <= MaxReportBytes && ed25519.Verify(ed25519.PublicKey(r.Key[:]), SigningBytes(r), r.Signature)
}

func Decode(raw []byte) (Report, error) {
	if len(raw) > MaxReportBytes {
		return Report{}, ErrReport
	}
	r, err := schema.Decode[Report](raw)
	if err != nil || !r.Valid() {
		return Report{}, ErrReport
	}
	return r, nil
}

func (r Report) Source() string {
	switch {
	case r.RegistryPull != nil:
		digest := sha256.Sum256([]byte(r.RegistryPull.Authority))
		return "registry-pull/" + r.RegistryPull.Tenant + "/" + hex.EncodeToString(digest[:])
	case r.Task != nil:
		return "task/" + r.Task.Key
	case r.Volume != nil:
		return "volume/" + r.Volume.Key
	case r.Host != nil:
		return "host"
	case r.Devices != nil:
		return "devices"
	case r.Disk != nil:
		return "disk/" + r.Disk.Source
	case r.Usage != nil:
		return "usage/" + r.Usage.Tenant
	case r.Link != nil:
		return "link/" + r.Link.Peer
	case r.Consensus != nil:
		return "consensus"
	}
	return ""
}

func PairID(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "/" + b
}

func FilesystemID(node, filesystem string) string {
	digest := sha256.Sum256([]byte("sfc-filesystem-1\x00" + node + "\x00" + filesystem))
	return hex.EncodeToString(digest[:])
}

func Fresh(at, now uint64) bool { return at != 0 && at <= now && now-at <= MaxAge }

// validFeatureNames: at most 64 distinct lowercase written names
// (group-set-vN[-postfix], buildinfo), each 1-64 bytes of a-z, 0-9 and '-'.
// Names a newer build defines are accepted as long as they are well formed;
// order is the reporter's, not checked.
func validFeatureNames(names []string) bool {
	if len(names) > 64 {
		return false
	}
	seen := map[string]bool{}
	for _, n := range names {
		if n == "" || len(n) > 64 || seen[n] {
			return false
		}
		for _, c := range n {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
		seen[n] = true
	}
	return true
}
