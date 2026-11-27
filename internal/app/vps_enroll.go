// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/ingress"
)

// VPS enrollment over the cluster's own ingress (devel/design/vps-nodes.md
// §4, docs/reference/vps-enroll.md). Every request is judged by the TLS
// connection's source address alone: it must be the public IPv4 of a VPS
// server in the installing phase. Nothing here is secret: the binary is the
// published sfcd and the invitation is useless without the key's private
// half, which never leaves the VPS.

const (
	vpsEnrollBinary = ingress.NodeEnrollPath + "sfcd"
	vpsEnrollPost   = ingress.NodeEnrollPath + "enroll"
)

var selfBuild = sync.OnceValues(func() (control.VPSBuild, error) {
	path, err := os.Executable()
	if err != nil {
		return control.VPSBuild{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return control.VPSBuild{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return control.VPSBuild{}, err
	}
	b := control.VPSBuild{OS: runtime.GOOS, Arch: runtime.GOARCH}
	copy(b.SHA256[:], h.Sum(nil))
	return b, nil
})

func (r *Runtime) serveNodeEnroll(w http.ResponseWriter, req *http.Request, source netip.Addr) {
	ctx, cancel := context.WithTimeout(req.Context(), 30*time.Second)
	defer cancel()
	switch {
	case req.URL.Path == vpsEnrollBinary && (req.Method == http.MethodGet || req.Method == http.MethodHead):
		r.serveVPSBinary(ctx, w, req, source)
	case req.URL.Path == vpsEnrollPost && req.Method == http.MethodPost:
		r.serveVPSEnroll(ctx, w, req, source)
	default:
		http.NotFound(w, req)
	}
}

// enrollingVPS finds the installing server name that source may act for.
func (r *Runtime) enrollingVPS(ctx context.Context, name string, source netip.Addr) (cluster.View, control.VPSServer, bool) {
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return cluster.View{}, control.VPSServer{}, false
	}
	catalog, err := r.controlPolicy.VPS(v.State)
	if err != nil {
		return cluster.View{}, control.VPSServer{}, false
	}
	server, ok := catalog.Server(name)
	if !ok || server.Phase != control.VPSInstalling || !source.Is4() || server.PublicIP != source.String() {
		return cluster.View{}, control.VPSServer{}, false
	}
	return v, server, true
}

func (r *Runtime) serveVPSBinary(ctx context.Context, w http.ResponseWriter, req *http.Request, source netip.Addr) {
	_, server, ok := r.enrollingVPS(ctx, req.URL.Query().Get("name"), source)
	if !ok || server.Build == nil {
		http.NotFound(w, req)
		return
	}
	own, err := selfBuild()
	if err != nil || own != *server.Build {
		// Only the leader's exact build is installed; this server runs
		// another one, so the VPS tries again (another ingress or later).
		http.Error(w, "this server does not run the leader's sfcd", http.StatusServiceUnavailable)
		return
	}
	path, err := os.Executable()
	if err != nil {
		http.Error(w, "binary unavailable", http.StatusServiceUnavailable)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "binary unavailable", http.StatusServiceUnavailable)
		return
	}
	defer f.Close()
	// The file on disk may have been replaced since startup (an upgrade
	// in progress): hash exactly what this open file will send.
	h := sha256.New()
	_, herr := io.Copy(h, f)
	_, serr := f.Seek(0, io.SeekStart)
	info, err := f.Stat()
	if herr != nil || serr != nil || err != nil || [32]byte(h.Sum(nil)) != server.Build.SHA256 {
		http.Error(w, "this server does not run the leader's sfcd", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Sfc-Sha256", hex.EncodeToString(own.SHA256[:]))
	http.ServeContent(w, req, "sfcd", info.ModTime(), f)
}

type vpsEnrollRequest struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

func (r *Runtime) serveVPSEnroll(ctx context.Context, w http.ResponseWriter, req *http.Request, source netip.Addr) {
	var q vpsEnrollRequest
	d := json.NewDecoder(req.Body)
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	key, err := identity.ParseKey(q.Key)
	if err != nil || hex.EncodeToString(key[:]) != q.Key {
		http.Error(w, "bad key", http.StatusBadRequest)
		return
	}
	view, server, ok := r.enrollingVPS(ctx, q.Name, source)
	if !ok {
		http.NotFound(w, req)
		return
	}
	members, err := r.memberPolicy().Members(view.State)
	if err != nil {
		http.Error(w, "try again", http.StatusServiceUnavailable)
		return
	}
	switch vpsEnrollStep(server, members, q.Key) {
	case vpsEnrollConflict:
		http.Error(w, "another key already enrolled", http.StatusConflict)
	case vpsEnrollDone:
		inv := server.Invitation
		raw, err := inv.Encode()
		sourceKey, kerr := identity.ParseKey(inv.Source.Key)
		if err != nil || kerr != nil {
			http.Error(w, "invitation unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Sfc-Cluster", hex.EncodeToString(inv.Cluster[:]))
		w.Header().Set("X-Sfc-Source-Public-Key", hex.EncodeToString(sourceKey[:]))
		w.Header().Set("X-Sfc-Node", inv.Target.ID)
		w.Header().Set("X-Sfc-Endpoint", inv.Target.Endpoint)
		_, _ = w.Write(raw)
	case vpsEnrollWait:
		vpsEnrollPending(w) // invited; the leader signs the invitation next
	case vpsEnrollReport:
		report := control.MemberReport{Action: "vps-enroll", Node: server.Name, Expected: members.Revision, Source: server.PublicIP,
			Peer: config.Peer{ID: server.Name, Key: q.Key, Endpoint: server.Endpoint()}}
		if err := r.memberReport(ctx, view, report); err != nil && !errors.Is(err, errMemberReportStale) {
			http.Error(w, "try again", http.StatusServiceUnavailable)
			return
		}
		vpsEnrollPending(w)
	}
}

type vpsEnrollAnswer int

const (
	vpsEnrollReport   vpsEnrollAnswer = iota // ask the cluster to invite key
	vpsEnrollWait                            // invited, invitation not signed yet
	vpsEnrollDone                            // hand out the invitation
	vpsEnrollConflict                        // another key holds the name
)

// vpsEnrollStep decides one enroll request. The first key to enroll keeps
// the name; any other key is refused from then on.
func vpsEnrollStep(server control.VPSServer, members membership.Directory, key string) vpsEnrollAnswer {
	if inv := server.Invitation; inv != nil {
		if inv.Target.Key != key {
			return vpsEnrollConflict
		}
		return vpsEnrollDone
	}
	if e, exists := members.Entry(server.Name); exists {
		if e.Peer.Key != key {
			return vpsEnrollConflict
		}
		return vpsEnrollWait
	}
	return vpsEnrollReport
}

func vpsEnrollPending(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "5")
	w.WriteHeader(http.StatusAccepted)
}

// vpsInvitation signs the join invitation of an enrolled VPS server. Only a
// voter that is a full member can; the shape is the node-invitation query's.
func (r *Runtime) vpsInvitation(v cluster.View, d membership.Directory, server control.VPSServer) (*membership.Invitation, bool) {
	target, ok := d.Entry(server.Name)
	if !ok || target.Phase != membership.Invited || target.JoinID != server.JoinID() {
		return nil, false
	}
	self := r.commandIdentity()
	var source config.Peer
	for _, entry := range d.Entries {
		if entry.CurrentPeer().Key == self.Actor() && membership.FullMember(entry) {
			source = entry.Peer
		}
	}
	if !source.Voter {
		return nil, false
	}
	inv := membership.Invitation{Schema: 1, Cluster: r.controlPolicy.Cluster, Admin: r.controlPolicy.BootstrapKey, Genesis: d.Genesis, Source: source, Target: target.Peer,
		JoinID: target.JoinID, ApprovalRevision: target.Job.Desired.Revision, MinimumIndex: v.RaftIndex}
	inv.Signature = ed25519.Sign(self.Private, membership.InvitationBytes(inv))
	return &inv, strings.HasPrefix(inv.JoinID, "vps-")
}
