// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/nodedisks"
	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/moby/moby/client"
)

// nodeDiskRuntime keeps this server's disk operations and mount records in
// <state_dir>/disks/mounts.db, outside Raft (proposal §4.2). A row is
// written before its step runs, so a restart never formats twice: a row
// still running at start becomes failed/interrupted.
type nodeDiskRuntime struct {
	mu   sync.Mutex
	db   *storage.DB
	host nodedisks.Host
	lvm  nodedisks.LVM
	// dir is <state_dir>/disks; fuse bundle specs go in dir/fuse.
	dir string
	// warned keeps one log line per record that cannot be mounted at start
	// (guarded by wmu: the observation loop reads it while mu is held by a
	// long format).
	wmu    sync.Mutex
	warned map[string]string
	// retries and diskSet space failed bundle activations (wmu).
	retries map[string]activationRetry
	diskSet string
}

type nodeDiskJournal struct {
	Request [32]byte
	Result  control.NodeDiskResult
	// FormatUUID is chosen before mkfs runs.
	FormatUUID string `json:",omitempty"`
}

func (r *Runtime) openNodeDisks(stateRoot string) error {
	if r.historicalOwner {
		return nil
	}
	db, err := storage.Open(filepath.Join(stateRoot, "disks", "mounts.db"))
	if err != nil {
		return err
	}
	d := &nodeDiskRuntime{db: db, host: nodedisks.Real, lvm: nodedisks.RealLVM, dir: filepath.Join(stateRoot, "disks"), warned: map[string]string{}}
	rows, err := db.Scan("op/")
	if err != nil {
		db.Close()
		return err
	}
	updates := map[string][]byte{}
	for key, raw := range rows {
		j, e := schema.Decode[nodeDiskJournal](raw)
		if e != nil || j.Result.State != "running" {
			continue
		}
		j.Result.State, j.Result.Code, j.Result.Error, j.Result.FinishedAt = "failed", "interrupted", "sfcd stopped during step "+j.Result.Step, time.Now().Unix()
		updates[key], _ = json.Marshal(j)
	}
	if len(updates) > 0 {
		if err := db.Write(updates); err != nil {
			db.Close()
			return err
		}
	}
	r.nodeDisks = d
	return nil
}

func (d *nodeDiskRuntime) records() ([]nodedisks.Record, error) {
	rows, err := d.db.Scan("mount/")
	if err != nil {
		return nil, err
	}
	out := []nodedisks.Record{}
	for _, raw := range rows {
		rec, e := schema.Decode[nodedisks.Record](raw)
		if e == nil && rec.Valid() {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func (d *nodeDiskRuntime) journal(id string) (nodeDiskJournal, bool, error) {
	raw, err := d.db.Get("op/" + id)
	if errors.Is(err, storage.ErrMissing) {
		return nodeDiskJournal{}, false, nil
	}
	if err != nil {
		return nodeDiskJournal{}, false, err
	}
	j, err := schema.Decode[nodeDiskJournal](raw)
	return j, err == nil, err
}

func (d *nodeDiskRuntime) save(j nodeDiskJournal, extra map[string][]byte) error {
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	values := map[string][]byte{"op/" + j.Result.Operation: raw}
	for k, v := range extra {
		values[k] = v
	}
	return d.db.Write(values)
}

// nodeDiskChange serves a user's disk operation on the server that holds
// the session's connection: it runs on this server or is relayed to the
// owner over SFCP, never through Raft.
func (r *Runtime) nodeDiskChange(ctx context.Context, read control.NodeDiskRead) (control.NodeDiskResult, error) {
	if read.Owner == r.Identity.Public {
		return r.nodeDiskLocal(ctx, read)
	}
	peer, ok := r.Mesh.Peer(sfcp.Identity(read.Owner))
	if !ok || !peer.Member || peer.ID != read.Op.Node {
		return control.NodeDiskResult{}, sfcp.ErrAdmission
	}
	// Only over a session that is up now: dialing a stopped server would
	// hold the request until the handshake times out.
	if !r.Mesh.Connected(peer.Key) {
		return control.NodeDiskResult{}, fmt.Errorf("%w: %s", sfcp.ErrNotConnected, peer.ID)
	}
	raw, _ := json.Marshal(read)
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "node-disk-owner", Input: raw})
	if err != nil {
		return control.NodeDiskResult{}, err
	}
	result, err := schema.Decode[control.NodeDiskResult](reply.Data)
	if err != nil || !result.Valid() || result.Operation != read.Op.Operation || result.Node != read.Op.Node {
		return control.NodeDiskResult{}, sfcp.ErrAdmission
	}
	return result, nil
}

func (r *Runtime) nodeDiskLocal(ctx context.Context, read control.NodeDiskRead) (control.NodeDiskResult, error) {
	if r.installation == nil || r.nodeDisks == nil || read.Owner != r.Identity.Public || read.Op.Node != r.installation.record.Root.Self.ID {
		return control.NodeDiskResult{}, sfcp.ErrAdmission
	}
	// The session is checked again on the owner at a quorum read, as for
	// diagnostics; an earlier approval is not a lasting grant.
	raw, _ := json.Marshal(read)
	permit, err := r.appCall(ctx, "node-disk-permit", raw)
	if err != nil {
		return control.NodeDiskResult{}, err
	}
	current, err := schema.Decode[control.NodeDiskRead](permit.Data)
	if err != nil || !control.SameNodeDiskOp(current.Op, read.Op) || current.Owner != r.Identity.Public || !bytes.Equal(access.SessionBytes(current.Session), access.SessionBytes(read.Session)) || !bytes.Equal(current.Session.Signature, read.Session.Signature) {
		return control.NodeDiskResult{}, sfcp.ErrAdmission
	}
	view, err := r.Engine().ReadAtLeast(ctx, current.Index)
	if err != nil {
		return control.NodeDiskResult{}, err
	}
	live, err := r.controlPolicy.ReadNodeDisk(view.State, current.Session, time.Now().Unix(), current.Op)
	if err != nil || view.State.Index() < current.Index || view.State.ModuleEpoch() != current.Epoch || live.Owner != current.Owner || live.MembersRoot != current.MembersRoot || live.RootsRevision != current.RootsRevision {
		return control.NodeDiskResult{}, sfcp.ErrAdmission
	}
	d := r.nodeDisks
	op := current.Op
	if op.Action == "status" {
		j, found, err := d.journal(op.Operation)
		if err != nil {
			return control.NodeDiskResult{}, err
		}
		if !found {
			return control.NodeDiskResult{}, userauth.ErrNodeDiskMissing
		}
		return j.Result, nil
	}
	request := sha256.Sum256(append([]byte("sfc-node-disk-op-1\x00"), diskJSON(op)...))
	d.mu.Lock()
	j, found, err := d.journal(op.Operation)
	if err != nil || found {
		d.mu.Unlock()
		if err == nil && j.Request != request {
			return control.NodeDiskResult{Schema: 1, Operation: op.Operation, Node: op.Node, Action: op.Action, User: current.Session.User, Disk: op.Disk, Part: op.Part, State: "failed", Step: "check", Code: "operation-conflict", Error: "this operation ID was used for another request"}, nil
		}
		return j.Result, err // the original outcome; never run twice
	}
	j = nodeDiskJournal{Request: request, Result: control.NodeDiskResult{Schema: 1, Operation: op.Operation, Node: op.Node, Action: op.Action, User: current.Session.User, Disk: op.Disk, Part: op.Part, Bundle: op.Bundle, State: "running", Step: "check", Label: op.Label, StartedAt: time.Now().Unix()}}
	if err := d.save(j, nil); err != nil {
		d.mu.Unlock()
		return control.NodeDiskResult{}, err
	}
	done := make(chan control.NodeDiskResult, 1)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer d.mu.Unlock() // one disk operation at a time on a server
		result := r.runNodeDisk(r.ctx, d, j, op, current.RootPaths)
		done <- result
	}()
	// Mount and unmount finish at once; a format may take longer and is
	// read back with status.
	select {
	case result := <-done:
		return result, nil
	case <-time.After(10 * time.Second):
		return j.Result, nil
	case <-ctx.Done():
		return j.Result, nil
	}
}

func diskJSON(v any) []byte {
	raw, _ := json.Marshal(v)
	return raw
}

func (r *Runtime) dockerRoot(ctx context.Context) string {
	if r.docker == nil {
		return ""
	}
	info, err := r.docker.API.Info(ctx, client.InfoOptions{})
	if err != nil {
		return ""
	}
	return info.Info.DockerRootDir
}

func (r *Runtime) diskInventory(ctx context.Context) (observability.Devices, error) {
	for i := 0; ; i++ {
		inv, err := observability.InspectDevices(ctx)
		if !errors.Is(err, observability.ErrDevicesBusy) || i == 20 {
			return inv, err
		}
		select {
		case <-ctx.Done():
			return observability.Devices{}, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// runNodeDisk runs one checked operation; the caller holds d.mu.
func (r *Runtime) runNodeDisk(ctx context.Context, d *nodeDiskRuntime, j nodeDiskJournal, op control.NodeDiskOp, roots []string) control.NodeDiskResult {
	step := func(name string, extra map[string][]byte) error {
		j.Result.Step = name
		return d.save(j, extra)
	}
	fail := func(err error) control.NodeDiskResult {
		var refusal nodedisks.Refusal
		if !errors.As(err, &refusal) {
			refusal = nodedisks.Refusal{Code: "io", Detail: err.Error()}
		}
		if len(refusal.Detail) > 512 {
			refusal.Detail = refusal.Detail[:512]
		}
		j.Result.State, j.Result.Code, j.Result.Error, j.Result.FinishedAt = "failed", refusal.Code, strings.ToValidUTF8(strings.Map(func(c rune) rune {
			if c < 0x20 || c == 0x7f {
				return ' '
			}
			return c
		}, refusal.Detail), ""), time.Now().Unix()
		if e := d.save(j, nil); e != nil {
			log.Printf("node disk journal: operation=%s error=%v", op.Operation, e)
		}
		r.recordNodeDiskEvent(j.Result)
		return j.Result
	}
	done := func() control.NodeDiskResult {
		j.Result.State, j.Result.FinishedAt = "done", time.Now().Unix()
		if err := d.save(j, nil); err != nil {
			log.Printf("node disk journal: operation=%s error=%v", op.Operation, err)
		}
		r.recordNodeDiskEvent(j.Result)
		return j.Result
	}
	switch op.Action {
	case "bundle", "unbundle", "replace-member":
		if err := r.runNodeDiskBundle(ctx, d, &j, op, roots, step); err != nil {
			return fail(err)
		}
		return done()
	}
	inventory, err := r.diskInventory(ctx)
	if err != nil {
		return fail(nodedisks.Refusal{Code: "io", Detail: "device inventory: " + err.Error()})
	}
	records, err := d.records()
	if err != nil {
		return fail(err)
	}
	plan, err := nodedisks.Check(op, inventory, roots, records, r.dockerRoot(ctx))
	if err != nil {
		return fail(err)
	}
	if bundles, err := d.bundles(); err != nil {
		return fail(err)
	} else if err := nodedisks.FuseMemberBusy(op, plan, bundles); err != nil {
		return fail(err)
	}
	format := func(plan nodedisks.Plan) error {
		uuid, _, err := nodedisks.NewUUID()
		if err != nil {
			return err
		}
		j.FormatUUID = uuid
		part := op.Part
		if plan.Whole {
			if err := step("partition", nil); err != nil {
				return err
			}
			_, diskGUID, err1 := nodedisks.NewUUID()
			_, partGUID, err2 := nodedisks.NewUUID()
			if err := errors.Join(err1, err2); err != nil {
				return err
			}
			if part, err = d.host.WriteTable(ctx, op.Disk, diskGUID, partGUID); err != nil {
				return err
			}
		} else {
			if err := step("wipe", nil); err != nil {
				return err
			}
			if err := d.host.WipePart(part); err != nil {
				return err
			}
		}
		j.Result.Part = part
		if err := step("format", nil); err != nil {
			return err
		}
		if err := d.host.MakeExt4(ctx, part, uuid, op.Label); err != nil {
			return err
		}
		j.Result.UUID, j.Result.Device = uuid, "/dev/"+part
		return nil
	}
	mount := func(plan nodedisks.Plan) error {
		rec := nodedisks.Record{Schema: 1, UUID: plan.Part.UUID, Path: plan.Path, Disk: plan.Disk.Name, Part: plan.Part.Name, Serial: plan.Disk.Serial, WWN: plan.Disk.WWN, Operation: op.Operation, User: j.Result.User, At: time.Now().Unix()}
		if err := nodedisks.PreparePoint(plan.Path); err != nil {
			return err
		}
		// The record goes first: from here on sfcd mounts it at start.
		if err := step("record", map[string][]byte{"mount/" + rec.UUID: diskJSON(rec)}); err != nil {
			return err
		}
		if err := d.host.Mount(plan.Part.Name, plan.Path); err != nil {
			if plan.Record == nil {
				_ = d.db.Write(map[string][]byte{"mount/" + rec.UUID: nil})
			}
			return err
		}
		j.Result.UUID, j.Result.Device, j.Result.MountPath = rec.UUID, "/dev/"+rec.Part, rec.Path
		return nil
	}
	switch op.Action {
	case "format":
		if err := format(plan); err != nil {
			return fail(err)
		}
	case "mount":
		if err := mount(plan); err != nil {
			return fail(err)
		}
	case "prepare-storage":
		if op.Format {
			if err := format(plan); err != nil {
				return fail(err)
			}
			// Check the mount half against the new filesystem.
			if inventory, err = r.diskInventory(ctx); err != nil {
				return fail(nodedisks.Refusal{Code: "io", Detail: "device inventory: " + err.Error()})
			}
			next := op
			next.Format, next.Part, next.UUID, next.Size, next.TableID, next.Label = false, j.Result.Part, j.Result.UUID, 0, "", ""
			if plan, err = nodedisks.Check(next, inventory, roots, records, r.dockerRoot(ctx)); err != nil {
				return fail(err)
			}
		}
		if plan.Mounted {
			j.Result.UUID, j.Result.Device, j.Result.MountPath = plan.Part.UUID, "/dev/"+plan.Part.Name, plan.Path
		} else if err := mount(plan); err != nil {
			return fail(err)
		}
		if err := step("directory", nil); err != nil {
			return fail(err)
		}
		if err := nodedisks.MakeRootDir(plan.Path, op.SubPath); err != nil {
			return fail(err)
		}
		j.Result.RootPath = plan.RootPath
	case "forget":
		if err := step("record", map[string][]byte{"mount/" + plan.Record.UUID: nil}); err != nil {
			return fail(err)
		}
		j.Result.UUID, j.Result.MountPath = plan.Record.UUID, plan.Path
	case "unmount":
		if err := step("unmount", nil); err != nil {
			return fail(err)
		}
		if plan.Mounted {
			if err := nodedisks.Unmount(plan.Path); err != nil {
				return fail(err)
			}
		}
		if err := step("record", map[string][]byte{"mount/" + plan.Record.UUID: nil}); err != nil {
			return fail(err)
		}
		j.Result.UUID, j.Result.Device, j.Result.MountPath = plan.Record.UUID, "/dev/"+plan.Part.Name, plan.Path
	}
	j.Result.State, j.Result.FinishedAt = "done", time.Now().Unix()
	if err := d.save(j, nil); err != nil {
		log.Printf("node disk journal: operation=%s error=%v", op.Operation, err)
	}
	r.recordNodeDiskEvent(j.Result)
	return j.Result
}

// recordNodeDiskEvent leaves who changed which disk in the signed event log.
func (r *Runtime) recordNodeDiskEvent(result control.NodeDiskResult) {
	if r.events == nil {
		return
	}
	kind := map[string]string{"format": "node-disk-formatted", "mount": "node-disk-mounted", "unmount": "node-disk-unmounted", "forget": "node-disk-unmounted", "prepare-storage": "node-disk-storage-prepared", "bundle": "node-disk-bundled", "unbundle": "node-disk-unbundled", "replace-member": "node-disk-member-replaced"}[result.Action]
	if result.State == "failed" {
		kind = "node-disk-failed"
	}
	now := uint64(time.Now().UnixMilli())
	user := result.User
	if len(user) > 63 {
		user = user[:63]
	}
	e := eventlog.Event{Kind: kind, Scope: "node", At: now, Target: eventlog.Target{Node: result.Node}, Detail: eventlog.Detail{Actor: user, Operation: result.Operation, Resource: cmp.Or(result.Part, result.Bundle), State: result.Action, Code: result.Code}}
	if _, err := r.events.Append("node-disk/"+result.Operation, e, now); err != nil {
		log.Printf("node disk event: operation=%s error=%v", result.Operation, err)
	}
}

// reconcileNodeDisks mounts every recorded disk that is not mounted yet. It
// runs before node storage, so a storage root on a missing disk stays not
// ready (its directory identity check fails) and the volumes and containers
// on it wait. A disk whose UUID or device identity no longer matches is
// never mounted in its place.
func (r *Runtime) reconcileNodeDisks(ctx context.Context) error {
	d := r.nodeDisks
	if d == nil || !d.mu.TryLock() {
		return nil // an operation is changing disks right now
	}
	defer d.mu.Unlock()
	records, err := d.records()
	if err != nil || len(records) == 0 {
		return err
	}
	inventory, err := r.diskInventory(ctx)
	if err != nil {
		return nil // the observation loop logs inventory failures
	}
	// Plain disks first: a fuse bundle's members are among them. Then the
	// bundles are turned on and the filesystems on them mounted.
	plain := slices.DeleteFunc(slices.Clone(records), func(rec nodedisks.Record) bool { return rec.Bundle != "" })
	mounted := r.mountNodeDiskRecords(d, plain, inventory)
	if len(plain) == len(records) {
		return nil
	}
	if activated := r.activateBundles(ctx, d, inventory); activated || mounted {
		if inventory, err = r.diskInventory(ctx); err != nil {
			return nil
		}
	}
	r.mountNodeDiskRecords(d, slices.DeleteFunc(records, func(rec nodedisks.Record) bool { return rec.Bundle == "" }), inventory)
	return nil
}

// mountNodeDiskRecords mounts records and says whether it mounted one.
func (r *Runtime) mountNodeDiskRecords(d *nodeDiskRuntime, records []nodedisks.Record, inventory observability.Devices) bool {
	mountedAny := false
	for _, rec := range records {
		reason := ""
		var target *observability.BlockPart
		var disk observability.BlockDisk
		for _, dk := range inventory.Disks {
			for i, p := range dk.Parts {
				if p.UUID == rec.UUID {
					target, disk = &dk.Parts[i], dk
				}
			}
		}
		switch {
		case target == nil:
			reason = "disk-not-found"
		case rec.Serial != "" && disk.Serial != rec.Serial || rec.WWN != "" && disk.WWN != rec.WWN:
			reason = "device-identity-changed"
		case disk.Class == "system" || target.Filesystem != "ext4":
			reason = "not-an-additional-ext4-disk"
		}
		if target != nil && reason == "" {
			mounted := false
			for _, m := range target.Mounts {
				mounted = mounted || m == rec.Path
			}
			if mounted {
				d.warn(rec, "")
				continue
			}
			if target.Busy() {
				reason = "mounted-elsewhere"
			} else if err := nodedisks.PreparePoint(rec.Path); err != nil {
				reason = "mount-point-not-empty"
			} else if err := d.host.Mount(target.Name, rec.Path); err != nil {
				reason = "mount-failed"
			} else {
				log.Printf("node disk mounted: uuid=%s device=/dev/%s path=%s", rec.UUID, target.Name, rec.Path)
				d.warn(rec, "")
				mountedAny = true
				continue
			}
		}
		d.warn(rec, reason)
	}
	return mountedAny
}

// warn logs once per reason change; "" clears it.
func (d *nodeDiskRuntime) warn(rec nodedisks.Record, reason string) {
	d.wmu.Lock()
	defer d.wmu.Unlock()
	if reason == "" {
		delete(d.warned, rec.UUID)
		return
	}
	if d.warned[rec.UUID] != reason {
		d.warned[rec.UUID] = reason
		log.Printf("node disk not mounted: uuid=%s path=%s reason=%s", rec.UUID, rec.Path, reason)
	}
}

func (d *nodeDiskRuntime) Close() error {
	if d == nil {
		return nil
	}
	return d.db.Close()
}

// nodeReadNodeDisk is node-disk-permit (leader) and node-disk-owner (the
// server whose disk it is).
func (r *Runtime) nodeReadNodeDisk(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	q, decodeErr := schema.Decode[control.NodeDiskRead](input)
	d, memberErr := r.controlPolicy.Members(v.State)
	if err != nil || decodeErr != nil || memberErr != nil || !d.MemberKey(caller) {
		return nil, sfcp.ErrAdmission
	}
	if method == "node-disk-owner" {
		result, err := r.nodeDiskLocal(ctx, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
	read, err := r.controlPolicy.ReadNodeDisk(v.State, q.Session, time.Now().Unix(), q.Op)
	if err != nil || v.Local || read.Owner != caller {
		return nil, sfcp.ErrAdmission
	}
	return json.Marshal(read)
}

// recordedMounts lists the mount records for the device report, with the
// last reason one is not mounted.
func (r *Runtime) recordedMounts(inventory observability.Devices) []observability.RecordedMount {
	d := r.nodeDisks
	if d == nil {
		return nil
	}
	records, err := d.records()
	if err != nil {
		return nil
	}
	d.wmu.Lock()
	warned := map[string]string{}
	for k, v := range d.warned {
		warned[k] = v
	}
	d.wmu.Unlock()
	out := []observability.RecordedMount{}
	for _, rec := range records {
		m := observability.RecordedMount{UUID: rec.UUID, Path: rec.Path, Disk: rec.Disk, Part: rec.Part, Reason: "pending"}
		for _, dk := range inventory.Disks {
			for _, p := range dk.Parts {
				for _, mount := range p.Mounts {
					if p.UUID == rec.UUID && mount == rec.Path {
						m.Reason = ""
					}
				}
			}
		}
		if reason := warned[rec.UUID]; m.Reason != "" && reason != "" {
			m.Reason = reason
		}
		out = append(out, m)
		if len(out) == 32 {
			break
		}
	}
	return out
}
