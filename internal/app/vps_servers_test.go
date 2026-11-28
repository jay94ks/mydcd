// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/vps"
)

type fakeVPSProvider struct {
	vps.ManagedProvider
	instances []vps.Instance
	listErr   error
	createErr error
	created   []vps.CreateRequest
	deleteErr error
	deleted   []string
	power     []string
}

func (f *fakeVPSProvider) Shutdown(_ context.Context, id string) error {
	f.power = append(f.power, "shutdown "+id)
	return nil
}

func (f *fakeVPSProvider) Start(_ context.Context, id string) error {
	f.power = append(f.power, "start "+id)
	return nil
}

func (f *fakeVPSProvider) Delete(_ context.Context, id string) error {
	f.deleted = append(f.deleted, id)
	return f.deleteErr
}

func (f *fakeVPSProvider) Instances(context.Context) ([]vps.Instance, error) {
	return f.instances, f.listErr
}

func (f *fakeVPSProvider) Create(_ context.Context, q vps.CreateRequest) (vps.Instance, error) {
	f.created = append(f.created, q)
	return vps.Instance{}, f.createErr
}

func TestVPSCreateIsSentOnceAfterCreateSent(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	server := control.VPSServer{Name: "edge-1", Zone: "KR1-Z01", Image: "PIMAGE-u", Flavor: "F1", SSHKeys: []string{"K1"}, Script: "S1", CreatedAt: now.Add(-time.Minute).Unix()}
	tag := "sfc:01000000:op-1"
	ctx := context.Background()

	f := &fakeVPSProvider{instances: []vps.Instance{{ID: "INSTANCE-other", Description: "someone else"}}}
	// Nothing found and nothing sent: commit create-sent first, no Create yet.
	if o := lookupVPSCreate(ctx, f, server, tag, now); o.Action != control.VPSCreateSent || len(f.created) != 0 {
		t.Fatalf("first tick = %+v, created %+v", o, f.created)
	}
	if o := sendVPSCreate(ctx, f, server, tag); o.Action != "" || len(f.created) != 1 || f.created[0].Description != tag || f.created[0].Script != "S1" {
		t.Fatalf("send = %+v, created %+v", o, f.created)
	}
	server.CreateSentAt = now.Unix()

	// 1. The vendor list is slow: the instance is not there yet. Wait.
	if o := lookupVPSCreate(ctx, f, server, tag, now.Add(time.Minute)); o.Action != "" || len(f.created) != 1 {
		t.Fatalf("slow list = %+v, creates %d", o, len(f.created))
	}
	// 2. The Create reply was lost (TRANSPORT) but it was made: it shows up.
	f.instances = append(f.instances, vps.Instance{ID: "INSTANCE-1", Description: tag, Status: vps.StatusPending})
	if o := lookupVPSCreate(ctx, f, server, tag, now.Add(2*time.Minute)); o.Action != "" || len(f.created) != 1 {
		t.Fatalf("pending = %+v, creates %d", o, len(f.created))
	}
	f.instances[1].Status, f.instances[1].PublicIPv4 = vps.StatusActive, "203.0.113.9"
	if o := lookupVPSCreate(ctx, f, server, tag, now.Add(3*time.Minute)); o != (vpsOutcome{Action: control.VPSInstalling, InstanceID: "INSTANCE-1", PublicIP: "203.0.113.9"}) {
		t.Fatalf("active = %+v", o)
	}
	f.instances[1].Status = vps.StatusError
	if o := lookupVPSCreate(ctx, f, server, tag, now.Add(3*time.Minute)); o.Action != control.VPSFailed || o.InstanceID != "INSTANCE-1" {
		t.Fatalf("error = %+v", o)
	}
}

func TestVPSNewLeaderNeverCreatesAgain(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	// 3. A new leader sees create-sent committed but no instance (the old
	// leader died before or during the Create). It only looks, until the
	// deadline, then fails.
	server := control.VPSServer{Name: "edge-1", CreatedAt: now.Add(-time.Hour).Unix(), CreateSentAt: now.Add(-time.Minute).Unix()}
	f := &fakeVPSProvider{}
	ctx := context.Background()
	if o := lookupVPSCreate(ctx, f, server, "t", now); o.Action != "" || len(f.created) != 0 {
		t.Fatalf("new leader = %+v, creates %d", o, len(f.created))
	}
	if o := lookupVPSCreate(ctx, f, server, "t", now.Add(vpsCreateTimeout)); o.Failure != "TIMEOUT" || len(f.created) != 0 {
		t.Fatalf("deadline = %+v", o)
	}
	f.listErr = &vps.Error{Kind: vps.KindTransport}
	if o := lookupVPSCreate(ctx, f, server, "t", now.Add(vpsCreateTimeout)); o.Action != "" {
		t.Fatalf("unknown list after send must not fail blind = %+v", o)
	}
}

func TestVPSDeleteInstance(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	ctx := context.Background()
	tag := "sfc:01000000:op-1"
	// Known instance: delete it; a vendor that no longer has it is done too.
	known := control.VPSServer{Name: "edge-1", Phase: control.VPSDeleting, InstanceID: "INSTANCE-1", CreateSentAt: now.Unix()}
	f := &fakeVPSProvider{}
	if o := deleteVPSInstance(ctx, f, known, tag, now); o.Action != control.VPSDeleted || len(f.deleted) != 1 || f.deleted[0] != "INSTANCE-1" {
		t.Fatalf("known = %+v, deleted %v", o, f.deleted)
	}
	f = &fakeVPSProvider{deleteErr: &vps.Error{Kind: vps.KindNotFound}}
	if o := deleteVPSInstance(ctx, f, known, tag, now); o.Action != control.VPSDeleted {
		t.Fatalf("not found = %+v", o)
	}
	f = &fakeVPSProvider{deleteErr: &vps.Error{Kind: vps.KindTransport}}
	if o := deleteVPSInstance(ctx, f, known, tag, now); o.Action != "" {
		t.Fatalf("unknown delete result must keep the record = %+v", o)
	}
	// Never sent: nothing to delete.
	f = &fakeVPSProvider{}
	if o := deleteVPSInstance(ctx, f, control.VPSServer{Name: "edge-1"}, tag, now); o.Action != control.VPSDeleted || len(f.deleted) != 0 {
		t.Fatalf("never sent = %+v", o)
	}
	// Sent but no ID: find it by tag, or wait for it until the create timeout.
	sent := control.VPSServer{Name: "edge-1", CreateSentAt: now.Unix()}
	if o := deleteVPSInstance(ctx, f, sent, tag, now.Add(time.Minute)); o.Action != "" || len(f.deleted) != 0 {
		t.Fatalf("not listed yet = %+v", o)
	}
	f.instances = []vps.Instance{{ID: "INSTANCE-late", Description: tag}}
	if o := deleteVPSInstance(ctx, f, sent, tag, now.Add(2*time.Minute)); o.Action != control.VPSDeleted || len(f.deleted) != 1 || f.deleted[0] != "INSTANCE-late" {
		t.Fatalf("by tag = %+v, deleted %v", o, f.deleted)
	}
	f = &fakeVPSProvider{}
	if o := deleteVPSInstance(ctx, f, sent, tag, now.Add(vpsCreateTimeout+time.Minute)); o.Action != control.VPSDeleted {
		t.Fatalf("after timeout = %+v", o)
	}
	f = &fakeVPSProvider{listErr: &vps.Error{Kind: vps.KindTransport}}
	if o := deleteVPSInstance(ctx, f, sent, tag, now.Add(vpsCreateTimeout+time.Minute)); o.Action != "" {
		t.Fatalf("unreadable list must keep the record = %+v", o)
	}
}

func TestVPSPowerReadsBeforeAsking(t *testing.T) {
	ctx := context.Background()
	server := control.VPSServer{Name: "edge-1", Phase: control.VPSStopping, InstanceID: "INSTANCE-1"}
	f := &fakeVPSProvider{instances: []vps.Instance{{ID: "INSTANCE-1", Status: vps.StatusActive}}}
	if o, sent := powerVPS(ctx, f, server, false); o.Action != "" || sent || len(f.power) != 0 {
		t.Fatalf("paced = %+v %v %v", o, sent, f.power)
	}
	if o, sent := powerVPS(ctx, f, server, true); o.Action != "" || !sent || len(f.power) != 1 || f.power[0] != "shutdown INSTANCE-1" {
		t.Fatalf("shutdown = %+v %v %v", o, sent, f.power)
	}
	f.instances[0].Status = vps.StatusWorking
	if o, sent := powerVPS(ctx, f, server, true); o.Action != "" || sent || len(f.power) != 1 {
		t.Fatalf("vendor job running must not ask again = %+v %v", o, f.power)
	}
	f.instances[0].Status = vps.StatusOff
	if o, _ := powerVPS(ctx, f, server, true); o.Action != control.VPSStopped || len(f.power) != 1 {
		t.Fatalf("off = %+v %v", o, f.power)
	}
	server.Phase = control.VPSStarting
	if o, sent := powerVPS(ctx, f, server, true); o.Action != "" || !sent || f.power[1] != "start INSTANCE-1" {
		t.Fatalf("start = %+v %v", o, f.power)
	}
	f.instances[0].Status = vps.StatusActive
	if o, _ := powerVPS(ctx, f, server, true); o.Action != control.VPSStarted {
		t.Fatalf("active = %+v", o)
	}
	f = &fakeVPSProvider{listErr: &vps.Error{Kind: vps.KindTransport}}
	if o, sent := powerVPS(ctx, f, server, true); o.Action != "" || sent || len(f.power) != 0 {
		t.Fatalf("unreadable = %+v", o)
	}
}

func TestVPSCreateErrors(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	server := control.VPSServer{Name: "edge-1", CreatedAt: now.Add(-time.Minute).Unix()}
	ctx := context.Background()
	for _, kind := range []vps.Kind{vps.KindTransport, vps.KindBusy, vps.KindProtocol} {
		f := &fakeVPSProvider{createErr: &vps.Error{Kind: kind}}
		if o := sendVPSCreate(ctx, f, server, "t"); o.Action != "" {
			t.Fatalf("%s = %+v", kind, o)
		}
	}
	f := &fakeVPSProvider{createErr: &vps.Error{Kind: vps.KindUnavailable}}
	if o := sendVPSCreate(ctx, f, server, "t"); o.Action != control.VPSFailed || o.Failure != "UNAVAILABLE" {
		t.Fatalf("unavailable = %+v", o)
	}
	f = &fakeVPSProvider{listErr: &vps.Error{Kind: vps.KindAuth}}
	if o := lookupVPSCreate(ctx, f, server, "t", now); o.Failure != "AUTH" || len(f.created) != 0 {
		t.Fatalf("auth = %+v", o)
	}
	old := server
	old.CreatedAt = now.Add(-vpsCreateTimeout - time.Minute).Unix()
	f = &fakeVPSProvider{}
	if o := lookupVPSCreate(ctx, f, old, "t", now); o.Failure != "TIMEOUT" || len(f.created) != 0 {
		t.Fatalf("timeout = %+v", o)
	}
}

type fakeVPSCatalog struct {
	fakeVPSProvider
	imageZone string
	flavorQ   vps.FlavorQuery
}

func (f *fakeVPSCatalog) Zones(context.Context) ([]vps.Zone, error) {
	return []vps.Zone{{ID: "KR1-Z01"}}, nil
}
func (f *fakeVPSCatalog) Images(_ context.Context, zone string) ([]vps.Image, error) {
	f.imageZone = zone
	return nil, nil
}
func (f *fakeVPSCatalog) Flavors(_ context.Context, q vps.FlavorQuery) ([]vps.Flavor, error) {
	f.flavorQ = q
	return []vps.Flavor{{ID: "F1"}}, nil
}
func (f *fakeVPSCatalog) SSHKeys(context.Context) ([]vps.SSHKey, error) { return nil, nil }
func (f *fakeVPSCatalog) Scripts(context.Context) ([]vps.Script, error) { return nil, nil }

func TestReadVPSOfferNarrowsByZone(t *testing.T) {
	f := &fakeVPSCatalog{}
	o, err := readVPSOffer(context.Background(), f, control.VPSOfferQuery{Account: "main", Zone: "KR1-Z01", Flavors: vps.FlavorQuery{MinVCPU: 2}}, time.Unix(5, 0))
	if err != nil || o.Account != "main" || o.At != 5 || len(o.Flavors) != 1 || f.imageZone != "KR1-Z01" || len(f.flavorQ.Zones) != 1 || f.flavorQ.MinVCPU != 2 {
		t.Fatalf("offer = %+v %+v, %v", o, f.flavorQ, err)
	}
}

func TestVPSEnrollStepFirstKeyWins(t *testing.T) {
	server := managedTarget(control.VPSServer{Name: "edge-1"})
	var d membership.Directory
	if got := vpsEnrollStep(server, d, "aa"); got != vpsEnrollReport {
		t.Fatal("new", got)
	}
	d.Entries = []membership.Entry{{Peer: config.Peer{ID: "edge-1", Key: "aa"}, Phase: membership.Invited}}
	if got := vpsEnrollStep(server, d, "aa"); got != vpsEnrollWait {
		t.Fatal("invited", got)
	}
	if got := vpsEnrollStep(server, d, "bb"); got != vpsEnrollConflict {
		t.Fatal("other key while invited", got)
	}
	server.Invitation = &membership.Invitation{Target: config.Peer{ID: "edge-1", Key: "aa"}}
	if got := vpsEnrollStep(server, d, "aa"); got != vpsEnrollDone {
		t.Fatal("signed", got)
	}
	if got := vpsEnrollStep(server, d, "bb"); got != vpsEnrollConflict {
		t.Fatal("other key after signing", got)
	}
}
