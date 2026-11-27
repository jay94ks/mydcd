// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"github.com/moby/moby/client"
)

func TestRQ9RealDelegatedVolumeFilesCLIAndOriginalPublicationResume(t *testing.T) {
	runManagedAppOwner(t, true, true, false, true, managedAppVolumeFiles, true)
}

// volumeFileGrantReadHook observes the original committed folder grant state
// using independent API requesters, without opening either CLI wallet/journal.
// granted is true immediately after grant and false immediately after revoke.
type volumeFileGrantReadHook func(t *testing.T, ctx context.Context, admin, delegated userauth.Client, peer sfcp.Peer, adminSession, delegatedSession access.Session, granted bool)

// This hook runs after the original managed app's real retirement. Its retained
// Volume, native manager, rollback, User/Raft and CLI wallet are the existing
// fixture's resources. No stand-in writer or replacement Volume is registered.
func verifyVolumeFilesUserNative(t *testing.T, ctx context.Context, owner **Runtime, cfg config.Node, root string, admin userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), grantRead volumeFileGrantReadHook) {
	t.Helper()
	catalog, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("tenant")
	change("rq9-restore-file-node", "set-nodes", tenant.Revision, control.NodeChangeTo("tenant", tenant.AllowedNodes, []string{"node-a"}))
	book, err := p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	source, ok := book.Native("tenant", "app", "data")
	if !ok {
		t.Fatal("retained original Volume missing")
	}
	original, ok := book.Volume(source.Spec.Scope)
	if !ok || len(original.Consumers()) != 0 {
		t.Fatal("app did not return original writer before delegated file mutation")
	}
	mount, err := (*owner).docker.API.VolumeInspect(ctx, source.Owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	base := &fixedAppNativeFixture{home: filepath.Join(root, "cli-home"), profile: filepath.Join(root, "cli.yaml"), binary: os.Getenv("SFC_TEST_CLI")}
	adminCLI := func(want int, args ...string) map[string]json.RawMessage {
		return base.cli(t, ctx, want, append([]string{"--tenant", "tenant"}, args...)...)
	}
	botKey, err := identity.Create(filepath.Join(root, "file-bot-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(botKey.Private)
	bot := access.User{ID: "file-bot", Username: "file-bot", Enabled: true, AutomationOnly: true, Credentials: []access.Credential{{ID: "files", Method: access.PrivateKey, PublicKey: botKey.Public, Enabled: true, Operations: []string{"volume-file-put", "volume-file-get", "volume-file-list", "volume-file-delete"}}}}
	change("rq9-file-bot", "put-user", 0, bot)
	change("rq9-file-bot-member", "set-membership", 0, access.Membership{Tenant: "tenant", User: bot.ID, Role: access.Viewer, Enabled: true})
	catalog, err = p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := catalog.User(bot.ID)
	adminCLI(0, "volume", "files", "grant", "app/data", "sfc-web-backups/", bot.ID, "--id", "folder-grant")
	// Use a separate authenticated requester; never open the running CLI's
	// wallet/journal for public reads or original-publication recovery.
	requester, err := identity.Create(filepath.Join(root, "file-recovery-requester"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(requester.Private)
	transport, err := sfcp.NewTransport(requester, admin.Cluster, func(key sfcp.Identity) (sfcp.Peer, bool) { return peer, key == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	delegated := admin
	delegated.Self, delegated.Mesh = requester, transport
	grant, err := delegated.Login(ctx, peer, bot.Username, botKey.Private)
	if err != nil {
		t.Fatal(err)
	}
	if grantRead != nil {
		grantRead(t, ctx, admin, delegated, peer, session, grant, true)
	}
	botCLI := &fixedAppNativeFixture{home: filepath.Join(root, "file-bot-home"), profile: base.profile, binary: base.binary}
	if err = os.Mkdir(botCLI.home, 0700); err != nil {
		t.Fatal(err)
	}
	botCLI.cli(t, ctx, 0, "wallet", "init")
	botCLI.cli(t, ctx, 0, "login", "--username", bot.Username, "--method", "private-key", "--key-file", filepath.Join(root, "file-bot-key", "key.pem"))
	botCLI.tenant = "tenant"
	call := func(want int, args ...string) map[string]json.RawMessage { return botCLI.cli(t, ctx, want, args...) }
	body := bytes.Repeat([]byte("rq9 authenticated finite folder bytes\n"), 2048)
	input := filepath.Join(root, "file-input.bin")
	if err = os.WriteFile(input, body, 0600); err != nil {
		t.Fatal(err)
	}
	call(0, "volume", "files", "put", "app/data", input, "sfc-web-backups/snapshot.bin", "--max-size", "131072", "--id", "delegated-put")
	listed := call(0, "volume", "files", "ls", "app/data", "sfc-web-backups/", "--id", "delegated-list")
	var entries []volumes.FileEntry
	if json.Unmarshal(listed["Entries"], &entries) != nil || len(entries) != 1 || entries[0].Path != "sfc-web-backups/snapshot.bin" {
		t.Fatal("actual delegated folder page", string(listed["Entries"]))
	}
	output := filepath.Join(root, "file-output.bin")
	call(0, "volume", "files", "get", "app/data", "sfc-web-backups/snapshot.bin", output, "--max-size", "131072", "--id", "delegated-get")
	got, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal("actual CLI digest/EOF output publication", err)
	}
	call(-1, "volume", "files", "put", "app/data", input, "outside/no.bin", "--max-size", "131072", "--id", "deny-prefix")
	call(-1, "volume", "files", "put", "app/foreign", input, "sfc-web-backups/no.bin", "--max-size", "131072", "--id", "deny-volume")
	call(2, "volume", "files", "put", "app/data", input, "sfc-web-backups/../escape", "--max-size", "131072", "--id", "deny-traversal")
	outside := filepath.Join(root, "file-outside")
	if err = os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(mount.Volume.Mountpoint, "sfc-web-backups", "link")
	if err = os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	call(-1, "volume", "files", "put", "app/data", input, "sfc-web-backups/link/escape", "--max-size", "131072", "--id", "deny-symlink")
	if _, err = os.Stat(filepath.Join(outside, "escape")); !os.IsNotExist(err) {
		t.Fatal("purpose18 followed native symlink", err)
	}
	if err = os.Remove(link); err != nil {
		t.Fatal(err)
	}
	call(0, "volume", "files", "rm", "app/data", "sfc-web-backups/snapshot.bin", "--id", "delegated-delete")
	if _, err = os.Stat(filepath.Join(mount.Volume.Mountpoint, "sfc-web-backups", "snapshot.bin")); !os.IsNotExist(err) {
		t.Fatal("actual delegated delete", err)
	}

	snapshot, err := state.Encode(read().State)
	if err != nil || bytes.Contains(snapshot, []byte("rq9 authenticated finite folder bytes")) {
		t.Fatal("file content entered shared state/history", err)
	}
	t.Log("actual delegated put/list/get/delete EOF/digest and prefix/Volume/traversal/symlink refusals; file content absent from shared state")

	// Only the original operation is accepted before the explicit native
	// post-rename/pre-completion cut, using a separate private journal.
	q := control.VolumeFileQuery{App: "app", Volume: "data", Path: "sfc-web-backups/original.bin", Method: "volume-file-put", Size: int64(len(body)), MaxBytes: 131072, Digest: sha256.Sum256(body)}
	plan, err := delegated.VolumeFilePlan(ctx, peer, grant, "tenant", q)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := control.ChangeBytes(q.Method, bot.ID, plan.Revision, plan.Change)
	if err != nil {
		t.Fatal(err)
	}
	var ch control.Change
	if err = json.Unmarshal(raw, &ch); err != nil {
		t.Fatal(err)
	}
	op, err := delegated.Prepare(ctx, peer, grant, "volume-file/original-publication", ch)
	if err != nil {
		t.Fatal(err)
	}
	journalHome := filepath.Join(root, "file-original-journal")
	if err = os.Mkdir(journalHome, 0700); err != nil {
		t.Fatal("prepare original recovery journal HOME", err)
	}
	if _, err = userauth.StageOperation(journalHome, delegated, op); err != nil {
		t.Fatal("stage exact original publication intent", err)
	}
	accepted, err := delegated.Operation(ctx, peer, op, false)
	if err != nil || accepted.Result == nil || accepted.Result.Code != state.Applied {
		t.Fatal("original delegated file acceptance", err)
	}
	if err = userauth.RecordOperationResult(journalHome, delegated, grant, op, *accepted.Result); err != nil {
		t.Fatal(err)
	}
	book, err = p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	job, ok := book.VolumeFile(control.VolumeFileID(op))
	if !ok {
		t.Fatal("accepted original file job missing")
	}
	activity, err := p.NodeActivity(read().State, job.Native.Owner.Key)
	if err != nil || activity.Resources == 0 || activity.Writers == 0 {
		t.Fatal("accepted original file effect omitted from node drain/remove blockers", activity, err)
	}
	r := *owner
	t.Cleanup(func() {
		if !t.Failed() || *owner == nil {
			return
		}
		// A known publication cut can be rolled back only by exact original
		// receipt recovery/return, never by clearing an unknown native pin.
		clean, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, e := (*owner).runVolumeFile(clean, grant, job, userauth.VolumeFileIO{Recover: true}); e != nil {
			t.Log("original file receipt remains unresolved; retaining its exact recovery root", e)
		}
	})
	r.volumeSourceMu.Lock()
	pin, err := r.nativeVolumes.Pin(ctx, volumes.NativeKey(job.Native.Spec), volumes.DataConsumerID(job.Consumer), job.Native.Generation)
	if err != nil {
		r.volumeSourceMu.Unlock()
		t.Fatal(err)
	}
	dataRoot, err := r.nativeVolumes.OpenConsumerData(ctx, job.Native, job.Consumer, pin)
	if err != nil {
		r.volumeSourceMu.Unlock()
		t.Fatal(err)
	}
	local := volumeFileOwner{Schema: 1, ID: job.ID, Scope: job.Request.Scope, Native: volumes.NativeBindingDigest(job.Native), Consumer: job.Consumer, Phase: "applying", Pin: &pin}
	if err = r.saveVolumeFile(local); err != nil {
		dataRoot.Close()
		r.volumeSourceMu.Unlock()
		t.Fatal(err)
	}
	_, err = volumes.PutFileWithPublication(ctx, dataRoot, job.Request.Path, job.ID, bytes.NewReader(body), job.Request.Size, job.Request.Digest, false, func(receipt volumes.FilePublication) error {
		if _, e := r.volumeFileWork(ctx, grant, job.ID); e != nil {
			return e
		}
		local.Publication = &receipt
		return r.saveVolumeFile(local)
	})
	closeErr := dataRoot.Close()
	r.volumeSourceMu.Unlock()
	if err != nil || closeErr != nil {
		t.Fatal("actual original staged inode publication", err, closeErr)
	}
	published := filepath.Join(mount.Volume.Mountpoint, job.Request.Path)
	inode, err := os.Stat(published)
	if err != nil || local.Publication == nil {
		t.Fatal("original publication receipt missing", err)
	}
	// This is a declared owner journal cut, not a claim that the OS crashed.
	// Applying is excluded from automatic settlement until exact receipt recovery.
	if err = r.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	*owner = nil
	*owner, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = (*owner).InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	_ = read()
	replay, err := delegated.Resume(ctx, peer, grant, op)
	if err != nil || replay.Result == nil || *replay.Result != *accepted.Result {
		t.Fatal("same original acceptance did not resume", err)
	}
	reply, err := delegated.VolumeFile(ctx, peer, grant, job, nil, nil)
	if err != nil || reply.Code != "ok" || reply.Result == nil || reply.Result.Digest != q.Digest {
		t.Fatal("purpose18 exact original receipt recovery", err)
	}
	after, err := os.Stat(published)
	if err != nil || !os.SameFile(inode, after) {
		t.Fatal("recovery recopied/replaced original published inode", err)
	}
	stored, err := userauth.LoadOperation(journalHome, delegated, grant, op.RequestID)
	if err != nil || !bytes.Equal(control.OperationBytes(stored.Operation), control.OperationBytes(op)) || !bytes.Equal(stored.Operation.Signature, op.Signature) {
		t.Fatal("file recovery changed original journal", err)
	}
	persisted, err := (*owner).reports.GetBounded("volume/file/"+job.ID, 128<<10)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := schema.Decode[volumeFileOwner](persisted)
	if err != nil || receipt.Phase != "returned" || receipt.Publication == nil || *receipt.Publication != *local.Publication {
		t.Fatal("original owner receipt not retained", err)
	}
	wait("original publication writer/native pin return", func() bool {
		v, e := p.Volumes(read().State)
		if e != nil {
			return false
		}
		j, ok := v.VolumeFile(job.ID)
		if !ok || j.Phase != "Completed" {
			return false
		}
		native, e := (*owner).nativeVolumes.View(pin.Key)
		_, held := native.Consumers[pin.Consumer]
		return e == nil && !held
	})
	call(0, "volume", "files", "rm", "app/data", job.Request.Path, "--id", "delete-recovered")
	adminCLI(0, "volume", "files", "revoke", "app/data", "sfc-web-backups/", bot.ID, "--id", "folder-revoke")
	if grantRead != nil {
		grantRead(t, ctx, admin, delegated, peer, session, grant, false)
	}
	call(-1, "volume", "files", "ls", "app/data", "sfc-web-backups/", "--id", "deny-revoked")
	catalog, err = p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	afterUser, _ := catalog.User(bot.ID)
	if before.Revision != afterUser.Revision || len(catalog.VolumeFileGrants("tenant", bot.ID, "app", "data")) != 0 {
		t.Fatal("folder grant/revoke changed credential or retained authority")
	}
	if original, err := os.ReadFile(filepath.Join(mount.Volume.Mountpoint, "marker")); err != nil || string(original) != "volume-original" {
		t.Fatal("delegated file operations damaged original app data", err)
	}
}
