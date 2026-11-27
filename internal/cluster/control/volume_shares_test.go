// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// A Volume's remote setting is one record changed against its own revision;
// off removes it, and only a Volume that exists at that generation can have
// one.
func TestVolumeRemoteSettingRevisionAndDelta(t *testing.T) {
	f := newBackupCore(t)
	shares := func() VolumeShares {
		t.Helper()
		b, err := f.p.VolumeShares(f.s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if _, ok := shares().Share(f.scope); ok {
		t.Fatal("share before any change")
	}
	f.apply("remote-off-missing", "set-volume-remote", 0, VolumeRemoteChange{Volume: f.scope, Mode: VolumeRemoteOff}, state.ConditionFailed)
	f.apply("remote-bad-mode", "set-volume-remote", 0, VolumeRemoteChange{Volume: f.scope, Mode: "everyone"}, state.Invalid)
	stale := f.scope
	stale.Generation++
	f.apply("remote-other-generation", "set-volume-remote", 0, VolumeRemoteChange{Volume: stale, Mode: VolumeRemoteShared}, state.Invalid)
	missing := f.scope
	missing.ID = "missing"
	f.apply("remote-missing", "set-volume-remote", 0, VolumeRemoteChange{Volume: missing, Mode: VolumeRemoteShared}, state.Invalid)

	f.apply("remote-on", "set-volume-remote", 0, VolumeRemoteChange{Volume: f.scope, Mode: VolumeRemoteSingleWriter}, state.Applied)
	r, ok := shares().Share(f.scope)
	if !ok || r.Mode != VolumeRemoteSingleWriter || r.Revision != 1 || r.Origin.Session.User != "admin" {
		t.Fatalf("share = %+v %v", r, ok)
	}
	if _, ok := shares().Share(stale); ok {
		t.Fatal("share applies to another generation")
	}
	f.apply("remote-stale-view", "set-volume-remote", 0, VolumeRemoteChange{Volume: f.scope, Mode: VolumeRemoteShared}, state.ConditionFailed)
	f.apply("remote-same", "set-volume-remote", 1, VolumeRemoteChange{Volume: f.scope, Mode: VolumeRemoteSingleWriter}, state.ConditionFailed)
	f.apply("remote-shared", "set-volume-remote", 1, VolumeRemoteChange{Volume: f.scope, Mode: VolumeRemoteShared}, state.Applied)
	if r, _ := shares().Share(f.scope); r.Mode != VolumeRemoteShared || r.Revision != 2 {
		t.Fatalf("share after change = %+v", r)
	}

	raw, _ := state.Encode(f.s)
	restored, err := state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := f.p.VolumeShares(restored); err != nil || len(b.Records) != 1 {
		t.Fatal("snapshot lost the share", err)
	}

	f.apply("remote-off", "set-volume-remote", 2, VolumeRemoteChange{Volume: f.scope, Mode: VolumeRemoteOff}, state.Applied)
	if b := shares(); len(b.Records) != 0 || b.Revision != 3 {
		t.Fatalf("off kept a record: %+v", b)
	}
}

// remoteConsumerCore is moveCore with a shared record and one remote writer
// on node-b.
func remoteConsumerCore(t *testing.T) (*backupCoreFixture, volumes.Consumer, [32]byte) {
	t.Helper()
	f, _ := moveCore(t)
	f.apply("remote-on", "set-volume-remote", 0, VolumeRemoteChange{Volume: f.scope, Mode: VolumeRemoteShared}, state.Applied)
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	runner := [32]byte(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{124}, 32)).Public().(ed25519.PublicKey))
	v := f.view()
	e := v.entries[volumeKey(f.scope)]
	var writer volumes.Consumer
	e.State, writer, err = e.State.AcquireShared(c, "admin", e.State.Revision(), "remote-task", 1, true, volumes.ShareShared, volumes.Owner{Node: "node-b", Key: runner})
	if err != nil {
		t.Fatal(err)
	}
	e.Grants = append(e.Grants, volumeGrant{Consumer: writer, Principal: "admin"})
	v.entries[volumeKey(f.scope)] = e
	writes, code := f.p.volumeCheckpoint(f.s, v)
	if code != state.Applied {
		t.Fatal(code)
	}
	var result state.Result
	f.s, result, err = state.ApplyReduced(f.s, f.s.Index()+1, state.Command{Kind: state.Module, Actor: "anchor", Epoch: f.s.ModuleEpoch(), RequestID: "remote-consumer-fixture", Key: VolumesKey, Expected: f.s.Object(VolumesKey).Revision, Value: "fixture"}, f.p.Validate, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil || result.Code != state.Applied {
		t.Fatal(result.Code, err)
	}
	return f, writer, runner
}

// The home lets only the remote consumer's current runner mount, only from
// the owner, and only while the exact share record stays.
func TestVolumeRemoteGrantNamesTheRunner(t *testing.T) {
	f, writer, runner := remoteConsumerCore(t)
	home := [32]byte(f.node.Public().(ed25519.PublicKey))
	got, native, err := f.p.VolumeRemoteGrant(f.s, home, runner, f.scope, writer.ID)
	if err != nil || got != writer || !got.Writable || native.Spec.Scope != f.scope {
		t.Fatal("runner refused", got, err)
	}
	stale := f.scope
	stale.Generation++
	for name, try := range map[string]func() error{
		"home as peer":     func() error { _, _, e := f.p.VolumeRemoteGrant(f.s, home, home, f.scope, writer.ID); return e },
		"runner as home":   func() error { _, _, e := f.p.VolumeRemoteGrant(f.s, runner, runner, f.scope, writer.ID); return e },
		"other consumer":   func() error { _, _, e := f.p.VolumeRemoteGrant(f.s, home, runner, f.scope, "other"); return e },
		"other generation": func() error { _, _, e := f.p.VolumeRemoteGrant(f.s, home, runner, stale, writer.ID); return e },
	} {
		if try() == nil {
			t.Fatal(name, "granted")
		}
	}
	request := volumes.StartRequest{Scope: f.scope, Consumer: writer, Boot: [32]byte{1}, Challenge: [32]byte{2}, Sequence: 1}
	if _, err := f.p.VolumePermit(f.s, runner, request); err != nil {
		t.Fatal("runner start permit", err)
	}
	if _, err := f.p.VolumePermit(f.s, home, request); err == nil {
		t.Fatal("home started a remote consumer")
	}
	f.apply("remote-off", "set-volume-remote", 1, VolumeRemoteChange{Volume: f.scope, Mode: VolumeRemoteOff}, state.Applied)
	if _, _, err := f.p.VolumeRemoteGrant(f.s, home, runner, f.scope, writer.ID); err == nil {
		t.Fatal("granted without a share record")
	}
	if _, err := f.p.VolumePermit(f.s, runner, request); err == nil {
		t.Fatal("start permit without a share record")
	}
}
