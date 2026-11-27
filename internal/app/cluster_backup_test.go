// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/clusterbackup"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/userauth"
)

// backupFile fetches the backup of operation from peer i into an encrypted
// file, as `sfcli cluster backup create` does.
func backupFile(t *testing.T, ctx context.Context, m *managedVoters, i int, operation string, recipient clusterbackup.Recipient, key clusterbackup.Key) ([]byte, error) {
	t.Helper()
	var file bytes.Buffer
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	started := false
	_, err := m.client.ClusterBackup(ctx, m.Peer(i), m.session, operation, func(r userauth.ClusterBackupReply) error {
		master, err := recipient.Open(r.Manifest.Cluster, operation, *r.Master)
		if err != nil {
			return err
		}
		started = true
		go func() {
			err := clusterbackup.Write(&file, key, clusterbackup.Contents{Manifest: *r.Manifest, Signature: r.Signature, Master: master}, pr)
			_ = pr.CloseWithError(err)
			done <- err
		}()
		return nil
	}, pw)
	_ = pw.CloseWithError(err)
	if started {
		if werr := <-done; err == nil {
			err = werr
		}
	}
	return file.Bytes(), err
}

// A recorded cluster-backup operation lets the administrator fetch the
// state and master key from any voter, and through a non-voter, which
// passes the request to the leader. The file verifies without a cluster,
// and its snapshot is the cluster's own state.
func TestClusterBackupFromEveryMember(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	admin, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	m := newManagedMembers(t, ctx, t.TempDir(), admin, 3, 2)
	key, _ := clusterbackup.KeyFromFile(bytes.Repeat([]byte{3}, 32))
	recipient, err := clusterbackup.NewRecipient()
	if err != nil {
		t.Fatal(err)
	}

	// Without a record no voter sends anything.
	if _, err := backupFile(t, ctx, m, 0, "backup-missing", recipient, key); !denied(err) {
		t.Fatal("unrecorded backup:", err)
	}
	m.Change(0, "backup-1", "cluster-backup", 0, control.ClusterBackupChange{Operation: "backup-1", Recipient: recipient.Public()})

	var masters [][]byte
	for i := range m.Nodes {
		file, err := backupFile(t, ctx, m, i, "backup-1", recipient, key)
		if err != nil {
			t.Fatal("backup from", i, err)
		}
		manifest, err := clusterbackup.Verify(bytes.NewReader(file), key)
		if err != nil {
			t.Fatal("verify", i, err)
		}
		voter := m.Configs[i].Node.ID
		if i >= 2 {
			voter = m.Configs[0].Node.ID // a non-voter hands the request to the leader
		}
		if manifest.Cluster != m.Cluster || manifest.Operation != "backup-1" || manifest.User != "admin" || manifest.Voter != voter || len(manifest.Members) != 3 {
			t.Fatalf("manifest from %d: %+v", i, manifest)
		}
		c, snapshot, err := clusterbackup.Open(bytes.NewReader(file), key)
		if err != nil {
			t.Fatal(err)
		}
		_, s, err := cluster.ReadSnapshot(m.Cluster, snapshot)
		if err != nil {
			t.Fatal(err)
		}
		records, err := m.Policy.ClusterBackups(s)
		if err != nil {
			t.Fatal(err)
		}
		// The backup's own record is in the state it holds.
		if _, ok := records.Record("backup-1"); !ok {
			t.Fatal("backup record missing from its snapshot", i)
		}
		masters = append(masters, c.Master)
	}
	if !bytes.Equal(masters[0], masters[1]) || !bytes.Equal(masters[0], masters[2]) {
		t.Fatal("voters sent different master keys")
	}

	// Another one-time key cannot open what was sealed for this one.
	other, _ := clusterbackup.NewRecipient()
	if _, err := backupFile(t, ctx, m, 1, "backup-1", other, key); err == nil {
		t.Fatal("other recipient opened the master key")
	}
	if _, err := clusterbackup.Verify(bytes.NewReader([]byte("not a backup")), key); err == nil {
		t.Fatal("garbage verified")
	}
}

func denied(err error) bool {
	var e *userauth.Error
	return errors.As(err, &e) && e.Code == "denied"
}
