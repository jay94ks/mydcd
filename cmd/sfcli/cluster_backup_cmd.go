// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/clusterbackup"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/userauth"
)

// clusterBackupCommand is `sfcli cluster backup`: the cluster state and the
// cluster master key, out of the cluster, in one encrypted file.
func clusterBackupCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "backup",
		Short: "Back up the cluster state and master key to a file (system administrator)",
		Sub: []*cli.Command{
			clusterBackupCreateCommand(g),
			clusterBackupVerifyCommand(g),
			clusterBackupKeygenCommand(g),
		},
	}
}

type backupKeyFlags struct{ keyFile, passwordFile string }

func (f *backupKeyFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.keyFile, "backup-key-file", "", "backup key `file` (32 bytes or 64 hex digits, mode 0600)")
	fs.StringVar(&f.passwordFile, "backup-password-file", "", "read the backup password from this `file` (mode 0600) instead of the terminal")
}

// readPrivateFile reads a small regular file no wider than mode 0600.
func readPrivateFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o177 != 0 {
		return nil, fmt.Errorf("%s must be a regular file with mode 0600", path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return os.ReadFile(path)
}

// key reads the backup key: a key file, a password file, or a password
// typed on the terminal (twice when making a backup).
func (f *backupKeyFlags) key(g *globals, c *cli.Context, confirm bool) (clusterbackup.Key, error) {
	switch {
	case f.keyFile != "" && f.passwordFile != "":
		return clusterbackup.Key{}, cli.Usagef("give --backup-key-file or --backup-password-file, not both")
	case f.keyFile != "":
		raw, err := readPrivateFile(f.keyFile, 130)
		if err != nil {
			return clusterbackup.Key{}, err
		}
		defer clear(raw)
		return clusterbackup.KeyFromFile(raw)
	case f.passwordFile != "":
		raw, err := readPrivateFile(f.passwordFile, 1025)
		if err != nil {
			return clusterbackup.Key{}, err
		}
		defer clear(raw)
		value := bytes.TrimSuffix(raw, []byte{'\n'})
		if bytes.ContainsAny(value, "\r\n\x00") {
			return clusterbackup.Key{}, errors.New("the backup password file must hold one line")
		}
		return clusterbackup.KeyFromPassword(value)
	}
	if g.noInput || nonInteractiveEnv() {
		return clusterbackup.Key{}, cli.Usagef("give --backup-key-file or --backup-password-file when not asking on the terminal")
	}
	first, err := promptBackupPassword(c, "Backup password")
	if err != nil {
		return clusterbackup.Key{}, err
	}
	defer clear(first)
	if confirm {
		again, err := promptBackupPassword(c, "Again")
		if err != nil {
			return clusterbackup.Key{}, err
		}
		defer clear(again)
		if subtle.ConstantTimeCompare(first, again) != 1 {
			return clusterbackup.Key{}, errors.New("the passwords do not match")
		}
	}
	return clusterbackup.KeyFromPassword(first)
}

func promptBackupPassword(c *cli.Context, label string) ([]byte, error) {
	tty, err := openPromptTerminal()
	if err != nil {
		return nil, errors.New("the backup password needs a terminal; give --backup-key-file or --backup-password-file")
	}
	defer tty.Close()
	fmt.Fprint(c.Err, label+": ")
	value, err := identity.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(c.Err)
	if err != nil || bytes.ContainsAny(value, "\r\n\x00") {
		clear(value)
		return nil, errors.New("could not read the backup password")
	}
	return value, nil
}

func clusterBackupCreateCommand(g *globals) *cli.Command {
	var keys backupKeyFlags
	var out string
	var id cli.IDFlag
	return &cli.Command{
		Name:  "create",
		Short: "Write a cluster backup file",
		Long: `Asks a voter for the cluster state and the cluster master key and writes
them to --out, encrypted with the backup key. The backup key never leaves
this computer: the voter seals the master key to a one-time key made for this
backup, and this command encrypts the whole file.

The request is recorded as a cluster-backup operation (who and when). If the
server you are connected to is not a voter, it passes the request to the
leader. Run it from cron or a systemd timer with SFC_NONINTERACTIVE=1,
SFC_WALLET_PASSWORD_FILE and --backup-key-file.

Keep the backup key and the file outside the cluster. Anyone with both can
read every certificate key and stored credential of the cluster.`,
		Flags: func(fs *flag.FlagSet) {
			keys.register(fs)
			fs.StringVar(&out, "out", "", "backup `file` to write (must not exist)")
			fs.Var(&id, "id", "operation `id` to use instead of a new one")
		},
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("create takes no arguments")
			}
			if out == "" {
				return cli.Usagef("give --out")
			}
			if _, err := os.Lstat(out); err == nil {
				return fmt.Errorf("%s already exists", out)
			}
			operation, err := operationID(id.Get())
			if err != nil {
				return err
			}
			key, err := keys.key(g, c, true)
			if err != nil {
				return err
			}
			defer key.Clear()
			recipient, err := clusterbackup.NewRecipient()
			if err != nil {
				return err
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			if _, err := g.send(c, s, change{Summary: "cluster backup create", ID: operation, Action: "cluster-backup",
				Payload: control.ClusterBackupChange{Operation: operation, Recipient: recipient.Public()}}); err != nil {
				return unknown(err)
			}
			g.settle(operation, cli.Done, "recorded")
			m, err := writeClusterBackup(c, s, out, operation, key, recipient)
			if err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "wrote %s\n", out)
			return printBackupManifest(c, g, m)
		},
	}
}

// writeClusterBackup fetches the backup into a hidden file next to out and
// renames it to out only once the whole file is written and verified.
func writeClusterBackup(c *cli.Context, s *session, out, operation string, key clusterbackup.Key, recipient clusterbackup.Recipient) (clusterbackup.Manifest, error) {
	dir, name := filepath.Split(out)
	if dir == "" {
		dir = "."
	}
	f, err := os.CreateTemp(dir, "."+name+".partial-*")
	if err != nil {
		return clusterbackup.Manifest{}, err
	}
	partial := f.Name()
	defer os.Remove(partial)
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		return clusterbackup.Manifest{}, err
	}
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	started := false
	ready := func(r userauth.ClusterBackupReply) error {
		master, err := recipient.Open(r.Manifest.Cluster, operation, *r.Master)
		if err != nil {
			return err
		}
		if clusterbackup.MasterCheck(r.Manifest.Cluster, master) != r.Manifest.MasterCheck {
			clear(master)
			return errors.New("the voter's master key does not match its manifest")
		}
		contents := clusterbackup.Contents{Manifest: *r.Manifest, Signature: r.Signature, Master: master}
		started = true
		go func() {
			err := clusterbackup.Write(f, key, contents, pr)
			clear(master)
			_ = pr.CloseWithError(err)
			done <- err
		}()
		return nil
	}
	ctx, cancel := context.WithTimeout(c.Ctx, time.Duration(control.ClusterBackupWindow)*time.Second)
	defer cancel()
	_, err = s.Client.ClusterBackup(ctx, s.Target, s.Stored.Session, operation, ready, pw)
	_ = pw.CloseWithError(err)
	if started {
		// Wait for the file writer even after a failed transfer, so it no
		// longer touches the file.
		if werr := <-done; err == nil {
			err = werr
		}
	}
	if err != nil {
		return clusterbackup.Manifest{}, err
	}
	if err := f.Sync(); err != nil {
		return clusterbackup.Manifest{}, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return clusterbackup.Manifest{}, err
	}
	m, err := clusterbackup.Verify(f, key)
	if err != nil {
		return clusterbackup.Manifest{}, fmt.Errorf("the written backup does not verify: %w", err)
	}
	if err := f.Close(); err != nil {
		return clusterbackup.Manifest{}, err
	}
	if _, err := os.Lstat(out); err == nil {
		return clusterbackup.Manifest{}, fmt.Errorf("%s already exists", out)
	}
	if err := os.Rename(partial, out); err != nil {
		return clusterbackup.Manifest{}, err
	}
	return m, nil
}

func clusterBackupVerifyCommand(g *globals) *cli.Command {
	var keys backupKeyFlags
	return &cli.Command{
		Name:  "verify",
		Short: "Check a cluster backup file without a cluster",
		Long: `Decrypts the whole file and checks the voter's signature, the snapshot's
cluster, digest and contents, and the master key. It needs no server.`,
		Flags: func(fs *flag.FlagSet) { keys.register(fs) },
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("verify takes the backup file")
			}
			key, err := keys.key(g, c, false)
			if err != nil {
				return err
			}
			defer key.Clear()
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			m, err := clusterbackup.Verify(f, key)
			if err != nil {
				return errors.New("the backup does not verify: wrong backup key, or the file is damaged")
			}
			fmt.Fprintln(c.Err, "ok")
			return printBackupManifest(c, g, m)
		},
	}
}

func clusterBackupKeygenCommand(g *globals) *cli.Command {
	var out string
	return &cli.Command{
		Name:  "keygen",
		Short: "Make a new backup key file",
		Long:  `Writes 32 random bytes as hex to --out with mode 0600. Keep a copy outside the cluster.`,
		Flags: func(fs *flag.FlagSet) { fs.StringVar(&out, "out", "", "key `file` to write (must not exist)") },
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 0 || out == "" {
				return cli.Usagef("keygen takes --out and no arguments")
			}
			raw, err := clusterbackup.NewKeyFile()
			if err != nil {
				return err
			}
			defer clear(raw)
			f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return err
			}
			if _, err := f.Write(raw); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "wrote %s\n", out)
			return nil
		},
	}
}

func printBackupManifest(c *cli.Context, g *globals, m clusterbackup.Manifest) error {
	return cli.Print(c.Out, g.output.Format(), m, func() cli.Rows {
		t := cli.Rows{Header: []string{"field", "value"}}
		t.Add("cluster", hex.EncodeToString(m.Cluster[:]))
		t.Add("created", time.Unix(m.CreatedAt, 0).Local().Format("2006-01-02 15:04:05"))
		t.Add("by", m.User)
		t.Add("voter", m.Voter)
		t.Add("version", m.Version)
		t.Add("raft index", m.RaftIndex)
		t.Add("term", m.Term)
		t.Add("members", len(m.Members))
		t.Add("snapshot bytes", m.SnapshotSize)
		return t
	})
}
