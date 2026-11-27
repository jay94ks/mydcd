// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/app"
	"github.com/jay94ks/seafield/internal/clusterbackup"
	"github.com/jay94ks/seafield/internal/config"
)

// runRestore is `sfcd restore` (design B4): after every voter was lost, a
// new server rebuilds the cluster from a `sfcli cluster backup` file and
// becomes its only voter. The other servers join it again afterwards.
func runRestore(args []string, globalConfig string, in io.Reader, out, diagnostic io.Writer) int {
	f := flag.NewFlagSet("sfcd restore", flag.ContinueOnError)
	f.SetOutput(diagnostic)
	file := onceString{value: globalConfig, set: globalConfig != ""}
	var backup, keyFile, passwordFile, request, confirm onceString
	f.Var(&file, "config", "managed node YAML file of the new server")
	f.Var(&backup, "backup", "cluster backup file (.sfcbak)")
	f.Var(&keyFile, "backup-key-file", "backup key file (32 bytes or 64 hex digits, mode 0600)")
	f.Var(&passwordFile, "backup-password-file", "file holding the backup password (mode 0600)")
	f.Var(&request, "request-id", "restore operation ID, recorded in the cluster")
	f.Var(&confirm, "confirm-cluster", "the first 8 hex digits of the backup's cluster ID (needed without a terminal)")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return fail(diagnostic, err, 2)
	}
	if f.NArg() != 0 || file.value == "" || backup.value == "" || request.value == "" {
		return fail(diagnostic, errors.New("restore requires --config, --backup and --request-id"), 2)
	}
	key, err := restoreKey(keyFile.value, passwordFile.value)
	if err != nil {
		return fail(diagnostic, err, 2)
	}
	defer key.Clear()
	c, err := config.LoadNode(file.value)
	if err != nil {
		return fail(diagnostic, err, 2)
	}
	source, err := os.Open(backup.value)
	if err != nil {
		return fail(diagnostic, err, 1)
	}
	b, err := app.ReadRestoreBackup(source, key)
	source.Close()
	if err != nil {
		return fail(diagnostic, fmt.Errorf("the backup does not open with this key or is damaged: %w", err), 1)
	}
	defer b.Clear()
	m := b.Manifest
	cluster := hex.EncodeToString(m.Cluster[:])
	fmt.Fprintf(diagnostic, "Cluster %s\n", cluster)
	fmt.Fprintf(diagnostic, "Backup %s by %s from %s at %s (state index %d, Raft index %d)\n", m.Operation, m.User, m.Voter, time.Unix(m.CreatedAt, 0).UTC().Format(time.RFC3339), m.Index, m.RaftIndex)
	fmt.Fprintf(diagnostic, "Servers in the backup, all retired by this restore: %s\n", strings.Join(b.Lost, ", "))
	fmt.Fprintf(diagnostic, "This server becomes the only voter: %s %s (restore generation %d)\n", c.Node.ID, c.Node.Listen, b.Generation)
	fmt.Fprintln(diagnostic, "Restore only when every voter of this cluster is lost for good, and on ONE server only. A server of the old cluster must not run again with its old state.")
	if confirm.value == "" {
		if nonInteractive() {
			return fail(diagnostic, errors.New("without a terminal give --confirm-cluster with the first 8 hex digits of the cluster ID shown above"), 2)
		}
		fmt.Fprintf(diagnostic, "Type the first 8 hex digits of the cluster ID (%s) to confirm: ", cluster[:8])
		line, _ := bufio.NewReader(in).ReadString('\n')
		confirm.value = strings.TrimSpace(line)
	}
	if strings.ToLower(confirm.value) != cluster[:8] {
		return fail(diagnostic, errors.New("not confirmed"), 1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	restored, err := app.Restore(ctx, c, b, request.value, time.Now())
	if err != nil {
		return fail(diagnostic, err, 1)
	}
	root := restored.Installation.Root
	fmt.Fprintf(out, "Restored cluster %s on %s at Raft index %d. Start sfcd, then trust this server's key in the CLI context (sfcli context trust) and join the other servers again.\n", cluster, root.Self.ID, root.Installed.Index)
	return 0
}

func restoreKey(keyFile, passwordFile string) (clusterbackup.Key, error) {
	switch {
	case keyFile != "" && passwordFile != "":
		return clusterbackup.Key{}, errors.New("give --backup-key-file or --backup-password-file, not both")
	case keyFile != "":
		raw, err := readPrivateFile(keyFile, 130)
		if err != nil {
			return clusterbackup.Key{}, err
		}
		defer clear(raw)
		return clusterbackup.KeyFromFile(raw)
	case passwordFile != "":
		raw, err := readPrivateFile(passwordFile, 1025)
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
	return clusterbackup.Key{}, errors.New("restore requires --backup-key-file or --backup-password-file")
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
