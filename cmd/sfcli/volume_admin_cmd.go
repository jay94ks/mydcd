// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/userauth"
)

// Space limits a system administrator sets: backup space per server (for
// the cluster or one tenant) and the reserved size of one volume.

// syncChange sends a change that the server finishes when it applies it.
func (g *globals) syncChange(c *cli.Context, s *session, f *changeFlags, summary, action string, expected uint64, payload any) error {
	id := f.id.Get()
	expected = f.expect(expected)
	// Running the command again with the same ID continues the saved change,
	// whose revision was read before the first send.
	if old, err := userauth.LoadOperation(s.Home, s.Client, s.Stored.Session, id); err == nil && old.Operation.Change.Action == action {
		expected = old.Operation.Change.Expected
	}
	if err := sendResult(g.send(c, s, change{Summary: summary, ID: id, Action: action, Expected: expected, Payload: payload})); err != nil {
		return err
	}
	fmt.Fprintf(c.Err, "Done as operation %s.\n", id)
	return nil
}

// node and all are the options of the parent `limits` command.
func volumeBackupLimitsSetCommand(g *globals, nodeFlag *string, allFlag *bool) *cli.Command {
	var f changeFlags
	var maxSize, stagingSize, volumeSize cli.Size
	var maxBackups, stagingBackups, volumeCount uint
	return &cli.Command{
		Name:  "set",
		Short: "Set the backup space of one server (system administrator)",
		Long: `Sets how much backup space the tenant (or, with --all, the whole cluster)
may reserve on the server given with --node. Options left out keep their current value.
--volume-size and --volumes also limit the space new volumes reserve on
that server; once set they cannot be removed, only changed.`,
		Flags: func(fs *flag.FlagSet) {
			f.register(fs, false, true)
			fs.Var(&maxSize, "max-size", "backup space, such as 100GiB")
			fs.UintVar(&maxBackups, "max-backups", 0, "number of `backups` kept")
			fs.Var(&stagingSize, "staging-size", "space for backups and restores in progress")
			fs.UintVar(&stagingBackups, "staging-backups", 0, "backups and restores in progress at once")
			fs.Var(&volumeSize, "volume-size", "space all volumes on the server may reserve")
			fs.UintVar(&volumeCount, "volumes", 0, "number of volumes on the server")
		},
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("limits set takes no arguments")
			}
			node, all := *nodeFlag, *allFlag
			if node == "" {
				return cli.Usagef("limits set needs --node")
			}
			set := map[string]bool{}
			c.Flags.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
			if maxBackups > 256 || stagingBackups > 256 {
				return cli.Usagef("--max-backups and --staging-backups are at most 256")
			}
			if volumeCount > 1<<20 {
				return cli.Usagef("--volumes is too large")
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			tenant := ""
			if !all {
				if tenant, err = g.Tenant(s, true); err != nil {
					return err
				}
			}
			ctx, cancel := g.Deadline(c)
			rows, err := readPublicRows(ctx, s, "volume-backup-limits", tenant, control.PublicReadQuery{Node: node})
			cancel()
			if err != nil {
				return err
			}
			var old control.PublicBackupLimit
			for _, r := range rows {
				if r.BackupLimit != nil && r.BackupLimit.Tenant == tenant && r.BackupLimit.Node == node {
					old = *r.BackupLimit
				}
			}
			limit := control.VolumeBackupLimit{Tenant: tenant, Node: node, Bytes: old.Bytes, Count: old.Count, StagingBytes: old.StagingBytes, StagingCount: old.StagingCount, Original: old.Original}
			if set["max-size"] {
				limit.Bytes = uint64(maxSize)
			}
			if set["max-backups"] {
				limit.Count = uint32(maxBackups)
			}
			if set["staging-size"] {
				limit.StagingBytes = uint64(stagingSize)
			}
			if set["staging-backups"] {
				limit.StagingCount = uint32(stagingBackups)
			}
			if set["volume-size"] || set["volumes"] {
				o := control.OriginalVolumeLimit{}
				if limit.Original != nil {
					o = *limit.Original
				}
				if set["volume-size"] {
					o.Bytes = uint64(volumeSize)
				}
				if set["volumes"] {
					o.Count = uint32(volumeCount)
				}
				limit.Original = &o
			}
			who := "tenant " + tenant
			if tenant == "" {
				who = "the cluster"
			}
			impact := fmt.Sprintf("Set backup space for %s on %s: %s in %d backups, %s in %d at once while in progress.", who, node, cli.Size(limit.Bytes), limit.Count, cli.Size(limit.StagingBytes), limit.StagingCount)
			if limit.Original != nil {
				impact += fmt.Sprintf(" Volumes: %s in %d.", cli.Size(limit.Original.Bytes), limit.Original.Count)
			}
			ok, err := g.confirm(c, &f, impact)
			if !ok || err != nil {
				return err
			}
			summary := "volume backup limits set --node " + node
			if tenant == "" {
				summary += " --all"
			} else {
				summary += " --tenant " + tenant
			}
			return g.syncChange(c, s, &f, summary, "set-volume-backup-limit", old.Revision, limit)
		},
	}
}

func volumeResizeCommand(g *globals) *cli.Command {
	var f changeFlags
	var size cli.Size
	return &cli.Command{
		Name:  "resize",
		Args:  "APP/VOLUME",
		Short: "Reserve more space for a volume (system administrator)",
		Long: `Raises the space a volume reserves on its server. The size only grows.
It is a reservation the cluster counts against the server's volume
space, not a filesystem quota.`,
		Flags: func(fs *flag.FlagSet) {
			f.register(fs, false, true)
			fs.Var(&size, "size", "new reserved space, such as 20GiB (up to 1TiB)")
		},
		Run: func(c *cli.Context, args []string) error {
			ref, err := volumeArg(args, 1, "resize needs one volume name", false)
			if err != nil {
				return err
			}
			if size == 0 || size > 1<<40 {
				return cli.Usagef("resize needs --size up to 1TiB")
			}
			s, tenant, err := g.volumeSession(c, args, 1, "resize needs one volume name")
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			v, _, err := findVolumeView(ctx, s, tenant, ref)
			cancel()
			if err != nil {
				return err
			}
			if uint64(size) <= v.CapacityBytes {
				return fmt.Errorf("volume %s already reserves %s; the size only grows", ref, cli.Size(v.CapacityBytes))
			}
			ok, err := g.confirm(c, &f, fmt.Sprintf("Reserve %s for volume %s on %s (now %s).", size, ref, v.Owner.Node, volumeSizeText(v.CapacityBytes)))
			if !ok || err != nil {
				return err
			}
			return g.syncChange(c, s, &f, "volume resize "+ref.String(), "set-volume-capacity", v.Revision, control.VolumeCapacity{Scope: v.Scope, Native: v.NativeBinding, Bytes: uint64(size)})
		},
	}
}
