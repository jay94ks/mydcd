// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func volumeBackupCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "backup",
		Short: "Back up volumes and manage their backups",
		Long: `A backup is a file copy of a volume, kept on the volume's server. It is
not a database dump: stop or quiesce the app first if its files must agree.`,
		Sub: []*cli.Command{
			volumeBackupCreateCommand(g),
			volumeBackupListCommand(g),
			volumeBackupShowCommand(g),
			volumeBackupCancelCommand(g),
			volumeBackupDeleteCommand(g),
			volumeBackupLimitsCommand(g),
		},
	}
}

func readVolumeBackups(ctx context.Context, s *session, tenant string) ([]control.VolumeBackupView, error) {
	var out []control.VolumeBackupView
	after := ""
	var root uint64
	for {
		reply, err := s.Client.VolumeBackupPage(ctx, s.Target, s.Stored.Session, tenant, after)
		if err != nil {
			return nil, err
		}
		if root != 0 && root != reply.RootRevision {
			return nil, errors.New("the backup list changed while it was read; try again")
		}
		root = reply.RootRevision
		last := after
		for _, b := range reply.Items {
			if b.Scope.Cluster != s.Client.Cluster || b.Scope.Tenant != tenant || b.Key <= last || len(out) >= 4096 {
				return nil, sfcp.ErrAdmission
			}
			out = append(out, b)
			last = b.Key
		}
		if reply.Next == "" {
			return out, nil
		}
		if last == after || reply.Next != last {
			return nil, sfcp.ErrAdmission
		}
		after = last
	}
}

func findVolumeBackupView(ctx context.Context, s *session, tenant string, ref volumeRef, name string) (control.VolumeBackupView, error) {
	all, err := readVolumeBackups(ctx, s, tenant)
	if err != nil {
		return control.VolumeBackupView{}, err
	}
	for _, b := range all {
		if ref.is(b.Scope) && b.ID == name {
			return b, nil
		}
	}
	return control.VolumeBackupView{}, fmt.Errorf("backup %s of %s not found", name, ref)
}

// backupName checks a backup or restore name given on the command line.
func backupName(kind, s string) error {
	if !lifecycle.ValidID(s) || len(s) > 61 {
		return cli.Usagef("%q is not a %s name (lower-case letters, digits and '-', starting with a letter)", s, kind)
	}
	return nil
}

func volumeBackupCreateCommand(g *globals) *cli.Command {
	var f changeFlags
	var name string
	var maxSize cli.Size
	var maxEntries uint
	return &cli.Command{
		Name:  "create",
		Args:  "APP/VOLUME",
		Short: "Back up a volume",
		Long: `Copies the volume's files into a backup on the same server. --max-size
reserves space for the copy, including archive overhead; the backup fails
if the files do not fit.`,
		Flags: func(fs *flag.FlagSet) {
			f.register(fs, true, true)
			fs.StringVar(&name, "name", "", "backup `name` (default: b-DATE-TIME)")
			fs.Var(&maxSize, "max-size", "space to reserve for the copy, such as 10GiB (1KiB..1TiB)")
			fs.UintVar(&maxEntries, "max-entries", 100000, "most files and directories to copy (1..100000)")
		},
		Run: func(c *cli.Context, args []string) error {
			ref, err := volumeArg(args, 1, "backup create needs one volume name APP/VOLUME", true)
			if err != nil {
				return err
			}
			if name == "" {
				name = "b-" + time.Now().UTC().Format("20060102-150405")
			}
			if err = backupName("backup", name); err != nil {
				return err
			}
			if maxSize < 1024 || maxSize > 1<<40 || maxEntries == 0 || maxEntries > 100000 {
				return cli.Usagef("--max-size (1KiB..1TiB) is required; --max-entries is 1..100000")
			}
			s, tenant, err := g.volumeSession(c, args, 1, "backup create needs one volume name APP/VOLUME")
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			reply, err := s.Client.VolumeBackupSource(ctx, s.Target, s.Stored.Session, tenant, ref.selector())
			cancel()
			if err != nil {
				return err
			}
			source := reply.Source
			q := control.VolumeBackupBegin{Scope: source.Scope, ID: name, MaxBytes: uint64(maxSize), MaxEntries: uint32(maxEntries), Compatibility: source.Compatibility}
			ok, err := g.confirm(c, &f, fmt.Sprintf("Back up volume %s as %s (up to %s, %d files).", ref, name, maxSize, maxEntries))
			if !ok || err != nil {
				return err
			}
			return g.volumeChange(c, s, &f, "volume backup create "+ref.String()+" "+name, "begin-volume-backup", reply.VolumeRevision, reply.ModuleEpoch, q)
		},
	}
}

func volumeBackupListCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "list",
		Args:  "[APP/VOLUME]",
		Short: "List backups, of one volume or of the whole tenant",
		Run: func(c *cli.Context, args []string) error {
			if len(args) > 1 {
				return cli.Usagef("list takes at most one volume name")
			}
			var ref *volumeRef
			if len(args) == 1 {
				r, err := parseVolumeRef(args[0], true)
				if err != nil {
					return err
				}
				ref = &r
			}
			s, tenant, err := g.volumeSession(c, nil, 0, "")
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			all, err := readVolumeBackups(ctx, s, tenant)
			if err != nil {
				return err
			}
			list := []control.VolumeBackupView{}
			for _, b := range all {
				if ref == nil || ref.is(b.Scope) {
					list = append(list, b)
				}
			}
			return cli.Print(c.Out, g.output.Format(), list, func() cli.Rows {
				t := cli.Rows{Header: []string{"volume", "backup", "node", "phase", "size", "max-size"}}
				for _, b := range list {
					size := ""
					if b.Receipt != nil {
						size = cli.Size(b.Receipt.Bytes).String()
					}
					t.Add(volumeName(b.Scope), b.ID, b.Node, b.Phase, size, volumeSizeText(b.MaxBytes))
				}
				return t
			})
		},
	}
}

func volumeBackupShowCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "show",
		Args:  "APP/VOLUME BACKUP",
		Short: "Show one backup",
		Run: func(c *cli.Context, args []string) error {
			ref, err := volumeArg(args, 2, "show needs a volume name and a backup name", true)
			if err != nil {
				return err
			}
			s, tenant, err := g.volumeSession(c, args, 2, "show needs a volume name and a backup name")
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			b, err := findVolumeBackupView(ctx, s, tenant, ref, args[1])
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), b, nil)
		},
	}
}

// backupChange cancels or deletes one backup.
func backupChange(g *globals, name, short, action, verb string) *cli.Command {
	var f changeFlags
	return &cli.Command{
		Name:  name,
		Args:  "APP/VOLUME BACKUP",
		Short: short,
		Flags: func(fs *flag.FlagSet) { f.register(fs, true, true) },
		Run: func(c *cli.Context, args []string) error {
			ref, err := volumeArg(args, 2, name+" needs a volume name and a backup name", true)
			if err != nil {
				return err
			}
			s, tenant, err := g.volumeSession(c, args, 2, name+" needs a volume name and a backup name")
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			b, err := findVolumeBackupView(ctx, s, tenant, ref, args[1])
			var epoch uint64
			if err == nil {
				epoch, err = moduleEpoch(ctx, s)
			}
			cancel()
			if err != nil {
				return err
			}
			ok, err := g.confirm(c, &f, fmt.Sprintf("%s backup %s of %s (now %s).", verb, b.ID, ref, b.Phase))
			if !ok || err != nil {
				return err
			}
			payload := control.VolumeBackupSelection{Scope: b.Scope, ID: b.ID}
			return g.volumeChange(c, s, &f, "volume backup "+name+" "+ref.String()+" "+b.ID, action, b.Revision, epoch, payload)
		},
	}
}

func volumeBackupCancelCommand(g *globals) *cli.Command {
	return backupChange(g, "cancel", "Stop a backup that is still running", "cancel-volume-backup", "Cancel")
}

func volumeBackupDeleteCommand(g *globals) *cli.Command {
	return backupChange(g, "delete", "Delete a finished backup", "delete-volume-backup", "Delete")
}

func volumeBackupLimitsCommand(g *globals) *cli.Command {
	var node string
	var all bool
	return &cli.Command{
		Name:  "limits",
		Short: "Show backup space limits and what is used",
		Sub:   []*cli.Command{volumeBackupLimitsSetCommand(g, &node, &all)},
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&node, "node", "", "only this `server`")
			fs.BoolVar(&all, "all", false, "cluster-wide limits (system administrator)")
		},
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("limits takes no arguments")
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
			defer cancel()
			rows, err := readPublicRows(ctx, s, "volume-backup-limits", tenant, control.PublicReadQuery{Node: node})
			if err != nil {
				return err
			}
			limits := []control.PublicBackupLimit{}
			for _, r := range rows {
				if r.BackupLimit != nil {
					limits = append(limits, *r.BackupLimit)
				}
			}
			return cli.Print(c.Out, g.output.Format(), limits, func() cli.Rows {
				t := cli.Rows{Header: []string{"tenant", "node", "used", "limit", "backups", "max-backups"}}
				for _, l := range limits {
					t.Add(l.Tenant, l.Node, cli.Size(l.UsedBytes), volumeSizeText(l.Bytes), l.UsedCount, l.Count)
				}
				return t
			})
		},
	}
}

func volumeRestoreCommand(g *globals) *cli.Command {
	var f changeFlags
	var to, name string
	var maxSize, size cli.Size
	var generation uint64
	return &cli.Command{
		Name:  "restore",
		Args:  "APP/VOLUME BACKUP --to APP/NEW-VOLUME",
		Short: "Restore a backup into a new volume",
		Long: `Copies a ready backup into a new, unused volume on the backup's server.
The restored files are checked against the backup; databases inside still
need their own recovery. Subcommands list, show and cancel restores.`,
		Flags: func(fs *flag.FlagSet) {
			f.register(fs, true, true)
			fs.StringVar(&to, "to", "", "new `volume` APP/VOLUME to restore into")
			fs.StringVar(&name, "name", "", "restore `name` (default: r-DATE-TIME)")
			fs.Var(&maxSize, "max-size", "space to reserve while restoring, such as 10GiB")
			fs.Var(&size, "size", "space to reserve for the new volume (at least --max-size)")
			fs.Uint64Var(&generation, "generation", 1, "generation `number` of the new volume")
		},
		Run: func(c *cli.Context, args []string) error {
			ref, err := volumeArg(args, 2, "restore needs a volume name, a backup name and --to", true)
			if err != nil {
				return err
			}
			target, err := parseVolumeRef(to, true)
			if err != nil {
				return cli.Usagef("--to needs the new volume as APP/VOLUME")
			}
			if name == "" {
				name = "r-" + time.Now().UTC().Format("20060102-150405")
			}
			if err = backupName("restore", name); err != nil {
				return err
			}
			if maxSize < 1024 || maxSize > 1<<40 || size != 0 && size < maxSize || generation == 0 {
				return cli.Usagef("--max-size (1KiB..1TiB) is required; --size must be at least --max-size; --generation is 1 or more")
			}
			s, tenant, err := g.volumeSession(c, args, 2, "restore needs a volume name, a backup name and --to")
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			b, err := findVolumeBackupView(ctx, s, tenant, ref, args[1])
			var epoch uint64
			if err == nil {
				epoch, err = moduleEpoch(ctx, s)
			}
			cancel()
			if err != nil {
				return err
			}
			if b.Phase != "Ready" || b.Receipt == nil {
				return cli.ExitError{Code: 3, Err: fmt.Errorf("backup %s is %s; only a ready backup can be restored", b.ID, b.Phase)}
			}
			spec := volumes.NativeSpec{Schema: 1, Scope: volumes.Scope{Cluster: s.Client.Cluster, Tenant: tenant, App: target.App, ID: target.ID, Generation: generation}, Node: b.Node, NodeKey: b.Owner, Materialization: "r-" + name, UID: b.UID, GID: b.GID, Mode: b.Mode, Retain: true}
			if spec.Validate() != nil {
				return cli.Usagef("restore name %q is too long", name)
			}
			q := control.VolumeRestoreBegin{Backup: control.VolumeBackupSelection{Scope: b.Scope, ID: b.ID}, ID: name, Target: spec, MaxBytes: uint64(maxSize), CapacityBytes: uint64(size)}
			ok, err := g.confirm(c, &f, fmt.Sprintf("Restore backup %s of %s into new volume %s on %s (restore %s).", b.ID, ref, target, b.Node, name))
			if !ok || err != nil {
				return err
			}
			return g.volumeChange(c, s, &f, "volume restore "+ref.String()+" "+b.ID+" --to "+target.String(), "begin-volume-restore", b.Revision, epoch, q)
		},
		Sub: []*cli.Command{
			volumeRestoreListCommand(g),
			volumeRestoreShowCommand(g),
			volumeRestoreCancelCommand(g, &f),
		},
	}
}

func readVolumeRestoreViews(ctx context.Context, s *session, tenant string) ([]control.VolumeRestoreView, error) {
	var out []control.VolumeRestoreView
	var root uint64
	after := ""
	for {
		reply, err := s.Client.VolumeRestorePage(ctx, s.Target, s.Stored.Session, tenant, after)
		if err != nil {
			return nil, err
		}
		if root != 0 && root != reply.RootRevision {
			return nil, errors.New("the restore list changed while it was read; try again")
		}
		root = reply.RootRevision
		last := after
		for _, j := range reply.Items {
			if j.Backup.Scope.Cluster != s.Client.Cluster || j.Backup.Scope.Tenant != tenant || j.Target.Cluster != s.Client.Cluster || j.Target.Tenant != tenant || j.Key <= last || len(out) >= 4096 {
				return nil, sfcp.ErrAdmission
			}
			out = append(out, j)
			last = j.Key
		}
		if reply.Next == "" {
			return out, nil
		}
		if last == after || reply.Next != last {
			return nil, sfcp.ErrAdmission
		}
		after = last
	}
}

// findRestore finds a restore by name. Names are chosen per backup, so the
// same name on two backups needs the backup to tell them apart.
func findRestore(ctx context.Context, s *session, tenant, name string) (control.VolumeRestoreView, error) {
	all, err := readVolumeRestoreViews(ctx, s, tenant)
	if err != nil {
		return control.VolumeRestoreView{}, err
	}
	var found []control.VolumeRestoreView
	for _, j := range all {
		if j.ID == name {
			found = append(found, j)
		}
	}
	switch len(found) {
	case 0:
		return control.VolumeRestoreView{}, fmt.Errorf("restore %s not found", name)
	case 1:
		return found[0], nil
	}
	return control.VolumeRestoreView{}, fmt.Errorf("more than one restore is named %s; see 'sfcli volume restore list -o json'", name)
}

func volumeRestoreListCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "list",
		Short: "List the tenant's restores",
		Run: func(c *cli.Context, args []string) error {
			s, tenant, err := g.volumeSession(c, args, 0, "list takes no arguments")
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			list, err := readVolumeRestoreViews(ctx, s, tenant)
			if err != nil {
				return err
			}
			if list == nil {
				list = []control.VolumeRestoreView{}
			}
			return cli.Print(c.Out, g.output.Format(), list, func() cli.Rows {
				t := cli.Rows{Header: []string{"restore", "from", "backup", "to", "node", "phase"}}
				for _, j := range list {
					t.Add(j.ID, volumeName(j.Backup.Scope), j.Backup.ID, volumeName(j.Target), j.Node, j.Phase)
				}
				return t
			})
		},
	}
}

func volumeRestoreShowCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "show",
		Args:  "RESTORE",
		Short: "Show one restore",
		Run: func(c *cli.Context, args []string) error {
			s, tenant, err := g.volumeSession(c, args, 1, "show needs one restore name")
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			j, err := findRestore(ctx, s, tenant, args[0])
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), j, nil)
		},
	}
}

// f is the parent restore command's --id, --dry-run and --no-wait, which
// subcommands inherit.
func volumeRestoreCancelCommand(g *globals, f *changeFlags) *cli.Command {
	return &cli.Command{
		Name:  "cancel",
		Args:  "RESTORE",
		Short: "Stop a restore that is still running",
		Run: func(c *cli.Context, args []string) error {
			s, tenant, err := g.volumeSession(c, args, 1, "cancel needs one restore name")
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			j, err := findRestore(ctx, s, tenant, args[0])
			var epoch uint64
			if err == nil {
				epoch, err = moduleEpoch(ctx, s)
			}
			cancel()
			if err != nil {
				return err
			}
			ok, err := g.confirm(c, f, fmt.Sprintf("Cancel restore %s into %s (now %s).", j.ID, volumeName(j.Target), j.Phase))
			if !ok || err != nil {
				return err
			}
			return g.volumeChange(c, s, f, "volume restore cancel "+j.ID, "cancel-volume-restore", j.Revision, epoch, control.VolumeRestoreSelection{Backup: j.Backup, ID: j.ID})
		},
	}
}
