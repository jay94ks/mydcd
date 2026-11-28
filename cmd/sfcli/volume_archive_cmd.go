// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/clusterbackup"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/volumearchive"
)

// Volume archives (devel/proposals/volume-archive-packages.md): a taken-down
// app's volume is packed, compressed and sealed into one file on a storage
// root of its server, and its directory is emptied. Nothing archives on its
// own: 'volume archive' or 'app archive' does (Jay 2026-11-28 09:37 KST).

// archiveFlags are the options of one new archive.
type archiveFlags struct {
	store      string
	noCompress bool
	maxSize    cli.Size
	maxEntries uint
}

func (a *archiveFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&a.store, "store", "", "storage root on the volume's server to keep the package in (default: the server's archive default, else its default root)")
	fs.BoolVar(&a.noCompress, "no-compress", false, "keep the package uncompressed (it is still sealed)")
	fs.Var(&a.maxSize, "max-size", "most bytes to pack, such as 10GiB (default: the volume's size)")
	fs.UintVar(&a.maxEntries, "max-entries", 100000, "most files and directories to pack (1..100000)")
}

func (a *archiveFlags) check() error {
	if a.store != "" && backupName("storage root", a.store) != nil {
		return cli.Usagef("%q is not a storage root name", a.store)
	}
	if a.maxSize != 0 && (a.maxSize < 1024 || a.maxSize > 1<<40) || a.maxEntries == 0 || a.maxEntries > 100000 {
		return cli.Usagef("--max-size is 1KiB..1TiB; --max-entries is 1..100000")
	}
	return nil
}

// begin builds the archive-volume payload for v, or says why it cannot.
func (a *archiveFlags) begin(v control.VolumeView, id string) (control.VolumeArchiveBegin, error) {
	if v.Scope.App == "" || v.Kind == "node-fixed" {
		return control.VolumeArchiveBegin{}, fmt.Errorf("volume %s is a registered node directory; only app volumes are archived", volumeName(v.Scope))
	}
	if v.Phase != "Ready" {
		return control.VolumeArchiveBegin{}, fmt.Errorf("volume %s is %s; only a ready volume is archived", volumeName(v.Scope), v.Phase)
	}
	size := uint64(a.maxSize)
	if size == 0 {
		size = v.CapacityBytes
	}
	if size < 1024 || size > 1<<40 {
		return control.VolumeArchiveBegin{}, cli.Usagef("volume %s has no size; give --max-size", volumeName(v.Scope))
	}
	compression := volumearchive.Zstd
	if a.noCompress {
		compression = volumearchive.None
	}
	return control.VolumeArchiveBegin{Scope: v.Scope, ID: id, Root: a.store, Compression: compression, MaxBytes: size, MaxEntries: uint32(a.maxEntries)}, nil
}

func (a *archiveFlags) where() string {
	where := "the server's archive default"
	if a.store != "" {
		where = "storage root " + a.store
	}
	if a.noCompress {
		return where + ", uncompressed"
	}
	return where + ", zstd"
}

// newArchiveID is the default archive name; the consumer that holds the
// volume is "a-" + it.
func newArchiveID() string { return time.Now().UTC().Format("20060102-150405") }

func readVolumeArchives(ctx context.Context, s *session, tenant string) ([]control.VolumeArchiveView, control.VolumeArchiveKeys, error) {
	var out []control.VolumeArchiveView
	var keys control.VolumeArchiveKeys
	var root uint64
	after := ""
	for {
		reply, err := s.Client.VolumeArchivePage(ctx, s.Target, s.Stored.Session, tenant, after)
		if err != nil {
			return nil, keys, err
		}
		if root != 0 && root != reply.RootRevision {
			return nil, keys, errors.New("the archive list changed while it was read; try again")
		}
		root, keys = reply.RootRevision, reply.Keys
		last := after
		for _, j := range reply.Items {
			if j.Scope.Cluster != s.Client.Cluster || tenant != "" && j.Scope.Tenant != tenant || j.Key <= last || len(out) >= 4096 {
				return nil, keys, sfcp.ErrAdmission
			}
			out = append(out, j)
			last = j.Key
		}
		if reply.Next == "" {
			return out, keys, nil
		}
		if last == after || reply.Next != last {
			return nil, keys, sfcp.ErrAdmission
		}
		after = last
	}
}

// findVolumeArchive finds archive id of the volume, or with no id the one
// that holds it now (else its latest).
func findVolumeArchive(ctx context.Context, s *session, tenant string, ref volumeRef, id string) (control.VolumeArchiveView, error) {
	all, _, err := readVolumeArchives(ctx, s, tenant)
	if err != nil {
		return control.VolumeArchiveView{}, err
	}
	var found *control.VolumeArchiveView
	for i, j := range all {
		if !ref.is(j.Scope) {
			continue
		}
		if id != "" {
			if j.ID == id {
				return j, nil
			}
			continue
		}
		if !archiveFinished(j.Phase) {
			return j, nil
		}
		found = &all[i]
	}
	if found != nil {
		return *found, nil
	}
	if id != "" {
		return control.VolumeArchiveView{}, fmt.Errorf("archive %s of %s not found", id, ref)
	}
	return control.VolumeArchiveView{}, fmt.Errorf("volume %s has no archive", ref)
}

func archiveFinished(phase string) bool {
	switch phase {
	case "Restored", "Cancelled", "Failed", "Discarded":
		return true
	}
	return false
}

func volumeArchiveCommand(g *globals) *cli.Command {
	var f changeFlags
	var a archiveFlags
	var name string
	return &cli.Command{
		Name:  "archive",
		Args:  "APP/VOLUME",
		Short: "Pack a taken-down app's volume into a sealed file and free its space",
		Long: `Packs the volume's files (tar, zstd unless --no-compress) into one package
sealed to the cluster key and the administrator's key, keeps it on a
storage root of the same server and empties the volume. The volume keeps
its name, owner and reserved size; nothing can use it until
'sfcli volume unarchive APP/VOLUME'.

The app must be down and its last writer must have stopped cleanly.
Subcommands list, show, cancel and discard archives; admin-key sets the
administrator's key every new package is also sealed to.`,
		Flags: func(fs *flag.FlagSet) {
			f.register(fs, true, true)
			a.register(fs)
			fs.StringVar(&name, "name", "", "archive `name` (default: DATE-TIME)")
		},
		Sub: []*cli.Command{
			volumeArchiveListCommand(g),
			volumeArchiveShowCommand(g),
			archiveChange(g, &f, "cancel", "Stop an archive that is still packing", "cancel-volume-archive", "Cancel", "Packing"),
			archiveChange(g, &f, "discard", "Delete an archived volume's package; the volume stays empty", "discard-volume-archive", "Discard", "Archived"),
			volumeArchiveAdminKeyCommand(g, &f),
		},
		Run: func(c *cli.Context, args []string) error {
			ref, err := volumeArg(args, 1, "archive needs one volume name APP/VOLUME", true)
			if err != nil {
				return err
			}
			if name == "" {
				name = newArchiveID()
			}
			if !volumearchive.ValidID(name) || len(name) > 61 {
				return cli.Usagef("%q is not an archive name (lower-case letters, digits and '-', at most 61)", name)
			}
			if err = a.check(); err != nil {
				return err
			}
			s, tenant, err := g.volumeSession(c, args, 1, "archive needs one volume name APP/VOLUME")
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			v, epoch, err := findVolumeView(ctx, s, tenant, ref)
			cancel()
			if err != nil {
				return err
			}
			q, err := a.begin(v, name)
			if err != nil {
				return err
			}
			ok, err := g.confirm(c, &f, fmt.Sprintf("Archive volume %s on %s as %s (%s, up to %s). The volume is emptied until it is unarchived.", ref, v.Owner.Node, name, a.where(), cli.Size(q.MaxBytes)))
			if !ok || err != nil {
				return err
			}
			return g.volumeChange(c, s, &f, "volume archive "+ref.String()+" "+name, "archive-volume", v.Revision, epoch, q)
		},
	}
}

func volumeUnarchiveCommand(g *globals) *cli.Command {
	var f changeFlags
	return &cli.Command{
		Name:  "unarchive",
		Args:  "APP/VOLUME [ARCHIVE]",
		Short: "Restore an archived volume in place and delete its package",
		Long: `Unpacks the volume's package into the same, emptied volume on its server,
checks the files against the package and deletes the package. The app
can then be deployed again with 'sfcli app deploy'.`,
		Flags: func(fs *flag.FlagSet) { f.register(fs, true, true) },
		Run: func(c *cli.Context, args []string) error {
			if len(args) < 1 || len(args) > 2 {
				return cli.Usagef("unarchive needs a volume name APP/VOLUME and, if it has more than one, the archive name")
			}
			ref, err := parseVolumeRef(args[0], true)
			if err != nil {
				return err
			}
			id := ""
			if len(args) == 2 {
				id = args[1]
			}
			s, tenant, err := g.volumeSession(c, nil, 0, "")
			if err != nil {
				return err
			}
			defer s.Close()
			return g.sendArchiveChange(c, s, &f, tenant, ref, id, "unarchive", "unarchive-volume", "Restore", "Archived")
		},
	}
}

// archiveChange cancels or discards one archive. f is the parent archive
// command's --id, --dry-run and --no-wait, which subcommands inherit.
func archiveChange(g *globals, f *changeFlags, name, short, action, verb, phase string) *cli.Command {
	return &cli.Command{
		Name:  name,
		Args:  "APP/VOLUME [ARCHIVE]",
		Short: short,
		Run: func(c *cli.Context, args []string) error {
			if len(args) < 1 || len(args) > 2 {
				return cli.Usagef("%s needs a volume name APP/VOLUME and, if it has more than one, the archive name", name)
			}
			ref, err := parseVolumeRef(args[0], true)
			if err != nil {
				return err
			}
			id := ""
			if len(args) == 2 {
				id = args[1]
			}
			s, tenant, err := g.volumeSession(c, nil, 0, "")
			if err != nil {
				return err
			}
			defer s.Close()
			return g.sendArchiveChange(c, s, f, tenant, ref, id, "archive "+name, action, verb, phase)
		},
	}
}

func (g *globals) sendArchiveChange(c *cli.Context, s *session, f *changeFlags, tenant string, ref volumeRef, id, summary, action, verb, phase string) error {
	ctx, cancel := g.Deadline(c)
	j, err := findVolumeArchive(ctx, s, tenant, ref, id)
	var epoch uint64
	if err == nil {
		epoch, err = moduleEpoch(ctx, s)
	}
	cancel()
	if err != nil {
		return err
	}
	if j.Phase != phase {
		return cli.ExitError{Code: 3, Err: fmt.Errorf("archive %s of %s is %s; %s needs it %s", j.ID, ref, j.Phase, summary, phase)}
	}
	ok, err := g.confirm(c, f, fmt.Sprintf("%s archive %s of %s on %s (now %s).", verb, j.ID, ref, j.Node, j.Phase))
	if !ok || err != nil {
		return err
	}
	payload := control.VolumeArchiveSelection{Scope: j.Scope, ID: j.ID}
	return g.volumeChange(c, s, f, "volume "+summary+" "+ref.String()+" "+j.ID, action, j.Revision, epoch, payload)
}

func volumeArchiveListCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "list",
		Args:  "[APP/VOLUME]",
		Short: "List archives, of one volume or of the whole tenant",
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
			all, _, err := readVolumeArchives(ctx, s, tenant)
			if err != nil {
				return err
			}
			list := []control.VolumeArchiveView{}
			for _, j := range all {
				if ref == nil || ref.is(j.Scope) {
					list = append(list, j)
				}
			}
			return cli.Print(c.Out, g.output.Format(), list, func() cli.Rows {
				t := cli.Rows{Header: []string{"volume", "archive", "node", "store", "phase", "size", "packed", "compression"}}
				for _, j := range list {
					size, packed := "", ""
					if j.TarBytes != 0 {
						size, packed = cli.Size(j.TarBytes).String(), cli.Size(j.DataBytes).String()
					}
					phase := j.Phase
					if j.Failure != "" {
						phase += ": " + j.Failure
					}
					t.Add(volumeName(j.Scope), j.ID, j.Node, j.Root, phase, size, packed, string(j.Compression))
				}
				return t
			})
		},
	}
}

func volumeArchiveShowCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "show",
		Args:  "APP/VOLUME [ARCHIVE]",
		Short: "Show one archive (default: the one that holds the volume)",
		Run: func(c *cli.Context, args []string) error {
			if len(args) < 1 || len(args) > 2 {
				return cli.Usagef("show needs a volume name and, optionally, an archive name")
			}
			ref, err := parseVolumeRef(args[0], true)
			if err != nil {
				return err
			}
			id := ""
			if len(args) == 2 {
				id = args[1]
			}
			s, tenant, err := g.volumeSession(c, nil, 0, "")
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			j, err := findVolumeArchive(ctx, s, tenant, ref, id)
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), j, nil)
		},
	}
}

// archiveKeysView is what 'admin-key' prints: public keys only.
type archiveKeysView struct {
	Cluster, Admin string
	Revision       uint64
}

func keyText(k [32]byte) string {
	if k == ([32]byte{}) {
		return ""
	}
	return hex.EncodeToString(k[:])
}

// f is the parent archive command's --id, --if-revision and --dry-run.
func volumeArchiveAdminKeyCommand(g *globals, f *changeFlags) *cli.Command {
	var keyFile string
	return &cli.Command{
		Name:  "admin-key",
		Short: "Show or set the administrator's key new packages are sealed to (system administrator)",
		Long: `Every new package is sealed to two keys: the cluster's own, which the
voters derive from the cluster master key, and the administrator's, which
opens packages when the whole cluster is lost. Without --key-file this
prints both public keys.

--key-file takes a key file from 'sfcli cluster backup keygen'. Only its
public half is sent; keep the file outside the cluster. Packages made
before a change stay sealed to the key they were made with.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&keyFile, "key-file", "", "key `file` whose public half becomes the administrator's key")
		},
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("admin-key takes no arguments")
			}
			var public [32]byte
			if keyFile != "" {
				raw, err := os.ReadFile(keyFile)
				if err != nil {
					return err
				}
				key, err := clusterbackup.KeyFromFile(raw)
				clear(raw)
				if err != nil {
					return err
				}
				r, err := key.Recipient(volumearchive.AdminKeyLabel)
				key.Clear()
				if err != nil {
					return err
				}
				public = r.Public()
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			_, keys, err := readVolumeArchives(ctx, s, "")
			var epoch uint64
			if err == nil && keyFile != "" {
				epoch, err = moduleEpoch(ctx, s)
			}
			cancel()
			if err != nil {
				return err
			}
			if keyFile == "" {
				view := archiveKeysView{Cluster: keyText(keys.Cluster), Admin: keyText(keys.Admin), Revision: keys.Revision}
				return cli.Print(c.Out, g.output.Format(), view, func() cli.Rows {
					t := cli.Rows{Header: []string{"key", "public"}}
					t.Add("cluster", orNone(view.Cluster))
					t.Add("admin", orNone(view.Admin))
					return t
				})
			}
			if public == keys.Admin {
				fmt.Fprintln(c.Err, "The administrator's key is already this one.")
				return nil
			}
			impact := "Set the administrator's archive key to " + keyText(public) + "."
			if keys.Admin != ([32]byte{}) {
				impact += " New packages are sealed to it instead of " + keyText(keys.Admin) + "."
			}
			ok, err := g.confirm(c, f, impact)
			if !ok || err != nil {
				return err
			}
			return sendResult(g.send(c, s, change{Summary: "volume archive admin-key", ID: f.id.Get(), Action: "set-volume-archive-admin-key", Expected: f.expect(keys.Revision), Epoch: epoch, Payload: control.VolumeArchiveAdminKey{Key: public}}))
		},
	}
}

// archiveProgress follows archive-volume, cancel, unarchive and discard.
func archiveProgress(ctx context.Context, s *session, action string, raw []byte) (progress, error) {
	var q control.VolumeArchiveSelection
	if err := json.Unmarshal(raw, &q); err != nil {
		return progress{}, err
	}
	j, err := findVolumeArchive(ctx, s, q.Scope.Tenant, volumeRef{App: q.Scope.App, ID: q.Scope.ID}, q.ID)
	if err != nil {
		return progress{}, err
	}
	phase := j.Phase
	if j.Failure != "" {
		phase += ": " + j.Failure
	}
	want := map[string]string{"archive-volume": "Archived", "cancel-volume-archive": "Cancelled", "unarchive-volume": "Restored", "discard-volume-archive": "Discarded"}[action]
	switch {
	case j.Phase == want:
		return progress{phase, true, true}, nil
	case archiveFinished(j.Phase):
		return progress{phase, true, false}, nil
	case action == "unarchive-volume" && j.Phase == "Archived":
		// Back to Archived after Restoring: the restore failed and the
		// package is kept.
		return progress{phase, true, false}, nil
	}
	return progress{phase, false, false}, nil
}

// appArchiveCommand archives every ready volume of a taken-down app, one
// archive-volume each under the same archive name.
func appArchiveCommand(g *globals) *cli.Command {
	var f changeFlags
	var a archiveFlags
	var name string
	return &cli.Command{
		Name:  "archive",
		Args:  "APP",
		Short: "Archive every volume of a taken-down app",
		Long: `Runs 'sfcli volume archive' for each of the app's ready volumes: packs and
seals them on their servers and empties them. Volumes already archived
are skipped. --max-size, when given, applies to each volume; otherwise
each volume's own size is used. Bring them back with
'sfcli volume unarchive APP/VOLUME', then 'sfcli app deploy'.`,
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&f.noWait, "no-wait", false, "return once the server accepts each change")
			fs.BoolVar(&f.dryRun, "dry-run", false, "only show what would change")
			a.register(fs)
			fs.StringVar(&name, "name", "", "archive `name` for every volume (default: DATE-TIME)")
		},
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("archive needs one app name")
			}
			app := args[0]
			if name == "" {
				name = newArchiveID()
			}
			if !volumearchive.ValidID(name) || len(name) > 61 {
				return cli.Usagef("%q is not an archive name (lower-case letters, digits and '-', at most 61)", name)
			}
			if err := a.check(); err != nil {
				return err
			}
			s, tenant, err := g.volumeSession(c, nil, 0, "")
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			all, epoch, err := readVolumes(ctx, s, tenant)
			cancel()
			if err != nil {
				return err
			}
			type planned struct {
				v control.VolumeView
				q control.VolumeArchiveBegin
			}
			var plan []planned
			for _, v := range all {
				if v.Scope.App != app || v.Kind == "node-fixed" {
					continue
				}
				if v.Phase == "Archived" {
					fmt.Fprintf(c.Err, "Volume %s is already archived (%s).\n", volumeName(v.Scope), v.ArchiveID)
					continue
				}
				q, err := a.begin(v, name)
				if err != nil {
					return err
				}
				plan = append(plan, planned{v, q})
			}
			if len(plan) == 0 {
				return fmt.Errorf("app %s has no volume to archive", app)
			}
			for _, p := range plan {
				fmt.Fprintf(c.Err, "Archive volume %s on %s as %s (up to %s).\n", volumeName(p.v.Scope), p.v.Owner.Node, name, cli.Size(p.q.MaxBytes))
			}
			ok, err := g.confirm(c, &f, fmt.Sprintf("Archive %d volume(s) of %s (%s). Each is emptied until it is unarchived.", len(plan), app, a.where()))
			if !ok || err != nil {
				return err
			}
			var failed []string
			for _, p := range plan {
				one := f // a new operation ID per volume
				ref := volumeRef{App: p.v.Scope.App, ID: p.v.Scope.ID}
				fmt.Fprintf(c.Err, "%s:\n", ref)
				if err := g.volumeChange(c, s, &one, "volume archive "+ref.String()+" "+name, "archive-volume", p.v.Revision, epoch, p.q); err != nil {
					fmt.Fprintf(c.Err, "  %v\n", err)
					failed = append(failed, ref.String())
				}
			}
			if len(failed) != 0 {
				return cli.ExitError{Code: 3, Err: fmt.Errorf("%d of %d volume(s) not archived: %v", len(failed), len(plan), failed)}
			}
			return nil
		},
	}
}
