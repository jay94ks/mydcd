// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/cli"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// The volume group of devel/design/cli-and-formats.md. A volume is named
// APP/VOLUME; a volume registered on a node directory with `volume register`
// belongs to the tenant and is named VOLUME alone.

func volumeCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "volume",
		Short: "Volumes: list, create, back up, restore, move and copy files",
		Long: `Volumes hold app data on one server. An app volume is named APP/VOLUME;
a volume registered on an existing node directory belongs to the tenant
and is named VOLUME.`,
		Sub: []*cli.Command{
			volumeListCommand(g),
			volumeShowCommand(g),
			volumeUsageCommand(g),
			volumeUsersCommand(g),
			volumeCreateCommand(g),
			volumeDeleteCommand(g),
			volumeResizeCommand(g),
			volumeRegisterCommand(g),
			volumeUnregisterCommand(g),
			volumeBackupCommand(g),
			volumeRestoreCommand(g),
			volumeMoveCommand(g),
			volumeFilesCommand(g),
		},
	}
}

// volumeRef is a volume name on the command line: APP/VOLUME, or VOLUME for
// a tenant volume.
type volumeRef struct{ App, ID string }

func (r volumeRef) String() string {
	if r.App == "" {
		return r.ID
	}
	return r.App + "/" + r.ID
}

func parseVolumeRef(s string, appRequired bool) (volumeRef, error) {
	app, id, found := strings.Cut(s, "/")
	if !found {
		app, id = "", s
	}
	if !lifecycle.ValidID(id) || found && !lifecycle.ValidID(app) {
		return volumeRef{}, cli.Usagef("%q is not a volume name; use APP/VOLUME or VOLUME (lower-case letters, digits and '-')", s)
	}
	if appRequired && app == "" {
		return volumeRef{}, cli.Usagef("%q needs its app: use APP/VOLUME", s)
	}
	return volumeRef{App: app, ID: id}, nil
}

func (r volumeRef) selector() control.VolumeSelector {
	return control.VolumeSelector{App: r.App, ID: r.ID}
}

func (r volumeRef) is(scope volumes.Scope) bool { return scope.App == r.App && scope.ID == r.ID }

func volumeName(scope volumes.Scope) string { return volumeRef{App: scope.App, ID: scope.ID}.String() }

// volumeArgs opens the session and reads the single volume argument.
func (g *globals) volumeSession(c *cli.Context, args []string, n int, usage string) (*session, string, error) {
	if len(args) != n {
		return nil, "", cli.Usagef("%s", usage)
	}
	s, err := g.open(c)
	if err != nil {
		return nil, "", err
	}
	tenant, err := g.Tenant(s, true)
	if err != nil {
		s.Close()
		return nil, "", err
	}
	return s, tenant, nil
}

// readVolumes reads every page of the tenant's volumes ("" with --all) from
// one catalog revision and returns them with the module epoch.
func readVolumes(ctx context.Context, s *session, tenant string) ([]control.VolumeView, uint64, error) {
	var out []control.VolumeView
	var root, epoch uint64
	after := ""
	for {
		reply, err := s.Client.VolumePage(ctx, s.Target, s.Stored.Session, tenant, after)
		if err != nil {
			return nil, 0, err
		}
		if root != 0 && reply.VolumesRootRevision != root {
			return nil, 0, errors.New("the volume list changed while it was read; try again")
		}
		root, epoch = reply.VolumesRootRevision, reply.ModuleEpoch
		last := after
		for _, v := range reply.Volumes {
			if v.Scope.Cluster != s.Client.Cluster || tenant != "" && v.Scope.Tenant != tenant || v.Key <= last || len(out) >= 4096 {
				return nil, 0, mydcp.ErrAdmission
			}
			out = append(out, v)
			last = v.Key
		}
		if reply.VolumesNext == "" {
			return out, max(1, epoch), nil
		}
		if last == after || reply.VolumesNext != last {
			return nil, 0, mydcp.ErrAdmission
		}
		after = last
	}
}

func findVolumeView(ctx context.Context, s *session, tenant string, ref volumeRef) (control.VolumeView, uint64, error) {
	all, epoch, err := readVolumes(ctx, s, tenant)
	if err != nil {
		return control.VolumeView{}, 0, err
	}
	for _, v := range all {
		if ref.is(v.Scope) {
			return v, epoch, nil
		}
	}
	return control.VolumeView{}, 0, fmt.Errorf("volume %s not found in tenant %s", ref, tenant)
}

// moduleEpoch reads the current management epoch for a new change.
func moduleEpoch(ctx context.Context, s *session) (uint64, error) {
	view, err := s.Client.Query(ctx, s.Target, s.Stored.Session, "whoami", "")
	if err != nil {
		return 0, err
	}
	return max(1, view.ModuleEpoch), nil
}

// readPublicRows reads every page of one public resource read.
func readPublicRows(ctx context.Context, s *session, method, tenant string, q control.PublicReadQuery) ([]control.PublicReadRow, error) {
	var rows []control.PublicReadRow
	after := ""
	var root uint64
	for {
		reply, err := s.Client.PublicRead(ctx, s.Target, s.Stored.Session, method, tenant, q, after)
		if err != nil {
			return nil, err
		}
		page := reply.PublicRead
		if page == nil {
			return nil, mydcp.ErrAdmission
		}
		if root != 0 && page.RootRevision != root {
			return nil, errors.New("the list changed while it was read; try again")
		}
		root = page.RootRevision
		rows = append(rows, page.Rows...)
		if page.Next == "" {
			return rows, nil
		}
		if page.Next == after || len(rows) > 4096 {
			return nil, mydcp.ErrAdmission
		}
		after = page.Next
	}
}

func volumeSizeText(n uint64) string {
	if n == 0 {
		return ""
	}
	return cli.Size(n).String()
}

func volumeListCommand(g *globals) *cli.Command {
	var all bool
	return &cli.Command{
		Name:  "list",
		Short: "List the tenant's volumes",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&all, "all", false, "every tenant's volumes (system administrator)")
		},
		Run: func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("list takes no arguments")
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
			list, _, err := readVolumes(ctx, s, tenant)
			if err != nil {
				return err
			}
			if list == nil {
				list = []control.VolumeView{}
			}
			return cli.Print(c.Out, g.output.Format(), list, func() cli.Rows {
				t := cli.Rows{Header: []string{"name", "node", "phase", "size", "used", "users"}}
				if all {
					t.Header = append([]string{"tenant"}, t.Header...)
				}
				for _, v := range list {
					used := ""
					if v.UsedBytes != nil {
						used = cli.Size(*v.UsedBytes).String()
					}
					row := []any{volumeName(v.Scope), v.Owner.Node, v.Phase, volumeSizeText(v.CapacityBytes), used, v.Consumers}
					if all {
						row = append([]any{v.Scope.Tenant}, row...)
					}
					t.Add(row...)
				}
				return t
			})
		},
	}
}

func volumeShowCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "show",
		Args:  "NAME",
		Short: "Show one volume",
		Run: func(c *cli.Context, args []string) error {
			ref, err := volumeArg(args, 1, "show needs one volume name", false)
			if err != nil {
				return err
			}
			s, tenant, err := g.volumeSession(c, args, 1, "show needs one volume name")
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			v, _, err := findVolumeView(ctx, s, tenant, ref)
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), v, nil)
		},
	}
}

func volumeUsageCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "usage",
		Args:  "APP/VOLUME",
		Short: "Measure how much space a volume uses now",
		Long:  "Asks the server that holds the volume to measure it. The result is a measurement, not a quota.",
		Run: func(c *cli.Context, args []string) error {
			ref, err := volumeArg(args, 1, "usage needs one volume name", true)
			if err != nil {
				return err
			}
			s, tenant, err := g.volumeSession(c, args, 1, "usage needs one volume name")
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			reply, err := s.Client.VolumeUsage(ctx, s.Target, s.Stored.Session, tenant, ref.selector())
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), reply.VolumeUsage, nil)
		},
	}
}

func volumeUsersCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "users",
		Args:  "NAME",
		Short: "List the services and containers that use a volume",
		Run: func(c *cli.Context, args []string) error {
			ref, err := volumeArg(args, 1, "users needs one volume name", false)
			if err != nil {
				return err
			}
			s, tenant, err := g.volumeSession(c, args, 1, "users needs one volume name")
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			rows, err := readPublicRows(ctx, s, "volume-users", tenant, control.PublicReadQuery{Name: ref.ID, App: ref.App})
			if err != nil {
				return err
			}
			users := []control.PublicResourceUser{}
			for _, r := range rows {
				if r.User != nil {
					users = append(users, *r.User)
				}
			}
			return cli.Print(c.Out, g.output.Format(), users, func() cli.Rows {
				t := cli.Rows{Header: []string{"kind", "app", "service", "node", "desired", "observed"}}
				for _, u := range users {
					owner := u.Service
					if u.Standalone != "" {
						owner = u.Standalone
					}
					t.Add(u.Kind, u.App, owner, u.Node, u.Desired, u.Observed)
				}
				return t
			})
		},
	}
}

// confirm prints what will change and asks. With --dry-run it stops there.
func (g *globals) confirm(c *cli.Context, f *changeFlags, impact string) (bool, error) {
	fmt.Fprintln(c.Err, impact)
	if f.dryRun {
		return false, nil
	}
	return true, g.Prompter(c).Confirm("Go ahead?")
}

// volumeChange sends one volume change and, unless --no-wait, follows it
// until the server reports the volume, backup or restore finished. The
// server accepting a change and the change finishing are printed apart.
func (g *globals) volumeChange(c *cli.Context, s *session, f *changeFlags, summary, action string, expected, epoch uint64, payload any) error {
	id := f.id.Get()
	expected = f.expect(expected)
	if err := sendResult(g.send(c, s, change{Kind: "volume", Summary: summary, ID: id, Action: action, Expected: expected, Epoch: epoch, Payload: payload, Async: true})); err != nil {
		return err
	}
	fmt.Fprintf(c.Err, "Accepted as operation %s.\n", id)
	if f.noWait {
		fmt.Fprintf(c.Err, "Not waiting. Check it with 'mydc op show %s'.\n", id)
		return nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	last := ""
	for {
		ctx, cancel := g.Deadline(c)
		p, err := volumeProgress(ctx, s, action, raw)
		cancel()
		if err != nil {
			return cli.ExitError{Code: exitUnknown, Err: fmt.Errorf("%w; the change goes on, check it with 'mydc op show %s'", err, id)}
		}
		if p.phase != last {
			fmt.Fprintf(c.Err, "  %s\n", p.phase)
			last = p.phase
		}
		if p.final {
			g.settle(id, p.state(), p.phase)
			if !p.ok {
				return cli.ExitError{Code: 3, Err: fmt.Errorf("finished as %s", p.phase)}
			}
			fmt.Fprintln(c.Err, "Done.")
			return nil
		}
		select {
		case <-c.Ctx.Done():
			return cli.ExitError{Code: exitUnknown, Err: fmt.Errorf("stopped waiting; the change goes on, check it with 'mydc op show %s'", id)}
		case <-time.After(time.Second):
		}
	}
}

// progress is where an accepted volume change stands.
type progress struct {
	phase     string
	final, ok bool
}

func (p progress) state() cli.State {
	switch {
	case !p.final:
		return cli.Accepted
	case p.ok:
		return cli.Done
	}
	return cli.Failed
}

// volumeProgress reads the volume, backup or restore a change works on and
// says whether the change has finished. raw is the change's payload.
func volumeProgress(ctx context.Context, s *session, action string, raw []byte) (progress, error) {
	switch action {
	case "begin-volume-create", "register-fixed-volume", "delete-volume", "unregister-fixed-volume", "cancel-volume-create":
		var scope volumes.Scope
		switch action {
		case "begin-volume-create":
			var q control.VolumeCreate
			err := json.Unmarshal(raw, &q)
			scope = q.Scope
			if err != nil {
				return progress{}, err
			}
		case "register-fixed-volume":
			var q control.VolumeFixedRegister
			err := json.Unmarshal(raw, &q)
			scope = q.Scope
			if err != nil {
				return progress{}, err
			}
		default:
			if err := json.Unmarshal(raw, &scope); err != nil {
				return progress{}, err
			}
		}
		all, _, err := readVolumes(ctx, s, scope.Tenant)
		if err != nil {
			return progress{}, err
		}
		create := action == "begin-volume-create" || action == "register-fixed-volume"
		for _, v := range all {
			if v.Scope.App != scope.App || v.Scope.ID != scope.ID {
				continue
			}
			switch {
			case create && v.Phase == "Ready":
				return progress{v.Phase, true, true}, nil
			case !create && v.Phase == "Deleted":
				return progress{v.Phase, true, true}, nil
			case v.Phase == "Failed" || v.Phase == "Cancelled":
				return progress{v.Phase, true, action == "cancel-volume-create"}, nil
			}
			return progress{v.Phase, false, false}, nil
		}
		return progress{"gone", true, !create}, nil
	case "delete-retained-volume":
		var q control.VolumeMoveSelection
		if err := json.Unmarshal(raw, &q); err != nil {
			return progress{}, err
		}
		v, _, err := findVolumeView(ctx, s, q.Scope.Tenant, volumeRef{App: q.Scope.App, ID: q.Scope.ID})
		if err != nil {
			return progress{}, err
		}
		for _, r := range v.Retained {
			if r.Move == q.ID {
				return progress{"old copy " + r.State, r.State == "removed", true}, nil
			}
		}
		return progress{"old copy removed", true, true}, nil
	case "cancel-volume-move":
		var q control.VolumeMoveSelection
		if err := json.Unmarshal(raw, &q); err != nil {
			return progress{}, err
		}
		v, _, err := findVolumeView(ctx, s, q.Scope.Tenant, volumeRef{App: q.Scope.App, ID: q.Scope.ID})
		if err != nil {
			return progress{}, err
		}
		if v.Phase == "Moving" && v.MoveID == q.ID {
			return progress{fmt.Sprintf("cancelling (%s)", v.MovePhase), false, false}, nil
		}
		return progress{"move cancelled; volume is " + v.Phase, true, true}, nil
	case "begin-volume-backup", "cancel-volume-backup", "delete-volume-backup":
		var q control.VolumeBackupSelection
		if err := json.Unmarshal(raw, &q); err != nil {
			return progress{}, err
		}
		want := map[string]string{"begin-volume-backup": "Ready", "cancel-volume-backup": "Cancelled", "delete-volume-backup": "Deleted"}[action]
		b, err := findVolumeBackupView(ctx, s, q.Scope.Tenant, volumeRef{App: q.Scope.App, ID: q.Scope.ID}, q.ID)
		if err != nil {
			if want == "Deleted" {
				return progress{"gone", true, true}, nil
			}
			return progress{}, err
		}
		switch b.Phase {
		case want:
			return progress{b.Phase, true, true}, nil
		case "Failed", "Cancelled", "Deleted", "Ready":
			if b.Failure != "" {
				return progress{b.Phase + ": " + b.Failure, true, false}, nil
			}
			return progress{b.Phase, true, false}, nil
		}
		return progress{b.Phase, false, false}, nil
	case "begin-volume-restore", "cancel-volume-restore":
		var q control.VolumeRestoreSelection
		if err := json.Unmarshal(raw, &q); err != nil {
			return progress{}, err
		}
		want := "Restored"
		if action == "cancel-volume-restore" {
			want = "Cancelled"
		}
		all, err := readVolumeRestoreViews(ctx, s, q.Backup.Scope.Tenant)
		if err != nil {
			return progress{}, err
		}
		for _, j := range all {
			if j.ID != q.ID || j.Backup != q.Backup {
				continue
			}
			switch j.Phase {
			case want:
				return progress{j.Phase, true, true}, nil
			case "Restored", "Cancelled", "Failed":
				return progress{j.Phase, true, false}, nil
			}
			return progress{j.Phase, false, false}, nil
		}
		return progress{}, fmt.Errorf("restore %s not found", q.ID)
	}
	return progress{}, fmt.Errorf("%s is not a volume change", action)
}

func init() {
	opKinds["volume"] = func(g *globals) cli.Handler {
		h := changeHandler(g, nil, true)
		follow := func(call func(*cli.Context, cli.Op) (cli.State, string, error)) func(*cli.Context, cli.Op) (cli.State, string, error) {
			return func(c *cli.Context, op cli.Op) (cli.State, string, error) {
				st, detail, err := call(c, op)
				if err != nil || st != cli.Accepted {
					return st, detail, err
				}
				s, err := g.opSession(c, op)
				if err != nil {
					return "", "", err
				}
				defer s.Close()
				record, err := userauth.LoadOperation(s.Home, s.Client, s.Stored.Session, op.ID)
				if err != nil {
					return "", "", err
				}
				ctx, cancel := g.Deadline(c)
				defer cancel()
				p, err := volumeProgress(ctx, s, record.Operation.Change.Action, record.Operation.Change.Payload)
				if err != nil {
					return "", "", err
				}
				return p.state(), p.phase, nil
			}
		}
		return cli.Handler{Show: follow(h.Show), Resume: follow(h.Resume)}
	}
}

type volumeCreateFlags struct {
	changeFlags
	node       string
	uid, gid   uint
	mode       string
	generation uint64
	size       cli.Size
}

func (f *volumeCreateFlags) creation(cluster [32]byte, tenant string, ref volumeRef) (control.VolumeCreate, error) {
	q := control.VolumeCreate{Scope: volumes.Scope{Cluster: cluster, Tenant: tenant, App: ref.App, ID: ref.ID, Generation: f.generation}, Node: f.node, UID: uint32(f.uid), GID: uint32(f.gid), CapacityBytes: uint64(f.size), QuotaMode: "observe"}
	if !lifecycle.ValidID(f.node) {
		return q, cli.Usagef("--node SERVER is required")
	}
	if f.uid == 0 || f.uid >= 1<<32-1 || f.gid == 0 || f.gid >= 1<<32-1 {
		return q, cli.Usagef("--uid and --gid are required and must not be 0 (root)")
	}
	mode, err := strconv.ParseUint(f.mode, 8, 32)
	if err != nil || mode&0700 != 0700 || mode&^uint64(0770) != 0 {
		return q, cli.Usagef("--mode must give the owner rwx and nothing to others, such as 0750")
	}
	q.Mode = uint32(mode)
	if f.generation == 0 {
		return q, cli.Usagef("--generation must be 1 or more")
	}
	if f.size > 1<<40 {
		return q, cli.Usagef("--size is at most 1TiB")
	}
	return q, nil
}

func volumeCreateCommand(g *globals) *cli.Command {
	var f volumeCreateFlags
	return &cli.Command{
		Name:  "create",
		Args:  "APP/VOLUME",
		Short: "Create an empty volume on a server",
		Long: `Creates an empty volume for an app on one server. Data files belong to
--uid and --gid, which must not be root. --size reserves space in the
tenant's budget; it is not a filesystem quota.`,
		Flags: func(fs *flag.FlagSet) {
			f.register(fs, true, true)
			fs.StringVar(&f.node, "node", "", "`server` that holds the data")
			fs.UintVar(&f.uid, "uid", 0, "owner user ID of the data (not 0)")
			fs.UintVar(&f.gid, "gid", 0, "owner group ID of the data (not 0)")
			fs.StringVar(&f.mode, "mode", "0750", "permission `bits` of the data directory")
			fs.Uint64Var(&f.generation, "generation", 1, "generation `number`; raise it to create again after a delete")
			fs.Var(&f.size, "size", "space to reserve, such as 2GiB")
		},
		Run: func(c *cli.Context, args []string) error {
			ref, err := volumeArg(args, 1, "create needs one volume name APP/VOLUME", true)
			if err != nil {
				return err
			}
			if _, err = f.creation([32]byte{}, "", ref); err != nil {
				return err
			}
			s, tenant, err := g.volumeSession(c, args, 1, "create needs one volume name APP/VOLUME")
			if err != nil {
				return err
			}
			defer s.Close()
			q, err := f.creation(s.Client.Cluster, tenant, ref)
			if err != nil {
				return err
			}
			ok, err := g.confirm(c, &f.changeFlags, fmt.Sprintf("Create volume %s on %s in tenant %s (owner %d:%d, mode %04o, size %s).", ref, q.Node, tenant, q.UID, q.GID, q.Mode, orNone(volumeSizeText(q.CapacityBytes))))
			if !ok || err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			err = checkCreateBudget(ctx, s, tenant, q.Node, q.CapacityBytes)
			cancel()
			if err != nil {
				return err
			}
			ctx, cancel = g.Deadline(c)
			epoch, err := moduleEpoch(ctx, s)
			cancel()
			if err != nil {
				return err
			}
			return g.volumeChange(c, s, &f.changeFlags, "volume create "+ref.String(), "begin-volume-create", 0, epoch, q)
		},
	}
}

// checkCreateBudget says before sending what the server would only refuse as
// a changed record: once a server has a volume budget (--volume-size and
// --volumes, for the tenant and for the cluster), every new volume there
// needs --size, and a --size needs both budgets.
func checkCreateBudget(ctx context.Context, s *session, tenant, node string, size uint64) error {
	rows, err := readPublicRows(ctx, s, "volume-backup-limits", tenant, control.PublicReadQuery{Node: node})
	if err != nil {
		return err
	}
	var own *control.PublicBackupLimit
	for _, r := range rows {
		if r.BackupLimit != nil && r.BackupLimit.Tenant == tenant && r.BackupLimit.Node == node {
			own = r.BackupLimit
		}
	}
	tenantBudget := own != nil && own.Original != nil
	clusterBudget := own != nil && own.GlobalOriginal
	switch {
	case size == 0 && (tenantBudget || clusterBudget):
		return fmt.Errorf("%s has a volume budget, so a new volume there needs --size", node)
	case size != 0 && !tenantBudget:
		return fmt.Errorf("tenant %s has no volume budget on %s; set one first with 'mydc volume backup limits set --tenant %s --node %s --volume-size SIZE --volumes N', or leave out --size", tenant, node, tenant, node)
	case size != 0 && !clusterBudget:
		return fmt.Errorf("%s has no cluster volume budget; a system administrator sets one with 'mydc volume backup limits set --all --node %s --volume-size SIZE --volumes N', or leave out --size", node, node)
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func creationPendingPhase(phase string) bool { return phase == "Reserved" || phase == "Creating" }

func volumeDeleteCommand(g *globals) *cli.Command {
	var f changeFlags
	var retained string
	return &cli.Command{
		Name:  "delete",
		Args:  "APP/VOLUME",
		Short: "Delete an app volume and its data",
		Long: `Deletes the volume and its data. A volume that is still being created is
cancelled instead. With --retained MOVE only the old copy that a finished
move left on the source server is deleted; the volume stays.`,
		Flags: func(fs *flag.FlagSet) {
			f.register(fs, true, true)
			fs.StringVar(&retained, "retained", "", "delete only the old source copy left by this `move`")
		},
		Run: func(c *cli.Context, args []string) error {
			ref, err := volumeArg(args, 1, "delete needs one volume name APP/VOLUME", true)
			if err != nil {
				return err
			}
			if retained != "" && !lifecycle.ValidID(retained) {
				return cli.Usagef("--retained needs a move ID")
			}
			s, tenant, err := g.volumeSession(c, args, 1, "delete needs one volume name APP/VOLUME")
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
			action, expected, impact := "delete-volume", v.Revision, fmt.Sprintf("Delete volume %s on %s and all its data.", ref, v.Owner.Node)
			var payload any = v.Scope
			switch {
			case retained != "":
				action, payload = "delete-retained-volume", control.VolumeMoveSelection{Scope: v.Scope, ID: retained}
				impact = fmt.Sprintf("Delete the old copy of %s left on the source server by move %s. The volume itself stays.", ref, retained)
			case creationPendingPhase(v.Phase):
				action, expected = "cancel-volume-create", v.CreateRevision
				impact = fmt.Sprintf("Cancel creating volume %s on %s.", ref, v.Owner.Node)
			case v.Consumers > 0:
				impact += fmt.Sprintf(" %d service(s) still use it; the server refuses while they do.", v.Consumers)
			}
			ok, err := g.confirm(c, &f, impact)
			if !ok || err != nil {
				return err
			}
			return g.volumeChange(c, s, &f, "volume delete "+ref.String(), action, expected, epoch, payload)
		},
	}
}

func volumeRegisterCommand(g *globals) *cli.Command {
	var f changeFlags
	var node, storage, path string
	var rootGeneration, generation uint64
	var size cli.Size
	return &cli.Command{
		Name:  "register",
		Args:  "VOLUME",
		Short: "Register an existing directory on a server as a tenant volume",
		Long: `Registers an existing directory under a storage root of a server (see
'mydc node storage') as a volume of the tenant. The files stay where they
are; unregister keeps them too.`,
		Flags: func(fs *flag.FlagSet) {
			f.register(fs, true, true)
			fs.StringVar(&node, "node", "", "`server` with the directory")
			fs.StringVar(&storage, "storage", "", "storage `root` ID on that server")
			fs.Uint64Var(&rootGeneration, "root-generation", 0, "generation `number` of that storage root registration")
			fs.StringVar(&path, "path", "", "existing `directory` under the storage root")
			fs.Uint64Var(&generation, "generation", 1, "volume generation `number`")
			fs.Var(&size, "size", "space to reserve, such as 2GiB")
		},
		Run: func(c *cli.Context, args []string) error {
			ref, err := volumeArg(args, 1, "register needs one volume name", false)
			if err != nil {
				return err
			}
			if ref.App != "" {
				return cli.Usagef("a registered directory belongs to the tenant; give VOLUME without an app")
			}
			if !lifecycle.ValidID(node) || !lifecycle.ValidID(storage) || nodestorage.ValidateRootPath(path) != nil {
				return cli.Usagef("register needs --node, --storage and an absolute, clean --path")
			}
			if rootGeneration == 0 || generation == 0 || size > 1<<40 {
				return cli.Usagef("--root-generation and --generation must be 1 or more; --size is at most 1TiB")
			}
			s, tenant, err := g.volumeSession(c, args, 1, "register needs one volume name")
			if err != nil {
				return err
			}
			defer s.Close()
			q := control.VolumeFixedRegister{Scope: volumes.Scope{Cluster: s.Client.Cluster, Tenant: tenant, ID: ref.ID, Generation: generation}, Node: node, Storage: storage, Path: path, RootGeneration: rootGeneration, CapacityBytes: uint64(size), QuotaMode: "observe"}
			ok, err := g.confirm(c, &f, fmt.Sprintf("Register %s on %s (storage %s) as volume %s of tenant %s.", path, node, storage, ref, tenant))
			if !ok || err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			epoch, err := moduleEpoch(ctx, s)
			cancel()
			if err != nil {
				return err
			}
			return g.volumeChange(c, s, &f, "volume register "+ref.String(), "register-fixed-volume", 0, epoch, q)
		},
	}
}

func volumeUnregisterCommand(g *globals) *cli.Command {
	var f changeFlags
	return &cli.Command{
		Name:  "unregister",
		Args:  "VOLUME",
		Short: "Stop using a registered directory; its files stay",
		Run: func(c *cli.Context, args []string) error {
			ref, err := volumeArg(args, 1, "unregister needs one volume name", false)
			if err != nil {
				return err
			}
			if ref.App != "" {
				return cli.Usagef("%s is an app volume; use 'mydc volume delete'", ref)
			}
			s, tenant, err := g.volumeSession(c, args, 1, "unregister needs one volume name")
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
			action, expected := "unregister-fixed-volume", v.Revision
			var payload any = v.Scope
			impact := fmt.Sprintf("Unregister volume %s on %s. The directory and its files stay on the server.", ref, v.Owner.Node)
			if creationPendingPhase(v.Phase) {
				action, expected = "cancel-volume-create", v.CreateRevision
				impact = fmt.Sprintf("Cancel registering volume %s.", ref)
			}
			ok, err := g.confirm(c, &f, impact)
			if !ok || err != nil {
				return err
			}
			return g.volumeChange(c, s, &f, "volume unregister "+ref.String(), action, expected, epoch, payload)
		},
	}
}

// volumeArg checks the argument count and reads the first argument as a
// volume name, before anything asks for the wallet password.
func volumeArg(args []string, n int, usage string, appRequired bool) (volumeRef, error) {
	if len(args) != n {
		return volumeRef{}, cli.Usagef("%s", usage)
	}
	return parseVolumeRef(args[0], appRequired)
}

// sendResult gives a rejected change exit code 3 and an unknown outcome
// exit code 4.
func sendResult(r *state.Result, err error) error {
	if err != nil && r != nil {
		return cli.ExitError{Code: 3, Err: err}
	}
	return unknown(err)
}
