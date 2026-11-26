// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cli"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// Volume file commands read and write single files inside a volume without
// a container. Each one is a management change (the server checks the
// path, the size and the caller's folder grant) followed by one stream to
// the volume's server. The change is the operation; the file bytes are never
// saved in the operation history.

func init() {
	opKinds["volume-file"] = func(g *globals) cli.Handler {
		run := func(c *cli.Context, op cli.Op, resume bool) (cli.State, string, error) {
			s, err := g.opSession(c, op)
			if err != nil {
				return "", "", err
			}
			defer s.Close()
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return "", "", err
			}
			record, err := userauth.LoadOperation(s.Home, s.Client, s.Stored.Session, op.ID)
			if err != nil {
				return "", "", err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			if record.Result == nil {
				return cli.Sending, "not accepted yet; run the same command again with --id " + op.ID, nil
			}
			view, err := s.Client.VolumeFileStatus(ctx, s.Target, s.Stored.Session, tenant, control.VolumeFileID(record.Operation))
			if err != nil {
				return "", "", err
			}
			if view.Result != nil || view.Code != "" {
				return fileState(view.Code), "file " + strings.TrimPrefix(view.Method, "volume-file-") + " " + view.Phase, nil
			}
			action := record.Operation.Change.Action
			if !resume || action == "volume-file-put" || action == "volume-file-get" {
				return cli.Accepted, "run the same command again with --id " + op.ID + " to finish it", nil
			}
			reply, err := g.streamVolumeFile(c, s, record.Operation, nil, nil)
			if err != nil {
				return "", "", err
			}
			return fileState(reply.Code), "file " + strings.TrimPrefix(action, "volume-file-") + " " + reply.Code, nil
		}
		return cli.Handler{
			Show:   func(c *cli.Context, op cli.Op) (cli.State, string, error) { return run(c, op, false) },
			Resume: func(c *cli.Context, op cli.Op) (cli.State, string, error) { return run(c, op, true) },
		}
	}
}

func fileState(code string) cli.State {
	switch code {
	case "ok", "Completed", "completed":
		return cli.Done
	case "":
		return cli.Accepted
	}
	return cli.Failed
}

func volumeFilesCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "files",
		Short: "Read and write files inside a volume",
		Long: `Copies single files in and out of a volume without a container. Paths are
relative to the volume and directories end with '/'. A user needs a folder
grant ('mydc volume files grant') unless they manage the tenant.`,
		Sub: []*cli.Command{
			volumeFilesLsCommand(g),
			volumeFilesGetCommand(g),
			volumeFilesPutCommand(g),
			volumeFilesRmCommand(g),
			volumeFilesGrantCommand(g, "grant", "Let a user read and write under a directory", "volume-file-grant"),
			volumeFilesGrantCommand(g, "revoke", "Take a directory grant back from a user", "volume-file-revoke"),
			volumeFilesGrantsCommand(g),
		},
	}
}

// fileChange sends the management change of a file command and returns the
// accepted operation. With the ID of an earlier accepted change it returns
// that change without sending anything new.
func (g *globals) fileChange(c *cli.Context, s *session, tenant, summary, id string, q control.VolumeFileQuery) (control.UserOperation, bool, error) {
	if old, err := userauth.LoadOperation(s.Home, s.Client, s.Stored.Session, id); err == nil {
		var original control.VolumeFileChange
		if jsonUnmarshalVolumeFile(old.Operation, &original) != nil || old.Operation.Change.Action != q.Method || original.Scope.Tenant != tenant || original.Scope.App != q.App || original.Scope.ID != q.Volume || original.Path != q.Path {
			return control.UserOperation{}, false, fmt.Errorf("operation %s is a different file change", id)
		}
		if old.Result != nil {
			if q.Method == "volume-file-put" && (original.Size != q.Size || original.Digest != q.Digest) {
				return control.UserOperation{}, false, errors.New("the local file changed since this operation started; it can only finish with the original contents")
			}
			return old.Operation, false, nil
		}
	} else if !errors.Is(err, userauth.ErrOperationMissing) {
		return control.UserOperation{}, false, err
	}
	ctx, cancel := g.Deadline(c)
	plan, err := s.Client.VolumeFilePlan(ctx, s.Target, s.Stored.Session, tenant, q)
	var epoch uint64
	if err == nil {
		epoch, err = moduleEpoch(ctx, s)
	}
	cancel()
	if err != nil {
		return control.UserOperation{}, false, err
	}
	if err = sendResult(g.send(c, s, change{Kind: "volume-file", Summary: summary, ID: id, Action: q.Method, Expected: plan.Revision, Epoch: epoch, Payload: plan.Change})); err != nil {
		return control.UserOperation{}, false, err
	}
	record, err := userauth.LoadOperation(s.Home, s.Client, s.Stored.Session, id)
	if err != nil {
		return control.UserOperation{}, false, err
	}
	return record.Operation, true, nil
}

func jsonUnmarshalVolumeFile(op control.UserOperation, q *control.VolumeFileChange) error {
	switch op.Change.Action {
	case "volume-file-put", "volume-file-get", "volume-file-list", "volume-file-delete":
		return json.Unmarshal(op.Change.Payload, q)
	}
	return mydcp.ErrAdmission
}

// streamVolumeFile runs the native part of an accepted file change once.
func (g *globals) streamVolumeFile(c *cli.Context, s *session, op control.UserOperation, source io.Reader, sink io.Writer) (userauth.VolumeFileReply, error) {
	var original control.VolumeFileChange
	if err := jsonUnmarshalVolumeFile(op, &original); err != nil {
		return userauth.VolumeFileReply{}, err
	}
	job := control.VolumeFileJob{ID: control.VolumeFileID(op), Method: op.Change.Action, Origin: op, Request: original}
	ctx, cancel := g.Deadline(c)
	defer cancel()
	reply, err := s.Client.VolumeFile(ctx, s.Target, s.Stored.Session, job, source, sink)
	if err != nil {
		return reply, cli.ExitError{Code: 4, Err: fmt.Errorf("%w; the change is kept, run the same command again with --id %s", err, op.RequestID)}
	}
	if x, e := openOps(); e == nil {
		_ = x.Update(op.RequestID, fileState(reply.Code), "file "+strings.TrimPrefix(op.Change.Action, "volume-file-")+" "+reply.Code)
		x.Close()
	}
	return reply, nil
}

func fileArgs(args []string, n int, usage string) (volumeRef, error) {
	if len(args) != n {
		return volumeRef{}, cli.Usagef("%s", usage)
	}
	return parseVolumeRef(args[0], false)
}

func volumeFilesLsCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var after string
	return &cli.Command{
		Name:  "ls",
		Args:  "NAME [DIRECTORY/]",
		Short: "List files under a directory of a volume",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` to use instead of a new one")
			fs.StringVar(&after, "after", "", "start after this `path` (from the previous page)")
		},
		Run: func(c *cli.Context, args []string) error {
			dir := ""
			if len(args) == 2 {
				dir, args = args[1], args[:1]
			}
			ref, err := fileArgs(args, 1, "ls needs a volume name and an optional directory")
			if err != nil {
				return err
			}
			if dir != "" && !strings.HasSuffix(dir, "/") {
				dir += "/"
			}
			q := control.VolumeFileQuery{App: ref.App, Volume: ref.ID, Path: dir, After: after, Method: "volume-file-list"}
			if !q.Valid(false) {
				return cli.Usagef("%q is not a directory inside the volume", dir)
			}
			s, tenant, err := g.volumeSession(c, nil, 0, "")
			if err != nil {
				return err
			}
			defer s.Close()
			op, _, err := g.fileChange(c, s, tenant, "volume files ls "+ref.String()+" "+dir, id.Get(), q)
			if err != nil {
				return err
			}
			reply, err := g.streamVolumeFile(c, s, op, nil, nil)
			if err != nil {
				return err
			}
			entries := reply.Entries
			if entries == nil {
				entries = []volumes.FileEntry{}
			}
			err = cli.Print(c.Out, g.output.Format(), reply, func() cli.Rows {
				t := cli.Rows{Header: []string{"path", "size"}}
				for _, e := range entries {
					t.Add(e.Path, cli.Size(e.Size))
				}
				return t
			})
			if err == nil && reply.Next != "" && g.output.Format() == cli.Table {
				fmt.Fprintf(c.Err, "More files follow: add --after %s\n", reply.Next)
			}
			return err
		},
	}
}

func volumeFilesGetCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var maxSize cli.Size
	return &cli.Command{
		Name:  "get",
		Args:  "NAME PATH LOCAL-FILE",
		Short: "Copy a file out of a volume",
		Long:  "Writes the file to LOCAL-FILE, which must not exist yet. The file appears only after all of it arrived and was checked.",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` to use instead of a new one; reuse it to finish an interrupted copy")
			fs.Var(&maxSize, "max-size", "largest file to accept, such as 100MiB")
		},
		Run: func(c *cli.Context, args []string) error {
			ref, err := fileArgs(args, 3, "get needs a volume name, a path in the volume and a local file")
			if err != nil {
				return err
			}
			path, local := args[1], args[2]
			q := control.VolumeFileQuery{App: ref.App, Volume: ref.ID, Path: path, Method: "volume-file-get", MaxBytes: int64(maxSize)}
			if maxSize == 0 || int64(maxSize) > volumes.MaxFileBytes || !q.Valid(false) {
				return cli.Usagef("get needs a file path inside the volume and --max-size (at most %s)", cli.Size(volumes.MaxFileBytes))
			}
			if _, err = os.Lstat(local); !os.IsNotExist(err) {
				return cli.Usagef("%s already exists", local)
			}
			s, tenant, err := g.volumeSession(c, nil, 0, "")
			if err != nil {
				return err
			}
			defer s.Close()
			op, _, err := g.fileChange(c, s, tenant, "volume files get "+ref.String()+" "+path, id.Get(), q)
			if err != nil {
				return err
			}
			out, err := os.CreateTemp(filepath.Dir(local), ".mydc-file-get-")
			if err != nil {
				return err
			}
			temporary := out.Name()
			defer os.Remove(temporary)
			defer out.Close()
			reply, err := g.streamVolumeFile(c, s, op, nil, out)
			if err != nil {
				return err
			}
			if err = out.Sync(); err == nil {
				err = out.Close()
			}
			if err == nil {
				err = os.Link(temporary, local)
			}
			if err == nil {
				err = syncDir(filepath.Dir(local))
			}
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), reply, nil)
		},
	}
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

func volumeFilesPutCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var maxSize cli.Size
	var overwrite bool
	return &cli.Command{
		Name:  "put",
		Args:  "NAME LOCAL-FILE PATH",
		Short: "Copy a local file into a volume",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` to use instead of a new one; reuse it to finish an interrupted copy")
			fs.Var(&maxSize, "max-size", "largest size the file may have (default: its size now)")
			fs.BoolVar(&overwrite, "overwrite", false, "replace the file if it exists")
		},
		Run: func(c *cli.Context, args []string) error {
			ref, err := fileArgs(args, 3, "put needs a volume name, a local file and a path in the volume")
			if err != nil {
				return err
			}
			local, path := args[1], args[2]
			in, err := os.Open(local)
			if err != nil {
				return err
			}
			defer in.Close()
			info, err := in.Stat()
			if err != nil || !info.Mode().IsRegular() || info.Size() > volumes.MaxFileBytes {
				return cli.Usagef("%s must be a regular file of at most %s", local, cli.Size(volumes.MaxFileBytes))
			}
			h := sha256.New()
			if _, err = io.Copy(h, in); err != nil {
				return err
			}
			if _, err = in.Seek(0, io.SeekStart); err != nil {
				return err
			}
			if maxSize == 0 {
				maxSize = cli.Size(max(info.Size(), 1))
			}
			q := control.VolumeFileQuery{App: ref.App, Volume: ref.ID, Path: path, Method: "volume-file-put", MaxBytes: int64(maxSize), Size: info.Size(), Overwrite: overwrite}
			copy(q.Digest[:], h.Sum(nil))
			if !q.Valid(false) {
				return cli.Usagef("put needs a file path inside the volume and a --max-size no smaller than the file")
			}
			s, tenant, err := g.volumeSession(c, nil, 0, "")
			if err != nil {
				return err
			}
			defer s.Close()
			op, _, err := g.fileChange(c, s, tenant, "volume files put "+ref.String()+" "+path, id.Get(), q)
			if err != nil {
				return err
			}
			reply, err := g.streamVolumeFile(c, s, op, in, nil)
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), reply, nil)
		},
	}
}

func volumeFilesRmCommand(g *globals) *cli.Command {
	var f changeFlags
	return &cli.Command{
		Name:  "rm",
		Args:  "NAME PATH",
		Short: "Delete a file in a volume",
		Flags: func(fs *flag.FlagSet) { f.register(fs, false, true) },
		Run: func(c *cli.Context, args []string) error {
			ref, err := fileArgs(args, 2, "rm needs a volume name and a path in the volume")
			if err != nil {
				return err
			}
			q := control.VolumeFileQuery{App: ref.App, Volume: ref.ID, Path: args[1], Method: "volume-file-delete"}
			if !q.Valid(false) {
				return cli.Usagef("%q is not a file inside the volume", args[1])
			}
			s, tenant, err := g.volumeSession(c, nil, 0, "")
			if err != nil {
				return err
			}
			defer s.Close()
			if ok, err := g.confirm(c, &f, fmt.Sprintf("Delete %s in volume %s.", args[1], ref)); !ok || err != nil {
				return err
			}
			op, _, err := g.fileChange(c, s, tenant, "volume files rm "+ref.String()+" "+args[1], f.id.Get(), q)
			if err != nil {
				return err
			}
			reply, err := g.streamVolumeFile(c, s, op, nil, nil)
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), reply, nil)
		},
	}
}

func volumeFilesGrantCommand(g *globals, name, short, action string) *cli.Command {
	var f changeFlags
	return &cli.Command{
		Name:  name,
		Args:  "NAME DIRECTORY/ USER",
		Short: short,
		Flags: func(fs *flag.FlagSet) { f.register(fs, false, true) },
		Run: func(c *cli.Context, args []string) error {
			ref, err := fileArgs(args, 3, name+" needs a volume name, a directory ending in '/' and a user")
			if err != nil {
				return err
			}
			dir, user := args[1], args[2]
			if !access.ValidVolumeFilePath(dir, true) || !strings.HasSuffix(dir, "/") || !lifecycle.ValidID(user) {
				return cli.Usagef("%s needs a directory inside the volume ending in '/' and a user ID", name)
			}
			s, tenant, err := g.volumeSession(c, nil, 0, "")
			if err != nil {
				return err
			}
			defer s.Close()
			verb := "Let " + user + " read and write under"
			if name == "revoke" {
				verb = "Take back " + user + "'s access to"
			}
			if ok, err := g.confirm(c, &f, fmt.Sprintf("%s %s in volume %s.", verb, dir, ref)); !ok || err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			members, err := s.Client.TenantMembersPage(ctx, s.Target, s.Stored.Session, tenant, "")
			var epoch uint64
			if err == nil {
				epoch, err = moduleEpoch(ctx, s)
			}
			cancel()
			if err != nil {
				return err
			}
			q := access.VolumeFileFolderGrant{Tenant: tenant, App: ref.App, Volume: ref.ID, Prefix: dir, User: user}
			err = sendResult(g.send(c, s, change{Summary: "volume files " + name + " " + ref.String() + " " + dir + " " + user, ID: f.id.Get(), Action: action, Expected: members.TenantMembersRevision, Epoch: epoch, Payload: q}))
			if err == nil {
				fmt.Fprintln(c.Err, "Done.")
			}
			return err
		},
	}
}

func volumeFilesGrantsCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "grants",
		Args:  "[NAME]",
		Short: "List directory grants, of one volume or of the whole tenant",
		Run: func(c *cli.Context, args []string) error {
			if len(args) > 1 {
				return cli.Usagef("grants takes at most one volume name")
			}
			q := control.PublicReadQuery{}
			if len(args) == 1 {
				ref, err := parseVolumeRef(args[0], false)
				if err != nil {
					return err
				}
				q.Name, q.App = ref.ID, ref.App
			}
			s, tenant, err := g.volumeSession(c, nil, 0, "")
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			rows, err := readPublicRows(ctx, s, "volume-file-grants", tenant, q)
			if err != nil {
				return err
			}
			grants := []control.PublicFileGrant{}
			for _, r := range rows {
				if r.FileGrant != nil {
					grants = append(grants, *r.FileGrant)
				}
			}
			return cli.Print(c.Out, g.output.Format(), grants, func() cli.Rows {
				t := cli.Rows{Header: []string{"volume", "directory", "user", "enabled"}}
				for _, x := range grants {
					t.Add(volumeRef{App: x.App, ID: x.Volume}.String(), x.Prefix, x.User, x.AccountEnabled)
				}
				return t
			})
		},
	}
}
