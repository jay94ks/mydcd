// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/cli"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// A volume move stops the app, copies the volume to another server and
// deploys the app again from the given app.yaml. It is several management
// changes; they all hang off the move ID, which is also the operation ID.

func init() {
	opKinds["volume-move"] = func(g *globals) cli.Handler {
		run := func(c *cli.Context, op cli.Op, resume bool) (cli.State, string, error) {
			s, err := g.opSession(c, op)
			if err != nil {
				return "", "", err
			}
			defer s.Close()
			intent, err := userauth.LoadCompose(s.Home, s.Client, s.Stored.Session, op.ID)
			if err != nil {
				return "", "", err
			}
			if intent.Move == nil {
				return "", "", errors.New("the saved operation is not a volume move")
			}
			if resume {
				if err = g.runVolumeMove(c, s, intent, true, groupPasswordFDs{}); err != nil {
					return cli.Failed, err.Error(), nil
				}
				return cli.Done, "moved", nil
			}
			return g.volumeMoveState(c, s, intent)
		}
		return cli.Handler{
			Show:   func(c *cli.Context, op cli.Op) (cli.State, string, error) { return run(c, op, false) },
			Resume: func(c *cli.Context, op cli.Op) (cli.State, string, error) { return run(c, op, true) },
		}
	}
}

func volumeMoveCommand(g *globals) *cli.Command {
	var f changeFlags
	var file, planFile, savePlan string
	var maxSize cli.Size
	var maxEntries uint
	var transfer time.Duration
	var passwords groupPasswordFDs
	return &cli.Command{
		Name:  "move",
		Sub:   []*cli.Command{volumeMoveCancelCommand(g, &f)},
		Args:  "APP/VOLUME -f app.yaml | --plan FILE",
		Short: "Move an app volume to another server",
		Long: `Stops the app, copies the volume to the server that app.yaml now names for
it, and deploys the app from app.yaml. The old copy stays on the source
server until 'mydc volume delete APP/VOLUME --retained MOVE'.

Review first with --dry-run --save-plan FILE, then run exactly that plan
with --plan FILE.

The new deployment may need Secret Group approvals. Without them the
command asks for each group password on the terminal; scripts give
--group-password-fd REALM/GROUP=FD instead.`,
		Flags: func(fs *flag.FlagSet) {
			f.register(fs, false, true)
			fs.StringVar(&file, "f", "", "app.yaml with the volume on its new server")
			fs.Var(&maxSize, "max-size", "space to reserve for the copy, such as 10GiB")
			fs.UintVar(&maxEntries, "max-entries", 100000, "most files and directories to copy (1..100000)")
			fs.DurationVar(&transfer, "transfer-timeout", 15*time.Minute, "longest time the copy may take (1s..24h)")
			fs.StringVar(&savePlan, "save-plan", "", "with --dry-run, save the plan to this `file`")
			fs.StringVar(&planFile, "plan", "", "run the plan saved in this `file`")
			fs.Var(&passwords, "group-password-fd", "for scripts: read the password of `REALM/GROUP=FD` from that open file descriptor (repeat)")
		},
		Run: func(c *cli.Context, args []string) error {
			var plan control.AppMovePlan
			var raw, document []byte
			var ref volumeRef
			var id string
			var err error
			if planFile != "" {
				if len(args) != 0 || file != "" || maxSize != 0 || savePlan != "" || c.Set("id") {
					return cli.Usagef("--plan runs a saved plan; give no volume, -f, --max-size, --save-plan or --id with it")
				}
				if raw, err = os.ReadFile(planFile); err != nil {
					return err
				}
				if plan, err = control.DecodeAppMovePlan(bytes.TrimSpace(raw)); err != nil {
					return fmt.Errorf("%s is not a volume move plan", planFile)
				}
			} else {
				if ref, err = volumeArg(args, 1, "move needs one volume name APP/VOLUME and -f app.yaml", true); err != nil {
					return err
				}
				if maxSize < 1024 || maxSize > 1<<40 || maxEntries == 0 || maxEntries > 100000 {
					return cli.Usagef("--max-size (1KiB..1TiB) is required; --max-entries is 1..100000")
				}
				if transfer < time.Second || transfer > 24*time.Hour || transfer%time.Second != 0 {
					return cli.Usagef("--transfer-timeout is whole seconds from 1s to 24h")
				}
				if savePlan != "" && !f.dryRun {
					return cli.Usagef("--save-plan goes with --dry-run")
				}
				id = f.id.Get()
				if !c.Set("id") {
					id = "m" + id
				}
				if !lifecycle.ValidID(id) || len(id) > 61 {
					return cli.Usagef("a move ID has at most 61 characters")
				}
				if document, err = composeDocument(file); err != nil {
					return err
				}
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			if planFile == "" {
				ctx, cancel := g.Deadline(c)
				raw, err = s.Client.StreamAppPlan(ctx, s.Target, s.Stored.Session, tenant, control.AppPlanRequest{Document: document, Project: ref.App, Move: &control.AppMovePlanRequest{Volume: ref.ID, ID: id, MaxBytes: uint64(maxSize), MaxEntries: uint32(maxEntries), TransferSeconds: uint32(transfer / time.Second)}})
				cancel()
				if err != nil {
					return volumeLimitHint(err)
				}
				if plan, err = control.DecodeAppMovePlan(raw); err != nil || plan.Begin.ID != id || !ref.is(plan.Begin.Scope) {
					return mydcp.ErrAdmission
				}
			}
			b := plan.Begin
			if b.Scope.Cluster != s.Client.Cluster || b.Scope.Tenant != tenant {
				return fmt.Errorf("the plan is for tenant %s, not %s", b.Scope.Tenant, tenant)
			}
			fmt.Fprintf(c.Err, "Move volume %s to %s (copy up to %s). The app stops during the copy and is deployed again from the plan.\n", volumeName(b.Scope), b.Target.Node, cli.Size(b.MaxBytes))
			fmt.Fprintf(c.Err, "The plan expires at %s.\n", time.Unix(b.ExpiresAt, 0).Local().Format("2006-01-02 15:04:05"))
			if f.dryRun {
				if savePlan != "" {
					if err = saveComposePlan(savePlan, raw); err != nil {
						return err
					}
					fmt.Fprintf(c.Err, "Saved the plan to %s. Run it with 'mydc volume move --plan %s'.\n", savePlan, savePlan)
				}
				return nil
			}
			if err = g.Prompter(c).Confirm("Go ahead?"); err != nil {
				return err
			}
			if err = g.Record(s, "volume-move", "volume move "+volumeName(b.Scope)+" --to "+b.Target.Node, b.ID); err != nil {
				return err
			}
			intent, err := userauth.LoadCompose(s.Home, s.Client, s.Stored.Session, b.ID)
			if errors.Is(err, userauth.ErrOperationMissing) {
				intent, err = userauth.StageComposeMove(s.Home, s.Client, s.Stored.Session, plan)
			}
			if err != nil {
				return err
			}
			if intent.Move == nil || intent.Move.ID != b.ID || intent.Scope.Tenant != tenant {
				return fmt.Errorf("operation %s is already used by another change", b.ID)
			}
			fmt.Fprintf(c.Err, "Operation %s.\n", b.ID)
			return g.runVolumeMove(c, s, intent, false, passwords)
		},
	}
}

// volumeMoveCancelCommand stops a move that has not committed the new owner.
// A move whose plan expired before the copy began can only be cancelled. f is
// the parent move command's --id and --dry-run, which subcommands inherit.
func volumeMoveCancelCommand(g *globals, f *changeFlags) *cli.Command {
	return &cli.Command{
		Name:  "cancel",
		Args:  "APP/VOLUME",
		Short: "Stop a move that has not finished",
		Long: `Stops the volume's current move before the new server takes over. Both
servers remove what the move prepared and the volume stays on its source
server. A move whose plan expired before the copy started cannot continue;
cancel it and plan the move again.`,
		Run: func(c *cli.Context, args []string) error {
			ref, err := volumeArg(args, 1, "cancel needs one volume name APP/VOLUME", true)
			if err != nil {
				return err
			}
			s, tenant, err := g.volumeSession(c, args, 1, "cancel needs one volume name APP/VOLUME")
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
			if v.Phase != "Moving" || v.MoveID == "" {
				return fmt.Errorf("volume %s has no move to cancel (it is %s)", ref, v.Phase)
			}
			ok, err := g.confirm(c, f, fmt.Sprintf("Cancel move %s of %s to %s (now %s). The volume stays on %s.", v.MoveID, ref, v.TargetNode, v.MovePhase, v.Owner.Node))
			if !ok || err != nil {
				return err
			}
			payload := control.VolumeMoveSelection{Scope: v.Scope, ID: v.MoveID}
			return g.volumeChange(c, s, f, "volume move cancel "+ref.String()+" "+v.MoveID, "cancel-volume-move", v.Revision, epoch, payload)
		},
	}
}

// runVolumeMove sends the move's changes in order: upload the app plan,
// accept the move, then the group approvals the new deployment needs. Every
// change has a fixed ID under the move, so running it again (op resume)
// continues the same move and never starts another.
func (g *globals) runVolumeMove(c *cli.Context, s *session, intent userauth.ComposeIntent, resume bool, passwords groupPasswordFDs) error {
	tenant := intent.Scope.Tenant
	ctx, cancel := context.WithTimeout(c.Ctx, g.timeout+time.Duration(len(intent.Artifact)/deployment.ArtifactPartBytes+2)*g.timeout)
	defer cancel()
	phase := func(name, action string, expected uint64, payload any) error {
		id := "volume-move/" + intent.ID + "/" + name
		result, err := managementMutation(ctx, s.Client, s.Target, s.Stored, s.Home, id, action, expected, intent.Epoch, payload, resume)
		if err != nil {
			return cli.ExitError{Code: 4, Err: fmt.Errorf("%s: %w; continue with 'mydc op resume %s'", name, err, intent.ID)}
		}
		if result.Code != state.Applied {
			return cli.ExitError{Code: 3, Err: fmt.Errorf("%s was rejected: %v", name, result.Code)}
		}
		return nil
	}
	if err := phase("upload", "begin-app-upload", 0, control.AppUploadBegin{Tenant: tenant, App: intent.Scope.App, Deployment: intent.Scope.Deployment, ID: intent.ID, Length: intent.Length, Digest: intent.Digest}); err != nil {
		return err
	}
	for index, start := 0, 0; start < intent.Length; index, start = index+1, start+deployment.ArtifactPartBytes {
		part := control.AppUploadPart{Tenant: tenant, ID: intent.ID, Index: index, Data: intent.Artifact[start:min(intent.Length, start+deployment.ArtifactPartBytes)]}
		if err := phase(fmt.Sprintf("part-%03d", index), "put-app-part", uint64(index+1), part); err != nil {
			return err
		}
	}
	if err := phase("accept", "begin-volume-move", intent.Expected, *intent.Move); err != nil {
		return err
	}
	acceptID := "volume-move/" + intent.ID + "/accept"
	record, err := userauth.LoadOperation(s.Home, s.Client, s.Stored.Session, acceptID)
	if err != nil {
		return err
	}
	exact, err := s.Client.AppOperation(ctx, s.Target, s.Stored.Session, tenant, control.AppOperationRequest{App: intent.Scope.App, ID: intent.ID})
	if err != nil {
		return err
	}
	if !exact.AppOperation.Found || exact.AppOperation.Current {
		o := composeOptions{method: "up", operation: onceString{value: intent.ID, set: true}, noInput: g.noInput, passwordFDs: passwords}
		if resume {
			o.method = "resume"
		}
		if err = ensureComposeApprovals(ctx, o, intent, record.Operation, tenant, s.Home, s.Client, s.Target, s.Stored, c.Err); err != nil {
			code := 4
			var problem *composeApprovalFailure
			if errors.As(err, &problem) {
				code = problem.code
			}
			return cli.ExitError{Code: code, Err: fmt.Errorf("approval needed: %w; continue with 'mydc op resume %s'", err, intent.ID)}
		}
	}
	fmt.Fprintf(c.Err, "Accepted. Follow the move with 'mydc volume show %s/%s'.\n", intent.Scope.App, intent.Move.Scope.ID)
	if x, e := openOps(); e == nil {
		_ = x.Update(intent.ID, cli.Accepted, "move accepted")
		x.Close()
	}
	return nil
}

// volumeMoveState reads where a move stands without sending anything.
func (g *globals) volumeMoveState(c *cli.Context, s *session, intent userauth.ComposeIntent) (cli.State, string, error) {
	record, err := userauth.LoadOperation(s.Home, s.Client, s.Stored.Session, "volume-move/"+intent.ID+"/accept")
	if errors.Is(err, userauth.ErrOperationMissing) {
		return cli.Sending, "move not accepted yet; 'mydc op resume' continues it", nil
	}
	if err != nil {
		return "", "", err
	}
	result := record.Result
	ctx, cancel := g.Deadline(c)
	defer cancel()
	if result == nil {
		reply, err := s.Client.Result(ctx, s.Target, s.Stored.Session, record.Operation)
		if err != nil || !reply.Found || reply.Result == nil {
			return cli.Sending, "outcome unknown; 'mydc op resume' continues it", nil
		}
		result = reply.Result
	}
	if result.Code != state.Applied {
		st, detail := changeState(*result, false)
		return st, detail, nil
	}
	ref := volumeRef{App: intent.Scope.App, ID: intent.Move.Scope.ID}
	v, _, err := findVolumeView(ctx, s, intent.Scope.Tenant, ref)
	if err != nil {
		return "", "", err
	}
	if v.Phase == "Moving" && v.MoveID == intent.ID {
		if v.MovePhase == volumes.Prepared && v.MoveExpiresAt != 0 && time.Now().Unix() >= v.MoveExpiresAt {
			return cli.Accepted, fmt.Sprintf("plan expired before the copy started; cancel with 'mydc volume move cancel %s' and plan again", ref), nil
		}
		return cli.Accepted, fmt.Sprintf("moving (%s)", v.MovePhase), nil
	}
	for _, r := range v.Retained {
		if r.Move == intent.ID {
			return cli.Done, "moved to " + v.Owner.Node, nil
		}
	}
	return cli.Accepted, "volume is " + v.Phase, nil
}

// volumeLimitHint tells how to fix a move target that has no room for the
// copy. Volume space is reserved per server for the tenant and the cluster.
func volumeLimitHint(err error) error {
	var input *deployment.InputError
	if !errors.As(err, &input) {
		return err
	}
	switch input.Code {
	case "TARGET_VOLUME_LIMIT_MISSING":
		return fmt.Errorf("%w; the target server has no volume space set for this tenant and the cluster: set both with 'mydc volume backup limits --node NODE set --volume-size SIZE --volumes N' and again with --all", err)
	case "TARGET_VOLUME_LIMIT_FULL":
		return fmt.Errorf("%w; the volume space on the target server is used up: raise it with 'mydc volume backup limits --node NODE set --volume-size SIZE --volumes N' (and --all for the cluster limit)", err)
	case "TARGET_STAGING_LIMIT_CLUSTER", "TARGET_STAGING_LIMIT_TENANT", "SOURCE_BACKUP_LIMIT_CLUSTER", "SOURCE_BACKUP_LIMIT_TENANT":
		server, kind, scope := "target", "--staging-size SIZE --staging-backups N", "the tenant limit"
		if strings.HasPrefix(input.Code, "SOURCE_") {
			server, kind = "source", "--max-size SIZE --max-backups N"
		}
		if strings.HasSuffix(input.Code, "_CLUSTER") {
			scope = "the cluster limit (--all)"
		}
		return fmt.Errorf("%w; the copy needs room in %s on the %s server: set it with 'mydc volume backup limits --node NODE set %s'", err, scope, server, kind)
	}
	return err
}
