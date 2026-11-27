// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
)

// Drain, isolate, restore, remove and rotate-key keep running after the
// server accepts them; other node changes use the plain "change" kind.
func init() {
	followKind("node-drain", followDrain)
	followKind("node-lifecycle", followLifecycle)
	followKind("node-rotate-key", followRotateKey)
}

// changeFlags are the options every changing command takes.
type changeFlags struct {
	id       cli.IDFlag
	revision cli.RevisionFlag
	noWait   bool
	dryRun   bool
}

func (f *changeFlags) register(fs *flag.FlagSet, wait, dryRun bool) {
	fs.Var(&f.id, "id", "operation `id` to use instead of a new one")
	fs.Var(&f.revision, "if-revision", "change only if the record is still at this `revision`")
	if wait {
		fs.BoolVar(&f.noWait, "no-wait", false, "return once the server accepts the change")
	}
	if dryRun {
		fs.BoolVar(&f.dryRun, "dry-run", false, "only show what would change")
	}
}

// expect returns the revision to send: --if-revision, else the one just
// read. A stale --if-revision is sent as given and the server refuses it.
func (f *changeFlags) expect(current uint64) uint64 {
	v, _ := f.revision.Resolve(func() (uint64, error) { return current, nil })
	return v
}

// operationID is the server-side ID of long node work. It is the request
// ID itself, so one ID names the whole change.
func operationID(id string) (string, error) {
	if !lifecycle.ValidID(id) {
		return "", cli.Usagef("operation id %q is not valid; pass another --id", id)
	}
	return id, nil
}

func nodeAddCommand(g *globals) *cli.Command {
	var f changeFlags
	var endpoint, key string
	var replace bool
	return &cli.Command{
		Name:  "add",
		Args:  "NODE",
		Short: "Register a new server so it can join (system administrator)",
		Long: `Registers a server by name, address and public key. On the new server,
'sfcd identity' prints the key. Then export the invitation with
'sfcli node invite NODE' and run 'sfcd join --invitation FILE' there.
The server joins as a non-voter; 'sfcli node promote' makes it a voter.
A server that was added but never joined can be added again with
--replace (for example with a new key), or forgotten with 'sfcli node
remove NODE'.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&endpoint, "endpoint", "", "`host:port` the cluster reaches the server at")
			fs.StringVar(&key, "public-key", "", "the server's public `key` (64 hex characters)")
			fs.BoolVar(&replace, "replace", false, "cancel the invitation of a server with this name that never joined, then register it again")
			f.register(fs, false, false)
		},
		Run: func(c *cli.Context, args []string) error {
			node, err := nodeArg(args, "add")
			if err != nil {
				return err
			}
			parsed, err := identity.ParseKey(key)
			if err != nil || fmt.Sprintf("%x", parsed) != key {
				return cli.Usagef("--public-key must be 64 lower-case hex characters")
			}
			if config.ValidateCanonicalEndpoint(endpoint) != nil {
				return cli.Usagef("--endpoint must be host:port")
			}
			id := f.id.Get()
			join, err := operationID(id)
			if err != nil {
				return err
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			nodes, err := readNodes(ctx, s)
			cancel()
			if err != nil {
				return err
			}
			if old, found := nodes.entry(node); found {
				if old.Phase == membership.Learner {
					return cli.ExitError{Code: 3, Err: fmt.Errorf("server %s started joining (learner); run 'sfcli node remove %s' to give up that join, and add it again once 'sfcli node list' no longer shows it", node, node)}
				}
				if !replace {
					return cli.ExitError{Code: 3, Err: fmt.Errorf("server %s is already registered (phase %s); to register it again with another key or endpoint before it joins, run 'sfcli node add %s --replace ...'", node, old.Phase, node)}
				}
				if err := cancelInvite(c, g, s, &changeFlags{}, id+"-cancel", old); err != nil {
					return err
				}
			}
			return g.apply(c, s, change{Summary: "node add " + node, ID: id, Action: "invite-node",
				Payload: control.NodeInvitation{Peer: config.Peer{ID: node, Key: key, Endpoint: endpoint}, JoinID: join}}, false)
		},
	}
}

func nodeInviteCommand(g *globals) *cli.Command {
	var file string
	return &cli.Command{
		Name:  "invite",
		Args:  "NODE",
		Short: "Print the signed invitation a registered server joins with",
		Long:  "Prints the invitation for 'sfcd join --invitation FILE'. Register the server with 'sfcli node add' first.",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&file, "out", "", "write to this new `file` instead of standard output")
		},
		Run: func(c *cli.Context, args []string) error {
			node, err := nodeArg(args, "invite")
			if err != nil {
				return err
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			invitation, err := s.Client.NodeInvitation(ctx, s.Target, s.Stored.Session, node)
			if err != nil {
				return err
			}
			raw, err := invitation.Encode()
			if err != nil {
				return err
			}
			if file == "" {
				_, err = c.Out.Write(raw)
				return err
			}
			f, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			_, err = f.Write(raw)
			// Close can report a write the disk could not keep.
			return errors.Join(err, f.Close())
		},
	}
}

func nodeVoteCommand(g *globals, verb string) *cli.Command {
	var f changeFlags
	short := "Make a joined server a voter (system administrator)"
	if verb == "demote" {
		short = "Make a voter a non-voter (system administrator)"
	}
	return &cli.Command{
		Name:  verb,
		Args:  "NODE",
		Short: short,
		Flags: func(fs *flag.FlagSet) { f.register(fs, false, verb == "demote") },
		Run: func(c *cli.Context, args []string) error {
			node, err := nodeArg(args, verb)
			if err != nil {
				return err
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			var expected uint64
			if verb == "promote" {
				d, err := readNodes(ctx, s)
				if err != nil {
					return err
				}
				e, ok := d.entry(node)
				if !ok {
					return fmt.Errorf("no node %s", node)
				}
				expected = e.Revision
			} else {
				plan, err := s.Client.NodeDemotePlan(ctx, s.Target, s.Stored.Session, node)
				if err != nil {
					return err
				}
				fmt.Fprintf(c.Err, "Voters after: %d (quorum %d, can lose %d)\n", plan.VotersAfter, plan.QuorumAfter, plan.FaultToleranceAfter)
				if err := blockers(c, plan.Blockers); err != nil {
					return err
				}
				if f.dryRun {
					return nil
				}
				if err := g.Prompter(c).Confirm("Demote " + node + "?"); err != nil {
					return err
				}
				expected = plan.Expected
			}
			id := f.id.Get()
			return g.apply(c, s, change{Summary: "node " + verb + " " + node, ID: id, Action: verb + "-node",
				Expected: f.expect(expected), Payload: control.NodeSelection{ID: node}}, false)
		},
	}
}

func blockers(c *cli.Context, list []control.NodeBlocker) error {
	if len(list) == 0 {
		return nil
	}
	fmt.Fprintln(c.Err, "Blocked by:")
	for _, b := range list {
		fmt.Fprintf(c.Err, "  %s  %s\n", b.Code, b.Detail)
	}
	return cli.ExitError{Code: 3, Err: errors.New("the change is blocked; nothing was sent")}
}

func nodeCordonCommand(g *globals, verb string) *cli.Command {
	var f changeFlags
	short, use := "Stop placing new containers on a server (running ones stay)", "NODE [REASON]"
	if verb == "uncordon" {
		short, use = "Allow new containers on a server again", "NODE"
	}
	return &cli.Command{
		Name:  verb,
		Args:  use,
		Short: short,
		Long: `cordon keeps running containers where they are and only stops new ones
from being placed on the server. REASON is an optional one-line note (up to
256 characters) shown by 'sfcli node list --all' and 'sfcli node show'.`,
		Flags: func(fs *flag.FlagSet) { f.register(fs, false, false) },
		Run: func(c *cli.Context, args []string) error {
			reason := ""
			if verb == "cordon" && len(args) == 2 {
				reason, args = args[1], args[:1]
			}
			node, err := nodeArg(args, verb)
			if err != nil {
				return err
			}
			var payload any = control.NodeSelection{ID: node}
			if verb == "cordon" {
				cordon := control.NodeCordonChange{ID: node, Reason: reason}
				if !cordon.Valid() {
					return cli.Usagef("the reason must be one line of at most 256 characters")
				}
				payload = cordon
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			d, err := readNodes(ctx, s)
			if err != nil {
				return err
			}
			v, ok := d.view(node)
			if !ok {
				return fmt.Errorf("no installed node %s", node)
			}
			if v.Scheduling.Enabled == (verb == "cordon") {
				fmt.Fprintf(c.Out, "%s is already %s\n", node, scheduling(v.Scheduling))
				return nil
			}
			return g.apply(c, s, change{Summary: "node " + verb + " " + node, ID: f.id.Get(), Action: verb + "-node",
				Expected: f.expect(v.Scheduling.Revision), Payload: payload}, false)
		},
	}
}

func nodeDrainCommand(g *globals) *cli.Command {
	var f changeFlags
	var leaveBlocked bool
	return &cli.Command{
		Name:  "drain",
		Args:  "NODE",
		Short: "Move the containers off a server (system administrator)",
		Long: `Moves every movable container to other servers and waits until they
run there. Cordon the server first so nothing new lands on it. Containers
that cannot move block the drain unless --leave-blocked.`,
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&leaveBlocked, "leave-blocked", false, "move what can move and leave blocked containers")
			f.register(fs, true, true)
		},
		Run: func(c *cli.Context, args []string) error {
			node, err := nodeArg(args, "drain")
			if err != nil {
				return err
			}
			id := f.id.Get()
			operation, err := operationID(id)
			if err != nil {
				return err
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			plan, err := s.Client.NodeDrainPlan(ctx, s.Target, s.Stored.Session, control.NodeDrainQuery{Node: node, Operation: operation})
			if err != nil {
				return err
			}
			movable, blocked := 0, 0
			for _, t := range plan.Tasks {
				if t.Movable {
					movable++
				} else {
					blocked++
				}
			}
			fmt.Fprintf(c.Err, "%d containers move, %d cannot move, %d apps change\n", movable, blocked, len(plan.Jobs))
			if !leaveBlocked {
				if err := blockers(c, plan.Blockers); err != nil {
					return err
				}
			}
			if f.dryRun {
				return cli.Print(c.Out, g.output.Format(), plan, nil)
			}
			if err := g.Prompter(c).Confirm("Drain " + node + "?"); err != nil {
				return err
			}
			if f.revision.String() != "" && f.expect(plan.Expected) != plan.Expected {
				return cli.ExitError{Code: 3, Err: errors.New("the server's scheduling revision changed; nothing was sent")}
			}
			return g.apply(c, s, change{Kind: "node-drain", Async: true, Summary: "node drain " + node, ID: id, Action: "drain-node", Expected: plan.Expected,
				Payload: control.NodeDrainChange{At: plan.At, ID: node, Operation: operation, LeaveBlocked: leaveBlocked, AppsRoot: plan.AppsRoot, Plan: plan.Digest, Jobs: plan.Jobs}}, f.noWait)
		},
	}
}

func followDrain(ctx context.Context, s *session, op control.UserOperation) (cli.State, string, error) {
	var q control.NodeDrainChange
	if err := json.Unmarshal(op.Change.Payload, &q); err != nil {
		return "", "", err
	}
	st, err := s.Client.NodeDrainStatus(ctx, s.Target, s.Stored.Session, control.NodeDrainQuery{Node: q.ID, Operation: q.Operation})
	if err != nil {
		return "", "", err
	}
	detail := fmt.Sprintf("%s: %d of %d moved, %d blocked", st.State, st.Moved, st.Total, st.Blocked)
	for _, job := range st.Jobs {
		if job.State == "Failed" {
			return cli.Failed, detail + "; " + job.Tenant + "/" + job.App + " failed", nil
		}
	}
	switch st.State {
	case "Succeeded", "Partial":
		return cli.Done, detail, nil
	}
	return cli.Accepted, detail, nil
}

func nodeLifecycleCommand(g *globals, verb string) *cli.Command {
	var f changeFlags
	short := "Take a server out of the cluster's work, keeping its data (system administrator)"
	if verb == "restore" {
		short = "Bring an isolated server back (system administrator)"
	}
	return &cli.Command{
		Name:  verb,
		Args:  "NODE",
		Short: short,
		Flags: func(fs *flag.FlagSet) { f.register(fs, true, false) },
		Run: func(c *cli.Context, args []string) error {
			node, err := nodeArg(args, verb)
			if err != nil {
				return err
			}
			id := f.id.Get()
			operation, err := operationID(id)
			if err != nil {
				return err
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			d, err := readNodes(ctx, s)
			if err != nil {
				return err
			}
			v, ok := d.view(node)
			if !ok {
				return fmt.Errorf("no installed node %s", node)
			}
			if v.Node.Pending != nil {
				return cli.ExitError{Code: 3, Err: fmt.Errorf("%s is busy with %s %s; follow it with 'sfcli op show'", node, v.Node.Pending.Action, v.Node.Pending.ID)}
			}
			if verb == "isolate" {
				if err := g.Prompter(c).Confirm("Isolate " + node + "?"); err != nil {
					return err
				}
			}
			return g.apply(c, s, change{Kind: "node-lifecycle", Async: true, Summary: "node " + verb + " " + node, ID: id, Action: verb + "-node",
				Expected: f.expect(v.Node.Revision), Payload: control.NodeLifecycleChange{ID: node, Operation: operation, Epoch: d.OperationEpoch}}, f.noWait)
		},
	}
}

func nodeRemoveCommand(g *globals) *cli.Command {
	var f changeFlags
	var force bool
	return &cli.Command{
		Name:  "remove",
		Args:  "NODE",
		Short: "Remove a server from the cluster (system administrator)",
		Long: `Removes a drained server. The server must hold no containers, volumes
or storage the cluster still needs. --force removes a server that is gone
for good; what it held is kept as stranded records, not deleted.
A server that was added but never joined is not removed but forgotten: its
invitation is cancelled and its name, key and endpoint are free again.`,
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&force, "force", false, "remove a server that cannot be reached")
			f.register(fs, true, true)
		},
		Run: func(c *cli.Context, args []string) error {
			node, err := nodeArg(args, "remove")
			if err != nil {
				return err
			}
			id := f.id.Get()
			operation, err := operationID(id)
			if err != nil {
				return err
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			// A server that never joined is not removed but forgotten:
			// its invitation is cancelled and the name is free again.
			nodes, err := readNodes(ctx, s)
			if err != nil {
				return err
			}
			entry, found := nodes.entry(node)
			if !found {
				return fmt.Errorf("server %s is not registered in this cluster ('sfcli node list' shows the servers)", node)
			}
			if entry.Phase == membership.Invited || entry.Phase == membership.Learner {
				return cancelInvite(c, g, s, &f, id, entry)
			}
			var plan control.NodeRemovePlan
			var ch change
			if force {
				p, err := s.Client.NodeForceRemovePlan(ctx, s.Target, s.Stored.Session, control.NodeForceQuery{Node: node, Operation: operation})
				if err != nil {
					return err
				}
				plan = p.NodeRemovePlan
				if p.Probe == nil && len(plan.Blockers) == 0 {
					return cli.ExitError{Code: 3, Err: errors.New("the server is still reachable; remove it without --force")}
				}
				ch = change{Action: "force-remove-node"}
				if p.Probe != nil {
					ch.Payload = control.NodeForceChange{ID: node, Operation: operation, Epoch: p.Epoch, Probe: *p.Probe}
				}
			} else {
				if plan, err = s.Client.NodeRemovePlan(ctx, s.Target, s.Stored.Session, node); err != nil {
					return err
				}
				ch = change{Action: "remove-node", Payload: control.NodeLifecycleChange{ID: node, Operation: operation, Epoch: plan.Epoch}}
			}
			fmt.Fprintf(c.Err, "Voters after: %d (quorum %d, can lose %d); %d containers, %d volumes, %d storage roots stay behind\n",
				plan.VotersAfter, plan.QuorumAfter, plan.FaultToleranceAfter, len(plan.Tasks), len(plan.Volumes), len(plan.Storage))
			if err := blockers(c, plan.Blockers); err != nil {
				return err
			}
			if f.dryRun {
				return cli.Print(c.Out, g.output.Format(), plan, nil)
			}
			if err := g.Prompter(c).Confirm("Remove " + node + " from the cluster?"); err != nil {
				return err
			}
			if f.revision.String() != "" && f.expect(plan.Expected) != plan.Expected {
				return cli.ExitError{Code: 3, Err: errors.New("the server changed; nothing was sent")}
			}
			ch.Kind, ch.Summary, ch.ID, ch.Expected, ch.Async = "node-lifecycle", "node remove "+node, id, plan.Expected, true
			return g.apply(c, s, ch, f.noWait)
		},
	}
}

// cancelInvite forgets a server that was added but never finished
// joining, or says precisely why it cannot be forgotten yet.
func cancelInvite(c *cli.Context, g *globals, s *session, f *changeFlags, id string, entry membership.Entry) error {
	node := entry.Peer.ID
	action, prompt := "cancel-node-invite", "Cancel the invitation of "+node+"?"
	switch err := membership.CancelableInvite(entry); {
	case err == nil:
		fmt.Fprintf(c.Err, "%s was added but never joined: its invitation is cancelled, and the name %s, its key and endpoint can be used again\n", node, node)
	case entry.Phase == membership.Learner && entry.Abort != nil:
		return cli.ExitError{Code: 3, Err: fmt.Errorf("the join of %s is already being given up; the leader removes it from Raft and then forgets it", node)}
	case entry.Phase == membership.Learner && entry.Ack == nil:
		action, prompt = "abort-node-join", "Give up the join of "+node+"?"
		fmt.Fprintf(c.Err, "%s started joining but never finished (it is a Raft learner that did not confirm its install): the leader removes it from Raft, then the name %s, its key and endpoint can be used again. If the server is still running, stop its sfcd first\n", node, node)
	case errors.Is(err, membership.ErrJoinStarted):
		return cli.ExitError{Code: 3, Err: fmt.Errorf("the join of %s was just sent to Raft and its result is being settled by the leader; run this again in a minute", node)}
	default:
		return cli.ExitError{Code: 3, Err: fmt.Errorf("server %s is %s, not a join that can be cancelled", node, entry.Phase)}
	}
	if f.dryRun {
		return cli.Print(c.Out, g.output.Format(), map[string]any{"node": node, "action": action, "expected": entry.Revision}, nil)
	}
	if err := g.Prompter(c).Confirm(prompt); err != nil {
		return err
	}
	if f.revision.String() != "" && f.expect(entry.Revision) != entry.Revision {
		return cli.ExitError{Code: 3, Err: errors.New("the server changed; nothing was sent")}
	}
	return g.apply(c, s, change{Summary: "node remove " + node + " (" + action + ")", ID: id, Action: action, Expected: entry.Revision, Payload: control.NodeSelection{ID: node}}, false)
}

func nodeRenewCommand(g *globals) *cli.Command {
	var f changeFlags
	return &cli.Command{
		Name:  "renew",
		Args:  "NODE",
		Short: "Take over a stalled isolate, restore or remove with your own authority (system administrator)",
		Long: `A node operation keeps running on the authority of the administrator who
started it. If that authority is gone (the account was disabled or lost
the role), the operation waits. renew lets you carry the same operation on
with your authority; it does not start a new one.`,
		Flags: func(fs *flag.FlagSet) { f.register(fs, true, false) },
		Run: func(c *cli.Context, args []string) error {
			node, err := nodeArg(args, "renew")
			if err != nil {
				return err
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			d, err := readNodes(ctx, s)
			if err != nil {
				return err
			}
			v, ok := d.view(node)
			if !ok || v.Node.Pending == nil {
				return cli.ExitError{Code: 3, Err: fmt.Errorf("%s has no operation in progress", node)}
			}
			p := v.Node.Pending
			fmt.Fprintf(c.Err, "%s %s %s is in progress\n", node, p.Action, p.ID)
			return g.apply(c, s, change{Kind: "node-lifecycle", Async: true, Summary: "node renew " + node, ID: f.id.Get(), Action: "resume-node-operation",
				Expected: f.expect(v.Node.Revision), Payload: control.NodeLifecycleChange{ID: node, Operation: p.ID, Epoch: p.Epoch}}, f.noWait)
		},
	}
}

func lifecycleTarget(op control.UserOperation) (node, operation string, err error) {
	var q struct{ ID, Operation string }
	if err = json.Unmarshal(op.Change.Payload, &q); err != nil {
		return "", "", err
	}
	return q.ID, q.Operation, nil
}

func followLifecycle(ctx context.Context, s *session, op control.UserOperation) (cli.State, string, error) {
	node, operation, err := lifecycleTarget(op)
	if err != nil {
		return "", "", err
	}
	d, err := readNodes(ctx, s)
	if err != nil {
		return "", "", err
	}
	v, ok := d.view(node)
	if !ok {
		if _, member := d.entry(node); !member && op.Change.Action != "isolate-node" && op.Change.Action != "restore-node" {
			return cli.Done, node + " removed", nil
		}
		return cli.Accepted, node + " is not installed yet", nil
	}
	if v.Node.Pending != nil && v.Node.Pending.ID == operation {
		return cli.Accepted, fmt.Sprintf("%s: %s", node, v.Node.Phase), nil
	}
	return cli.Done, fmt.Sprintf("%s: %s", node, v.Node.Phase), nil
}

func nodeRotateKeyCommand(g *globals) *cli.Command {
	var f changeFlags
	return &cli.Command{
		Name:  "rotate-key",
		Args:  "NODE",
		Short: "Give a server a new identity key (system administrator)",
		Flags: func(fs *flag.FlagSet) { f.register(fs, true, false) },
		Run: func(c *cli.Context, args []string) error {
			node, err := nodeArg(args, "rotate-key")
			if err != nil {
				return err
			}
			id := f.id.Get()
			operation, err := operationID(id)
			if err != nil {
				return err
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			d, err := readNodes(ctx, s)
			if err != nil {
				return err
			}
			e, ok := d.entry(node)
			if !ok {
				return fmt.Errorf("no node %s", node)
			}
			if err := g.Prompter(c).Confirm("Rotate the identity key of " + node + "?"); err != nil {
				return err
			}
			return g.apply(c, s, change{Kind: "node-rotate-key", Async: true, Summary: "node rotate-key " + node, ID: id, Action: "rotate-node-identity",
				Expected: f.expect(e.Revision), Payload: control.NodeIdentityChange{ID: node, Operation: operation}}, f.noWait)
		},
	}
}

func followRotateKey(ctx context.Context, s *session, op control.UserOperation) (cli.State, string, error) {
	node, operation, err := lifecycleTarget(op)
	if err != nil {
		return "", "", err
	}
	d, err := readNodes(ctx, s)
	if err != nil {
		return "", "", err
	}
	v, ok := d.view(node)
	if !ok || v.Identity == nil || v.Identity.Operation != operation {
		return cli.Accepted, node + ": waiting for the new key", nil
	}
	return identityState(v.Identity)
}

func identityState(r *membership.IdentityRotationView) (cli.State, string, error) {
	switch {
	case r.Failure != "":
		return cli.Failed, r.Phase + ": " + r.Failure, nil
	case r.Phase == "Installed":
		return cli.Done, "new key installed", nil
	}
	return cli.Accepted, r.Phase, nil
}
