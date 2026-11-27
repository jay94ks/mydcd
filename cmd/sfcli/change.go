// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/userauth"
)

// A change is one signed management operation: the CLI prepares it with
// the server, saves the signed original in the user's journal, records it in
// the op index and sends it. A lost reply is settled with the same original
// by `sfcli op show|resume ID` (opKinds["change"], or the kind's own handler).
type change struct {
	// Kind is the op index kind. Empty means "change", whose handler only
	// asks for and resends the saved original. A kind that needs work before
	// resending (approvals, follow-up steps) registers its own handler.
	Kind string
	// Summary is the command as the person would type it, such as
	// "registry stop shop-registry". Plain text: names and targets only,
	// never secret values or tokens.
	Summary  string
	ID       string // cli.IDFlag.Get()
	Action   string // server action, such as "stop-registry"
	Expected uint64 // record revision (CAS), usually from cli.RevisionFlag.Resolve
	// Epoch, when not 0, must match the management epoch Prepare returns
	// (a plan read before confirmation). 0 takes the prepared epoch.
	Epoch   uint64
	Payload any
	// Before, when set, runs just before the original is first sent and
	// before it is resent by resume (for example to add approvals).
	Before func(control.UserOperation) error
	// Async means Applied only accepts the work (a build, a registry start):
	// the op stays "accepted" until the kind's handler sees it finish.
	Async bool
}

// errOutcomeUnknown means the request may or may not have reached the
// server. The original is kept; `sfcli op show ID` or `sfcli op resume ID`
// settles it with the same ID.
type errOutcomeUnknown struct {
	id  string
	err error
}

func (e errOutcomeUnknown) Error() string {
	msg := fmt.Sprintf("the result of %s is not known yet; run 'sfcli op show %s' to check or 'sfcli op resume %s' to send it again", e.id, e.id, e.id)
	if e.err != nil {
		msg += " (" + e.err.Error() + ")"
	}
	return msg
}
func (e errOutcomeUnknown) Unwrap() error { return e.err }

// exitUnknown is the exit code of a command whose change may or may not
// have been applied.
const exitUnknown = 4

// unknown turns errOutcomeUnknown into exit code 4 with its message; other
// errors pass through. Commands return g.send errors through it.
func unknown(err error) error {
	var u errOutcomeUnknown
	if errors.As(err, &u) {
		return cli.ExitError{Code: exitUnknown, Err: u}
	}
	return err
}

// withSession wraps a Run function: it opens the logged-in session and
// closes it when the command ends.
func (g *globals) withSession(run func(c *cli.Context, s *session, args []string) error) func(*cli.Context, []string) error {
	return func(c *cli.Context, args []string) error {
		if g.session != nil {
			return unknown(run(c, g.session, args))
		}
		s, err := openSession(g, c)
		if err != nil {
			return err
		}
		defer s.Close()
		return unknown(run(c, s, args))
	}
}

// send records ch in the op index, then prepares, saves and sends it. It
// returns the server result; an Applied result returns nil error. A rejected
// change returns the result and an error naming the server's code. If the
// outcome is unknown the error is errOutcomeUnknown.
//
// Reusing an ID (--id) that already has a saved original continues that
// original instead of preparing a new one; it must be the same action and
// payload.
func (g *globals) send(c *cli.Context, s *session, ch change) (*state.Result, error) {
	if ch.Kind == "" {
		ch.Kind = "change"
	}
	if err := g.Record(s, ch.Kind, ch.Summary, ch.ID); err != nil {
		return nil, err
	}
	raw, err := control.ChangeBytes(ch.Action, s.Stored.Session.User, ch.Expected, ch.Payload)
	if err != nil {
		return nil, err
	}
	var want control.Change
	if err = json.Unmarshal(raw, &want); err != nil {
		return nil, err
	}
	ctx, cancel := g.Deadline(c)
	defer cancel()
	record, err := userauth.LoadOperation(s.Home, s.Client, s.Stored.Session, ch.ID)
	fresh := errors.Is(err, userauth.ErrOperationMissing)
	switch {
	case fresh:
		op, err := s.Client.Prepare(ctx, s.Target, s.Stored.Session, ch.ID, want)
		if err != nil {
			g.settle(ch.ID, cli.Failed, "not sent: "+err.Error())
			return nil, err
		}
		if ch.Epoch != 0 && op.Epoch != ch.Epoch {
			g.settle(ch.ID, cli.Failed, "not sent: the cluster changed after the plan was read")
			return nil, errors.New("the cluster changed after the plan was read; nothing was sent, run the command again")
		}
		if record, err = userauth.StageOperation(s.Home, s.Client, op); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		// Running a command again with the same ID continues the saved change.
		// Its revision was read before the first send and may have moved on
		// since, so only the action, the user and the payload must match.
		old := record.Operation.Change
		if old.Action != want.Action || old.Principal != want.Principal || !bytes.Equal(old.Payload, want.Payload) {
			return nil, fmt.Errorf("--id %s already names a different change; choose another ID", ch.ID)
		}
	}
	var reply userauth.Reply
	if record.Result == nil {
		if ch.Before != nil {
			if err = ch.Before(record.Operation); err != nil {
				return nil, err
			}
		}
		// A leader change can refuse the send or lose its reply. Ask the
		// new leader for the saved result, or resend the same original,
		// until --timeout instead of ending with an unknown outcome.
		saved := func() (userauth.Reply, error) {
			reply, err := s.Client.Result(ctx, s.Target, s.Stored.Session, record.Operation)
			if err == nil && (!reply.Found || reply.Result == nil) {
				reply, err = s.Client.Resume(ctx, s.Target, s.Stored.Session, record.Operation)
			}
			return reply, err
		}
		first := saved
		if fresh {
			first = func() (userauth.Reply, error) {
				return s.Client.Operation(ctx, s.Target, record.Operation, false)
			}
		}
		reply, err = settleSend(ctx, first, saved)
		if err != nil || !reply.Found || reply.Result == nil {
			return nil, errOutcomeUnknown{id: ch.ID, err: err}
		}
		if err = keepResult(s, record.Operation, *reply.Result); err != nil {
			return nil, err
		}
		record.Result = reply.Result
	}
	st, detail := changeState(*record.Result, ch.Async)
	g.settle(ch.ID, st, detail)
	if record.Result.Code != state.Applied {
		return record.Result, errors.New(detail)
	}
	return record.Result, nil
}

// settle updates the op index; a failure here does not change what the
// server did, so it is only reported by the next `sfcli op show`.
func (g *globals) settle(id string, st cli.State, detail string) {
	x, err := openOps()
	if err != nil {
		return
	}
	defer x.Close()
	_ = x.Update(id, st, detail)
}

var resultCodes = map[state.Code]string{
	state.Applied:         "applied",
	state.ConditionFailed: "rejected: the record changed (revision differs); read it again",
	state.Invalid:         "rejected: invalid",
	state.RequestConflict: "rejected: the ID was already used for another request",
	state.Forbidden:       "rejected: not permitted",
	state.Expired:         "rejected: the session expired; log in again and resume",
	state.LedgerFull:      "rejected: too many pending requests; try again later",
}

// retryable results are not final: the same original can be resent after
// logging in again or once the ledger has room.
func retryable(r state.Result) bool { return r.Code == state.Expired || r.Code == state.LedgerFull }

// keepResult saves a final server result with the original.
func keepResult(s *session, op control.UserOperation, r state.Result) error {
	if retryable(r) {
		return nil
	}
	return userauth.RecordOperationResult(s.Home, s.Client, s.Stored.Session, op, r)
}

// changeState is the op index state and one result line for a server
// result.
func changeState(r state.Result, async bool) (cli.State, string) {
	detail, ok := resultCodes[r.Code]
	if !ok {
		detail = fmt.Sprintf("rejected: code %d", r.Code)
	}
	if r.Reason != "" {
		detail += ": " + r.Reason
	}
	if retryable(r) {
		return cli.Sending, detail
	}
	if r.Code != state.Applied {
		return cli.Failed, detail
	}
	if async {
		return cli.Accepted, "accepted"
	}
	return cli.Done, detail
}

// opSession opens the session an op was sent with: its context and tenant,
// unless --context/--tenant say otherwise.
// openSession and openOpSession open the logged-in session of a command
// and of a recorded operation; tests replace them with a fixture session.
var (
	openSession   = (*globals).open
	openOpSession = (*globals).opSession
)

func (g *globals) opSession(c *cli.Context, op cli.Op) (*session, error) {
	if g.session != nil {
		s := *g.session
		s.closers = nil // the test owns it
		return &s, nil
	}
	h := *g
	if h.context == "" && op.Context != "default" {
		h.context = op.Context
	}
	if h.tenant == "" {
		h.tenant = op.Tenant
	}
	return h.open(c)
}

// changeHandler settles a change from the saved original. before, when set,
// runs before a resend (as change.Before); async keeps Applied "accepted".
// A kind with follow-up work wraps this handler and inspects the server
// after it.
func changeHandler(g *globals, before func(c *cli.Context, s *session, op control.UserOperation) error, async bool) cli.Handler {
	settle := func(c *cli.Context, op cli.Op, resume bool) (cli.State, string, error) {
		s, err := openOpSession(g, c, op)
		if err != nil {
			return "", "", err
		}
		defer s.Close()
		record, err := userauth.LoadOperation(s.Home, s.Client, s.Stored.Session, op.ID)
		if errors.Is(err, userauth.ErrOperationMissing) {
			// Recorded but never prepared: nothing reached the server.
			return cli.Failed, "not sent", nil
		}
		if err != nil {
			return "", "", err
		}
		if record.Result == nil {
			ctx, cancel := g.Deadline(c)
			defer cancel()
			reply, err := s.Client.Result(ctx, s.Target, s.Stored.Session, record.Operation)
			if err == nil && (!reply.Found || reply.Result == nil) && resume {
				if before != nil {
					if err = before(c, s, record.Operation); err != nil {
						return "", "", err
					}
				}
				reply, err = s.Client.Resume(ctx, s.Target, s.Stored.Session, record.Operation)
			}
			if err != nil {
				return "", "", err
			}
			if !reply.Found || reply.Result == nil {
				if resume {
					return cli.Sending, "sent again; the server has not answered", nil
				}
				return cli.Sending, "the server has no result for this ID yet; 'sfcli op resume' sends it again", nil
			}
			if err = keepResult(s, record.Operation, *reply.Result); err != nil {
				return "", "", err
			}
			record.Result = reply.Result
		}
		st, detail := changeState(*record.Result, async)
		return st, detail, nil
	}
	return cli.Handler{
		Show:   func(c *cli.Context, op cli.Op) (cli.State, string, error) { return settle(c, op, false) },
		Resume: func(c *cli.Context, op cli.Op) (cli.State, string, error) { return settle(c, op, true) },
	}
}

func init() {
	opKinds["change"] = func(g *globals) cli.Handler { return changeHandler(g, nil, false) }
}
