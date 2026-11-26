// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"encoding/hex"
	"errors"
	"slices"
)

// REQ-25 in the fake. SetCDCandidate emits cd-candidate-created (and
// cd-approval-required in manual mode); sync/approve emit started and
// succeeded (or failed with the code); pause/resume, Fake.ReportCDDrift
// and Fake.RollBackCD emit theirs. The pause reason is not modeled:
// control.AppCDChange has no Reason (mydcd's part).

func (w *world) username(id string) string {
	if u := w.users[id]; u != nil {
		return u.rec.Username
	}
	return id
}

func (w *world) cdEvent(a *fakeApp, kind, commit, actor, code, reason string, now int64) {
	cd := a.view.CD
	e := &CDEvent{Commit: commit, FromVersion: cd.Running, ToVersion: cd.Candidate, Code: code, Reason: reason}
	if commit != "" {
		d := candidateDigest(a.view.Tenant, a.view.App, commit)
		e.CandidateID = hex.EncodeToString(d[:])
	}
	if actor != "" {
		e.Actor = w.username(actor)
	}
	w.addEvent(FixtureEvent{Time: now, Scope: "app", Tenant: a.view.Tenant, App: a.view.App, Kind: kind, Target: commit, Detail: reason, CD: e})
}

func (w *world) cdApprover(user, tenant, app string) bool {
	a := w.apps[tenant+"/"+app]
	return a != nil && a.view.CD != nil && slices.Contains(a.view.CD.Approvers, user)
}

func (c *fakeConn) applyCDDecision(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	ch := op.Change
	now := c.f.now().Unix()
	if ch.Action == ActionGrantCDApprover || ch.Action == ActionDropCDApprover {
		var q CDApproverGrant
		if decodePayload(ch.Payload, &q) != nil || q.Tenant == "" || q.App == "" || q.User == "" {
			return errors.New("payload")
		}
		if !w.canManage(actor, q.Tenant) {
			return errForbidden
		}
		a := w.apps[q.Tenant+"/"+q.App]
		if a == nil || a.view.CD == nil || ch.Expected != a.view.CD.Revision {
			return errCAS
		}
		uid := q.User
		if u := w.users[uid]; u == nil || ch.Action == ActionGrantCDApprover && !u.rec.Enabled {
			return errCAS
		}
		has := slices.Contains(a.view.CD.Approvers, uid)
		if has == (ch.Action == ActionGrantCDApprover) {
			return errCAS
		}
		if has {
			a.view.CD.Approvers = slices.DeleteFunc(slices.Clone(a.view.CD.Approvers), func(id string) bool { return id == uid })
		} else {
			a.view.CD.Approvers = append(slices.Clone(a.view.CD.Approvers), uid)
			slices.Sort(a.view.CD.Approvers)
		}
		a.view.CD.Revision = next
		return nil
	}
	var q CDDecision
	if decodePayload(ch.Payload, &q) != nil || q.Tenant == "" || q.App == "" || q.Candidate == ([32]byte{}) || q.Target == ([32]byte{}) {
		return errors.New("payload")
	}
	reason := ""
	if op.Reason != nil {
		reason = op.Reason.Text
	}
	if !w.canManage(actor, q.Tenant) && !w.cdApprover(actor, q.Tenant, q.App) {
		return errForbidden
	}
	a := w.apps[q.Tenant+"/"+q.App]
	if a == nil || a.view.CD == nil || a.cd == nil {
		return errCAS
	}
	cur := a.cdView()
	cd := a.view.CD
	if ch.Expected > cur.Revision || q.Strict && ch.Expected != cur.Revision || q.Target != cur.Target || cd.Candidate == "" || cd.Candidate == cd.Running || q.Candidate != cur.CandidateDigest {
		return errCAS
	}
	commit := cd.Candidate
	if ch.Action == ActionRejectAppCD {
		if r := a.cd.row(commit, CDCandidate); r != nil {
			r.Result, r.Reason, r.Actor, r.FinishedAt = CDRejected, reason, w.username(actor), now
		}
		a.cd.rejected[commit] = true
		w.cdEvent(a, EventCDRejected, commit, actor, "", reason, now)
		cd.Candidate = cd.Running
		cd.Revision = next
		return nil
	}
	if cd.Mode != "manual" || cd.Paused {
		return errCAS
	}
	w.cdEvent(a, EventCDApproved, commit, actor, "", reason, now)
	if r := a.cd.row(commit, CDCandidate); r != nil {
		r.Actor, r.Note = w.username(actor), reason
	}
	if err := c.cdRun(a, commit, "approve-"+op.RequestID, actor, now); err != nil {
		return err
	}
	cd.Revision = next
	return nil
}

// cdRun: the sync part shared by sync-app/recover-app and cd-approve.
func (c *fakeConn) cdRun(a *fakeApp, commit, operation, actor string, now int64) error {
	w := c.f.w
	cd := a.view.CD
	w.cdEvent(a, EventCDSyncStarted, commit, actor, "", "", now)
	if conflicts := a.localConflicts(); len(conflicts) > 0 {
		// a Git service took a local service's name.
		cd.Blocked = "name-conflict"
		w.cdEvent(a, EventCDSyncFailed, commit, actor, "NAME_CONFLICT", "", now)
		return errCAS
	}
	if cd.Blocked == "name-conflict" {
		cd.Blocked = ""
	}
	cd.Running = commit
	// the applied commit is a new app version of Kind "cd", so a
	// rollback right after CD can tell it from a person's version.
	if doc, ok := a.cd.docs[commit]; ok {
		merged := []byte(doc)
		if a.cd.local != "" {
			merged, _ = mergeLocal(doc, a.cd.local)
		}
		if _, err := w.deploy(a.view.Tenant, a.view.App, merged, w.username(actor), operation, now); err == nil {
			a.sources[len(a.sources)-1].Kind = "cd"
		}
	}
	a.cdSynced(commit, operation, now)
	w.cdEvent(a, EventCDSyncSucceeded, commit, actor, "", "", now)
	return nil
}

// ReportCDDrift emits cd-drift-detected for the running commit.
func (f *Fake) ReportCDDrift(tenant, app string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.w.apps[tenant+"/"+app]
	if a == nil || a.view.CD == nil {
		panic("mydc fake: not a CD app " + tenant + "/" + app)
	}
	f.w.cdEvent(a, EventCDDriftDetected, a.view.CD.Running, "", "", "", f.now().Unix())
}

// RollBackCD puts an earlier applied commit back as the running one (the
// incident response rollback) and emits cd-rolled-back.
func (f *Fake) RollBackCD(tenant, app, commit, actor string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := f.w
	a := w.apps[tenant+"/"+app]
	if a == nil || a.view.CD == nil || a.cd == nil || a.cd.row(commit, CDSucceeded) == nil {
		panic("mydc fake: no applied commit " + commit)
	}
	now := f.now().Unix()
	from := a.view.CD.Running
	w.root++
	a.view.CD.Running, a.view.CD.Revision = commit, w.root
	for id, u := range w.users {
		if u.rec.Username == actor {
			actor = id
		}
	}
	w.cdEvent(a, EventCDRolledBack, commit, actor, "", "", now)
	w.events[len(w.events)-1].CD.FromVersion = from
}
