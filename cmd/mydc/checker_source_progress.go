// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

func positiveSourceMissing(err error) bool {
	var outcome *userauth.Error
	return errors.As(err, &outcome) && outcome.Code == "missing" && outcome.Phase == mydcp.Completed
}

// Shared CLI source progression for named publication and compose staging.
// Only their callers decide whether to register a name or request an app plan.
func advanceCheckerSource(ctx context.Context, c userauth.Client, session access.Session, home string, intent userauth.CheckerScriptIntent, proceed, retry bool) (userauth.CheckerScriptIntent, string, error) {
	if intent.Fact != nil {
		return intent, "source-stored", nil
	}
	provider, err := userauth.CheckerProviderPeer(c, intent.Provider)
	if err != nil {
		return intent, "source-unknown", err
	}
	c = c.WithCheckerUpload(intent)
	var fact checker.SourceFact
	send := intent.Sequence == 0 && proceed
	if intent.Sequence > 0 {
		fact, err = c.RecoverCheckerSource(ctx, provider, session, intent.Descriptor)
		if err != nil {
			if !positiveSourceMissing(err) || !retry || !proceed {
				return intent, "source-unknown", err
			}
			send = true
		}
	}
	if send {
		next := intent
		next.Sequence++
		if err := userauth.ReplaceCheckerScript(home, c, session, intent, next); err != nil {
			return intent, "source-unknown", err
		}
		intent = next
		fact, err = c.StageCheckerSource(ctx, provider, session, intent.Descriptor, intent.Data)
		if err != nil {
			return intent, "source-unknown", err
		}
	} else if intent.Sequence == 0 {
		return intent, "source-prepared", nil
	}
	next := intent
	next.Fact = &fact
	if err := userauth.ReplaceCheckerScript(home, c, session, intent, next); err != nil {
		return intent, "source-unknown", err
	}
	return next, "source-stored", nil
}

// checkerRetryFlag is an explicit once-only boolean option of the old
// commands that still use it (compose, standalone, volume files).
type checkerRetryFlag struct{ value, set bool }

func (o *checkerRetryFlag) String() string { return strconv.FormatBool(o.value) }
func (*checkerRetryFlag) IsBoolFlag() bool { return true }
func (o *checkerRetryFlag) Set(raw string) error {
	if o.set {
		return errors.New("duplicate retry-source option")
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return err
	}
	o.value, o.set = v, true
	return nil
}

// Applied source/policy versions are useful app.yaml references. A root result
// revision belongs to the checkpoint CAS and must not be mislabeled as a source
// revision. Call only after a positive Applied result for this exact operation.
func checkerAppliedIdentity(output map[string]any, op control.UserOperation) {
	switch op.Change.Action {
	case "put-lifecycle-script":
		var q control.LifecycleScriptPut
		if json.Unmarshal(op.Change.Payload, &q) == nil {
			output["tenant"], output["script"], output["source_revision"] = q.Tenant, q.Name, op.Change.Expected+1
		}
	case "retire-lifecycle-script", "delete-lifecycle-script":
		var q control.LifecycleScriptSelection
		if json.Unmarshal(op.Change.Payload, &q) == nil {
			output["tenant"], output["script"], output["source_revision"], output["record_revision"] = q.Tenant, q.Name, q.Revision, op.Change.Expected+1
		}
	case "set-lifecycle-policy":
		var q checker.TenantPolicy
		if json.Unmarshal(op.Change.Payload, &q) == nil {
			output["tenant"], output["policy_revision"] = q.Tenant, op.Change.Expected+1
		}
	}
}
