// SPDX-License-Identifier: Apache-2.0

package control

import (
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/deployment"
)

type AppOperationRequest struct {
	App, ID    string
	Standalone string `json:",omitempty"`
}

// AppOperationView is an exact operation result, never a live health assertion.
// A missing or collected operation cannot prove that it was never submitted.
type AppOperationView struct {
	Standalone                  string `json:",omitempty"`
	Tenant, App, Deployment, ID string
	Revision                    uint64
	Found, Current              bool
	Operation                   *deployment.OperationSummary `json:",omitempty"`
	// Waiting lists, for a current deploy, the steps no server has started
	// and what each waits on. Status text only; never admission.
	Waiting []string `json:",omitempty"`
}

func (a Apps) Operation(c access.Catalog, actor, tenant string, q AppOperationRequest) (AppOperationView, error) {
	var out AppOperationView
	if tenant == "" || c.Authorize(actor, tenant, access.Read, "") != nil {
		return out, access.ErrDenied
	}
	if q.Standalone != "" {
		if q.App != "" {
			return out, access.ErrConflict
		}
		scope, ok := a.StandaloneScope(tenant, q.Standalone)
		if !ok {
			return out, nil
		}
		q.App = scope
	}
	if strings.Contains(q.ID, "/") || deployment.ResourceKey("task", tenant, q.App, q.ID) == "" {
		return out, access.ErrConflict
	}
	out.Tenant, out.App, out.ID, out.Standalone = tenant, q.App, q.ID, q.Standalone
	entry, ok := a.entries[appKey(tenant, q.App)]
	if !ok || (entry.Standalone != nil) != (q.Standalone != "") {
		return out, nil
	}
	i := entry.Inventory
	out.Deployment, out.Revision = i.Scope().Deployment, i.Revision()
	summary, found := i.Operation(q.ID)
	if !found && entry.Compacted != nil && entry.Compacted.ID == q.ID {
		summary, found = *entry.Compacted, true
	}
	if found {
		out.Found, out.Operation = true, &summary
		active, exists := i.Active()
		out.Current = exists && active.ID == q.ID
		if e, ok := i.Execution(); out.Current && ok {
			out.Waiting = e.Waiting(uint64(time.Now().Unix()), 8)
		}
	}
	return out, nil
}
