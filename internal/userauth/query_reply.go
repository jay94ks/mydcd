// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
)

// Query assembly runs only after the handler's admission and user authorization.
// Each helper receives the original committed view and preserves that view for
// both root revisions and page contents. No helper refreshes state or authority.

func (s Service) appsQueryReply(view cluster.View, catalog access.Catalog, session access.Session, request Request, reply Reply) Reply {
	reply.AppsRootRevision = view.State.Object(control.AppsKey).Revision
	if apps, err := s.Policy.Apps(view.State); err == nil {
		reply.AppRevision = apps.Revision
		if request.Method == "apps" {
			reply.Apps, reply.AppsNext, err = apps.ObservedPage(catalog, session.User, request.Tenant, request.After, uint64(time.Now().Unix()))
			if err == nil {
				for i := range reply.Apps {
					if err = s.Policy.ObserveAppReplicaHealth(view.State, apps, &reply.Apps[i], uint64(time.Now().Unix())); err != nil {
						break
					}
					s.Policy.ObserveAppCD(view.State, apps, catalog, &reply.Apps[i], uint64(time.Now().Unix()))
				}
			}
		} else if request.Method == "app-operation" {
			var operation control.AppOperationView
			operation, err = apps.Operation(catalog, session.User, request.Tenant, *request.AppOperation)
			if err == nil {
				reply.AppOperation = &operation
			}
		} else {
			reply.Uploads, reply.UploadsNext, err = apps.Uploads(catalog, session.User, request.Tenant, request.After)
		}
		if err != nil {
			reply = Reply{Schema: 1, Code: "denied"}
		}
	} else {
		reply = Reply{Schema: 1, Code: "unavailable"}
	}

	return reply
}
