// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"time"
)

func init() {
	defineNodeRead((*Runtime).nodeReadRouteFlowObserve, false, "route-flow-observe")
	defineNodeRead((*Runtime).nodeReadRouteNativePermit, false, "route-native-permit")
	defineNodeRead((*Runtime).nodeReadRouteWork, false, "route-work")
}

func (r *Runtime) nodeReadRouteFlowObserve(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, sfcp.ErrAdmission
	}
	return r.observeRouteFlow(ctx, caller, input)
}

func (r *Runtime) nodeReadRouteNativePermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	request, decodeErr := schema.Decode[control.RouteNativeRequest](input)
	now := time.Now().Unix()
	if err != nil || decodeErr != nil || v.Local || request.At <= 0 || !access.Recent(request.At, now, 30) {
		return nil, sfcp.ErrAdmission
	}
	permit, err := r.controlPolicy.RouteNativePermit(v.State, caller, request)
	if err != nil {
		return nil, err
	}
	return json.Marshal(permit)
}

func (r *Runtime) nodeReadRouteWork(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	request, decodeErr := schema.Decode[control.RouteWorkRequest](input)
	now := time.Now().Unix()
	if err != nil || decodeErr != nil || v.Local || request.At <= 0 || !access.Recent(request.At, now, 30) {
		return nil, sfcp.ErrAdmission
	}
	work, err := r.controlPolicy.RouteWork(v.State, caller, request)
	if err != nil {
		return nil, err
	}
	return json.Marshal(work)
}
