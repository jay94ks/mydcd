// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/deployment"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func (c Client) AppDeliveryRegistration(ctx context.Context, target mydcp.Peer, session access.Session, tenant, app string, selection control.AppApprovalSelection) (control.AppCDApprovalRegistration, error) {
	if !selection.Valid() {
		return control.AppCDApprovalRegistration{}, mydcp.ErrAdmission
	}
	reply, err := c.query(ctx, target, session, Request{Method: "app-cd-registration", Tenant: tenant, AppCDApproval: &control.AppCDApprovalRequest{App: app, Selection: selection}})
	if err != nil {
		return control.AppCDApprovalRegistration{}, err
	}
	v := reply.AppCDRegistration
	if v == nil || !v.Selection.Equal(selection) || len(v.Realms) > 2 {
		return control.AppCDApprovalRegistration{}, mydcp.ErrAdmission
	}
	u := &v.Origin
	var begin control.AppBegin
	if u == nil || u.VerifyOriginal(c.Cluster) != nil || u.Session.User != session.User || u.Change.Action != "begin-app" || strict(u.Change.Payload, &begin) != nil || begin.Tenant != tenant || begin.App != app {
		return control.AppCDApprovalRegistration{}, mydcp.ErrAdmission
	}
	for i, realm := range v.Realms {
		if realm != "" && realm != tenant || i > 0 && v.Realms[i-1] >= realm {
			return control.AppCDApprovalRegistration{}, mydcp.ErrAdmission
		}
	}
	return *v, nil
}

func (c Client) AppDeliveryField(ctx context.Context, target mydcp.Peer, session access.Session, tenant string, q control.AppCDFieldRequest) (control.AppCDField, error) {
	if q.Part != 0 || q.Digest != ([32]byte{}) {
		return control.AppCDField{}, mydcp.ErrAdmission
	}
	reply, err := c.query(ctx, target, session, Request{Method: "app-cd-field", Tenant: tenant, AppCDField: &q})
	if err != nil {
		return control.AppCDField{}, err
	}
	v := reply.AppCDField
	if v == nil || v.Schema != 1 || v.Tenant != tenant || v.App != q.App || !slices.Equal(v.Path, q.Path) || v.Revision == 0 || len(v.Refs) > 128 || v.Override != nil && (v.Override.Revision == 0 || v.Override.Actor == "" || len(v.Override.Anchors) == 0 || len(v.Override.Anchors) > 128) {
		return control.AppCDField{}, mydcp.ErrAdmission
	}
	if v.Values != nil && v.ValuesPart != nil {
		return control.AppCDField{}, mydcp.ErrFrame
	}
	if v.ValuesPart != nil {
		raw, err := collectCDSnapshot(tenant, q.App, "field-values", func(part int, digest [32]byte) (*control.AppCDSnapshotPart, error) {
			if part == 0 {
				return v.ValuesPart, nil
			}
			next := q
			next.Part, next.Digest = part, digest
			response, err := c.query(ctx, target, session, Request{Method: "app-cd-field", Tenant: tenant, AppCDField: &next})
			if err != nil {
				return nil, err
			}
			field := response.AppCDField
			if field == nil || field.Target != v.Target || !slices.Equal(field.Path, q.Path) || field.Values != nil {
				return nil, mydcp.ErrFrame
			}
			return field.ValuesPart, nil
		})
		if err != nil {
			return control.AppCDField{}, err
		}
		var values deployment.DeliveryFieldValues
		if json.Unmarshal(raw, &values) != nil {
			return control.AppCDField{}, mydcp.ErrFrame
		}
		v.Values, v.ValuesPart = &values, nil
	}
	if v.Values != nil {
		for _, field := range []deployment.PublicFieldValue{v.Values.Source, v.Values.RunningSource, v.Values.Current} {
			if field.Present != (len(field.Value) > 0) || field.Present && !json.Valid(field.Value) {
				return control.AppCDField{}, mydcp.ErrFrame
			}
		}
	}
	return *v, nil
}
