// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/sfcp"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	quic "github.com/quic-go/quic-go"
)

func TestRequestValidationRequiredPayloadsCannotCrossMethods(t *testing.T) {
	for _, tc := range []struct {
		method string
		set    func(*Request)
	}{
		{"registry-prune-preview", func(r *Request) {
			r.RegistryPrune = &control.RegistryPruneQuery{ID: "private", Part: "items", Conditions: &registryclient.PruneConditions{}}
		}},
		{"registry-prune-results", func(r *Request) {
			r.RegistryPrune = &control.RegistryPruneQuery{Operation: "original-prune", Part: "items"}
		}},
		{"registry-maintenance-plan", func(r *Request) {
			r.RegistryMaintenance = &control.RegistryMaintenanceQuery{Action: "gc-registry", ID: "private"}
		}},
		{"registry-maintenance-status", func(r *Request) { r.RegistryMaintenance = &control.RegistryMaintenanceQuery{Operation: "original-42"} }},
		{"registry-catalog", func(r *Request) { r.RegistryCatalog = &control.RegistryCatalogueQuery{Kind: "managed", ID: "private"} }},
		{"image-usages", func(r *Request) { r.ImageUsage = &control.ImageUsageQuery{} }},
		{"image-resolve", func(r *Request) { r.ImageResolve = &control.ImageResolveQuery{Ref: "alpine:latest"} }},
		{"external-registry-bind-plan", func(r *Request) {
			r.ExternalRegistryBind = &control.ExternalRegistryBindQuery{ID: "source", Node: "node-a"}
		}},
		{"registry-login-test", func(r *Request) {
			r.ExternalRegistryProbe = &control.ExternalRegistryProbeQuery{ID: "source", Image: "ghcr.io/team/app:latest"}
		}},
		{"container-observe", func(r *Request) {
			r.Container = &containerops.Query{Schema: 1, Selection: containerops.Selection{App: "app", Service: "web"}, Kind: "top", MaxBytes: 16384}
		}},
		{"app-plan", func(r *Request) { r.AppPlan = &control.AppPlanRequest{} }},
		{"app-plan-stream", func(r *Request) { r.AppPlan = &control.AppPlanRequest{}; r.AppInput = &AppPlanInput{} }},
		{"app-operation", func(r *Request) { r.AppOperation = &control.AppOperationRequest{} }},
		{"app-cd-registration", func(r *Request) { r.AppCDApproval = &control.AppCDApprovalRequest{} }},
		{"app-cd-field", func(r *Request) {
			r.AppCDField = &control.AppCDFieldRequest{App: "app", Path: []string{"services", "web", "image"}}
		}},
		{"app-cd-history", func(r *Request) { r.AppCDRead = &control.AppCDReadRequest{App: "app"} }},
		{"app-cd-diff", func(r *Request) { r.AppCDRead = &control.AppCDReadRequest{App: "app"} }},
		{"vault-approval-plan", func(r *Request) { r.VaultPlan = &control.VaultApprovalPlanRequest{} }},
		{"vault-write-plan", func(r *Request) { r.VaultWritePlan = &control.VaultWritePlanRequest{Realm: "tenant"} }},
		{"registry-credential", func(r *Request) { r.Registry = &RegistryCredentialRequest{} }},
		{"checker-source-stage", func(r *Request) { r.CheckerSource = &checker.SourceDescriptor{} }},
		{"checker-source-recover", func(r *Request) { r.CheckerSource = &checker.SourceDescriptor{} }},
		{"checker-module-stage", func(r *Request) {
			r.CheckerSource = &checker.SourceDescriptor{}
			r.CheckerModule = &checker.ModulePin{}
		}},
		{"checker-module-recover", func(r *Request) {
			r.CheckerSource = &checker.SourceDescriptor{}
			r.CheckerModule = &checker.ModulePin{}
		}},
	} {
		t.Run(tc.method, func(t *testing.T) {
			r := Request{Method: tc.method, Tenant: "tenant"}
			if r.validMethodFields() {
				t.Fatal("missing required payload accepted")
			}
			tc.set(&r)
			if !r.validMethodFields() {
				t.Fatal("valid method payload rejected")
			}
			r.Method = "whoami"
			if r.validMethodFields() {
				t.Fatal("foreign payload accepted by another method")
			}
		})
	}
	for _, r := range []Request{
		{Method: "app-plan-stream", AppPlan: &control.AppPlanRequest{}},
		{Method: "app-plan-stream", AppInput: &AppPlanInput{}},
		{Method: "app-operation", AppOperation: &control.AppOperationRequest{}, After: "cursor"},
		{Method: "app-cd-registration", AppCDApproval: &control.AppCDApprovalRequest{}},
		{Method: "app-cd-field", Tenant: "tenant", AppCDField: &control.AppCDFieldRequest{}, After: "cursor"},
		{Method: "vault-write-plan", Tenant: "other", VaultWritePlan: &control.VaultWritePlanRequest{Realm: "tenant"}},
		{Method: "checker-source-stage", CheckerSource: &checker.SourceDescriptor{}, CheckerUpload: &[32]byte{}},
		{Method: "whoami", CheckerUpload: &[32]byte{1}},
		{Method: "checker-source-stage", CheckerSource: &checker.SourceDescriptor{}, CheckerModule: &checker.ModulePin{}},
	} {
		if r.validMethodFields() {
			t.Fatalf("invalid request shape accepted: %+v", r)
		}
	}
	for _, method := range []string{"checker-source-stage", "checker-source-recover"} {
		r := Request{Method: method, CheckerSource: &checker.SourceDescriptor{}, CheckerUpload: &[32]byte{1}}
		if !r.validMethodFields() {
			t.Fatal("nonzero original upload rejected")
		}
	}
	// This is shape validation, not the method dispatcher or current authorization.
	if !(Request{Method: "unknown"}).validMethodFields() {
		t.Fatal("shape check became a new dispatch policy")
	}
}

func TestRequestValidationCredentialAndSelectorBoundaries(t *testing.T) {
	for _, method := range []string{"credential-challenge", "credential-login"} {
		r := Request{Method: method}
		if !r.validCredentialFields(Envelope{}, 1) || r.validCredentialFields(Envelope{Session: &access.Session{}}, 1) || r.validCredentialFields(Envelope{}, 3) {
			t.Fatal("credential entry/relay contract changed", method)
		}
	}
	if (Request{Method: "whoami", Secret: []byte{}}).validCredentialFields(Envelope{}, 1) {
		t.Fatal("credential-only fields accepted on ordinary request")
	}
	if !(Request{Method: "login"}).validCredentialFields(Envelope{}, 1) {
		t.Fatal("private-key login rejected")
	}
	for _, method := range []string{"tenant-retirement", "members", "node-storage", "apps", "app-uploads", "vault", "registries"} {
		if !(Request{Method: method, After: "next"}).validQuerySelectors() {
			t.Fatal("valid cursor rejected", method)
		}
		if (Request{Method: method, After: strings.Repeat("a", 513)}).validQuerySelectors() {
			t.Fatal("unbounded cursor accepted", method)
		}
	}
	for _, r := range []Request{
		{Method: "whoami", After: "next"}, {Method: "members", After: "../node"},
		{Method: "node-invitation"}, {Method: "node-invitation", Node: "../node"},
		{Method: "node-storage", Node: "../node"}, {Method: "whoami", Node: "node"},
		{Method: "whoami", NodeStorage: &control.NodeStorageSelection{}},
	} {
		if r.validQuerySelectors() {
			t.Fatal("invalid selector accepted", r.Method)
		}
	}
	if !(Request{Method: "node-invitation", Node: "node-a"}).validQuerySelectors() {
		t.Fatal("valid invitation selector rejected")
	}
}

type validationStream struct{ bytes.Buffer }

func (*validationStream) Close() error                     { return nil }
func (*validationStream) SetDeadline(time.Time) error      { return nil }
func (*validationStream) CancelRead(quic.StreamErrorCode)  {}
func (*validationStream) CancelWrite(quic.StreamErrorCode) {}

func TestRequestValidationRejectsBeforeBindingAndClearsCredentialEnvelope(t *testing.T) {
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(self.Private)
	service := Service{Self: self} // No Engine/connection: invalid shape must never reach effects/auth binding.
	for _, tc := range []struct {
		r       Request
		e       Envelope
		private bool
	}{
		{r: Request{Method: "whoami", AppOperation: &control.AppOperationRequest{}}},
		{r: Request{Method: "credential-login", Params: []byte(`{"Ticket":{"AuthMethod":"password"},"Secret":"cHJpdmF0ZS1wYXNzd29yZA=="}`)}, e: Envelope{Session: &access.Session{}}, private: true},
	} {
		tc.r.Schema = 1
		tc.r.Nonce = [32]byte{1}
		tc.e.Body, _ = json.Marshal(tc.r)
		raw, _ := json.Marshal(tc.e)
		digest := sha256.Sum256(raw)
		frame := sfcp.Frame{Purpose: sfcp.User, Kind: 1, Request: 55, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: digest[:]}}}
		stream := new(validationStream)
		if err := service.handle(context.Background(), nil, stream, frame); err != nil {
			t.Fatal(err)
		}
		response, err := sfcp.ReadFrame(stream, sfcp.MaxBody)
		var reply Reply
		if err != nil || json.Unmarshal(response.Fields[0].Value, &reply) != nil || reply.Code != "denied" || response.Request != 55 {
			t.Fatal("invalid request crossed guard", err)
		}
		if tc.private && !bytes.Equal(raw, make([]byte, len(raw))) {
			t.Fatal("credential envelope was not cleared")
		}
	}
}
