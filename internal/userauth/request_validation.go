// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"reflect"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

func (r Request) initialCredentialRequest() bool {
	return r.Method == "initial-credential-stage" || r.Method == "initial-credential-observe" || r.Method == "initial-credential-profile"
}

func (r Request) validInitialCredentialFields() bool {
	if r.Method == "initial-credential-profile" {
		return reflect.DeepEqual(r, Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce})
	}
	if !r.initialCredentialRequest() || r.InitialCredential == nil || !r.InitialCredential.Valid() ||
		r.Method == "initial-credential-observe" && r.Secret != nil {
		return false
	}
	want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, InitialCredential: r.InitialCredential, Secret: r.Secret}
	return reflect.DeepEqual(r, want)
}

// These checks only constrain request shape. Authentication, current authority,
// quorum/CAS and effects stay at their existing service boundaries.
func (r Request) checkerArtifactRequest() bool {
	return r.Method == "checker-module-stage" || r.Method == "checker-module-recover" || r.Method == "checker-source-stage" || r.Method == "checker-source-recover"
}

func (r Request) credentialRequest() bool {
	return r.Method == "credential-challenge" || r.Method == "credential-login"
}

func (r Request) validMethodFields() bool {
	if _, typed, ok := r.typedMethod(); typed || !ok {
		return typed && ok
	}
	if !r.validStandaloneFileFields() {
		return false
	}
	if !r.validCDReadFields() {
		return false
	}
	if r.initialCredentialRequest() {
		return r.validInitialCredentialFields()
	}
	if r.InitialCredential != nil {
		return false
	}
	if !r.validLookupFields() {
		return false
	}
	if r.Method == "standalone-plan" && (r.AppPlan == nil || r.AppPlan.Standalone == nil) {
		return false
	}
	if (r.AppPlan != nil) != (r.Method == "app-plan" || r.Method == "standalone-plan" || r.Method == "app-plan-stream") || (r.AppInput != nil) != (r.Method == "app-plan-stream") {
		return false
	}
	if (r.AppOperation != nil) != (r.Method == "app-operation") || r.AppOperation != nil && r.After != "" {
		return false
	}
	if (r.AppCDApproval != nil) != (r.Method == "app-cd-registration") || r.AppCDApproval != nil && (r.After != "" || r.Tenant == "") {
		return false
	}
	if (r.AppCDField != nil) != (r.Method == "app-cd-field") || r.AppCDField != nil && (r.After != "" || r.Tenant == "" || !(control.AppCDReadRequest{App: r.AppCDField.App, Part: r.AppCDField.Part, Digest: r.AppCDField.Digest}).Valid(false)) {
		return false
	}
	return true
}

func (r Request) validCredentialFields(envelope Envelope, kind uint8) bool {
	if r.initialCredentialRequest() {
		return r.validInitialCredentialFields() && kind == 1 && envelope.Session != nil && envelope.Relay == nil
	}
	if r.credentialRequest() {
		return envelope.Session == nil && kind == 1
	}
	return r.Secret == nil
}

// execute is also called directly by in-process consumers/tests. Keep its
// narrower selector checks separate from the transport's required-field gate.
func (r Request) validQuerySelectors() bool {
	if r.lifecycleEditorRequest() || r.checkerArtifactRequest() {
		_, ok := r.checkerStage()
		return ok
	}
	if r.Method == ServiceCallMethod.Name {
		_, ok := r.serviceCall()
		return ok
	}
	if r.Method == CDProbeMethod.Name {
		_, ok := paramsOf(r, CDProbeMethod)
		return ok
	}
	if !r.validStandaloneFileFields() {
		return false
	}
	if r.Method == "standalone-list" || r.Method == "standalone-get" {
		return true
	}
	if !r.validLookupFields() {
		return false
	}
	if r.After != "" {
		switch r.Method {
		case "app-cd-history", "raft-status", "app-revisions", "apps", "app-uploads":
		default:
			return false
		}
		if len(r.After) > 512 {
			return false
		}
	}
	if r.Node != "" {
		return false
	}
	if r.Method == "raft-status" && (r.Tenant != "" || r.Node != "") {
		return false
	}
	return true
}

// Both the transport entry and direct query execution reject payloads for a
// different method; share that rule without moving any authorization checks.
func (r Request) validLookupFields() bool {
	if !r.validCDReadFields() {
		return false
	}
	if (r.CDToggle != nil) != (r.Method == "app-cd-toggle-plan") || r.CDToggle != nil && (r.Tenant == "" || r.Node != "" || r.After != "" || !r.CDToggle.Valid()) {
		return false
	}
	if (r.AppSource != nil) != (r.Method == "app-source" || r.Method == "app-revisions") || r.AppSource != nil && (r.Tenant == "" || r.Node != "" || !r.AppSource.Valid(r.Method == "app-revisions") || r.Method == "app-source" && r.After != "") {
		return false
	}
	return (r.TaskRestart != nil) == (r.Method == "task-restart-plan" || r.Method == "task-restart-status") && (r.TaskRestart == nil || r.Tenant != "" && r.After == "" && r.Node == "" && r.TaskRestart.Valid(r.Method == "task-restart-plan")) &&
		(r.Container != nil) == (r.Method == "container-observe") &&
		(r.Container == nil || r.Container.Validate() == nil && r.Tenant != "" && r.After == "" && r.Node == "")
}
