// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"reflect"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/registryclient"
)

func (r Request) initialCredentialRequest() bool {
	return r.Method == "initial-credential-stage" || r.Method == "initial-credential-observe"
}

func (r Request) validInitialCredentialFields() bool {
	if !r.initialCredentialRequest() || r.InitialCredential == nil || !r.InitialCredential.Valid() ||
		r.Method == "initial-credential-observe" && r.Secret != nil {
		return false
	}
	want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, InitialCredential: r.InitialCredential, Secret: r.Secret}
	return reflect.DeepEqual(r, want)
}

// These checks only constrain request shape. Authentication, current authority,
// quorum/CAS and effects stay at their existing service boundaries.
func (r Request) checkerModuleRequest() bool {
	return r.Method == "checker-module-stage" || r.Method == "checker-module-recover"
}

func (r Request) checkerArtifactRequest() bool {
	return r.checkerModuleRequest() || r.Method == "checker-source-stage" || r.Method == "checker-source-recover"
}

func (r Request) credentialRequest() bool {
	return r.Method == "credential-challenge" || r.Method == "credential-login"
}

func (r Request) validImageBuildFields() bool {
	if (r.ImageBuildCache != nil) != (r.Method == "image-build-cache") {
		return false
	}
	if r.Method == "image-build-cache" {
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, ImageBuildCache: r.ImageBuildCache, After: r.After}
		_, _, _, _, err := control.ImageBuildCacheOffset(r.After)
		return r.Tenant != "" && r.ImageBuildCache.Valid() && err == nil && reflect.DeepEqual(r, want)
	}
	if (r.ImageBuildLog != nil) != (r.Method == "image-build-logs") {
		return false
	}
	if r.Method == "image-build-logs" {
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, ImageBuildLog: r.ImageBuildLog, After: r.After}
		return r.Tenant != "" && r.ImageBuildLog.Valid() && !(r.ImageBuildLog.Tail && r.After != "") && len(r.After) <= 512 && reflect.DeepEqual(r, want)
	}

	if (r.ImageBuildGit != nil) != (r.Method == "save-build-git") {
		return false
	}
	if r.Method == "save-build-git" {
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, ImageBuildGit: r.ImageBuildGit}
		return r.Tenant != "" && r.ImageBuildGit.Valid() && reflect.DeepEqual(r, want)
	}
	if (r.ImageBuildDraft != nil) != (r.Method == "build-draft") {
		return false
	}
	if r.Method == "build-draft" {
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, ImageBuildDraft: r.ImageBuildDraft}
		return r.Tenant != "" && r.ImageBuildDraft.Valid() && reflect.DeepEqual(r, want)
	}
	if (r.ImageBuildJob != nil) != (r.Method == "image-build-job-plan") {
		return false
	}
	if r.Method == "image-build-job-plan" {
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, ImageBuildJob: r.ImageBuildJob}
		return r.Tenant != "" && r.ImageBuildJob.Valid() && reflect.DeepEqual(r, want)
	}
	if (r.ImageBuildContent != nil) != (r.Method == "build-context-content") {
		return false
	}
	if r.Method == "build-context-content" {
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, ImageBuildContent: r.ImageBuildContent, After: r.After}
		return r.Tenant != "" && r.ImageBuildContent.Valid() && len(r.After) <= 512 && reflect.DeepEqual(r, want)
	}
	if (r.ImageBuildSource != nil) != (r.Method == "check-build-context") {
		return false
	}
	if r.Method == "check-build-context" {
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, ImageBuildSource: r.ImageBuildSource}
		return r.Tenant != "" && r.ImageBuildSource.Valid() && reflect.DeepEqual(r, want)
	}
	if (r.ImageBuildTransfer != nil) != (r.Method == "build-zip-transfer") {
		return false
	}
	if r.Method == "build-zip-transfer" {
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, ImageBuildTransfer: r.ImageBuildTransfer}
		return r.Tenant != "" && r.ImageBuildTransfer.Valid() && reflect.DeepEqual(r, want)
	}
	if (r.ImageBuild != nil) != (r.Method == "image-builds") {
		return false
	}
	if r.Method == "image-builds" {
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, After: r.After, ImageBuild: r.ImageBuild}
		return r.Tenant != "" && r.ImageBuild.Valid() && len(r.After) <= 512 && reflect.DeepEqual(r, want)
	}
	return true
}

func (r Request) validMethodFields() bool {
	if r.State != "" && r.Method != "node-shell-sessions" {
		return false
	}
	if nodeShellQuery(r.Method) {
		return r.validNodeShellQuery()
	}
	if r.lifecycleEditorRequest() || r.Method == "lifecycle-source" {
		return r.validLifecycleSourceFields()
	}
	if r.LifecycleSource != nil {
		return false
	}
	if (r.NodeForce != nil) != (r.Method == "node-force-remove-plan") {
		return false
	}
	if !r.validTenantStorageFields() || !r.validCertificateFields() || !r.validIngressFields() || !r.validServiceReadFields() || !r.validStandaloneFileFields() || !r.validPublicReadFields() {
		return false
	}
	if !r.validImageBuildFields() {
		return false
	}
	if !r.validCDReadFields() {
		return false
	}
	if r.Events != nil && r.Method != "events" || r.Method == "events" && (r.Events == nil || !r.Events.Valid() || r.Tenant != r.Events.Tenant) {
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
	if (r.VolumeUsage != nil) != (r.Method == "volume-usage") || r.VolumeUsage != nil && (!r.VolumeUsage.Valid() || r.After != "" || r.Tenant == "") {
		return false
	}
	if (r.VolumeSource != nil) != (r.Method == "volume-backup-source") || r.VolumeSource != nil && (!r.VolumeSource.Valid() || r.After != "" || r.Tenant == "") {
		return false
	}
	if (r.VaultPlan != nil) != (r.Method == "vault-approval-plan") {
		return false
	}
	if (r.VaultWritePlan != nil) != (r.Method == "vault-write-plan") || r.VaultWritePlan != nil && r.Tenant != r.VaultWritePlan.Realm {
		return false
	}
	checkerModuleRequest := r.checkerModuleRequest()
	checkerArtifactRequest := r.checkerArtifactRequest()
	if (r.CheckerSource != nil) != checkerArtifactRequest || (r.CheckerModule != nil) != checkerModuleRequest || r.CheckerUpload != nil && (!checkerArtifactRequest || *r.CheckerUpload == ([32]byte{})) {
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
	return r.AuthMethod == "" && r.Credential == "" && r.Secret == nil &&
		(r.Ticket == nil || r.Ticket.AuthMethod == "" && r.Ticket.VerifierRef == "")
}

// execute is also called directly by in-process consumers/tests. Keep its
// narrower selector checks separate from the transport's required-field gate.
func (r Request) validQuerySelectors() bool {
	if r.State != "" && r.Method != "node-shell-sessions" {
		return false
	}
	if nodeShellQuery(r.Method) {
		return r.validNodeShellQuery()
	}
	if r.lifecycleEditorRequest() || r.Method == "lifecycle-source" {
		return r.validLifecycleSourceFields()
	}
	if r.LifecycleSource != nil {
		return false
	}
	if !r.validTenantStorageFields() || !r.validCertificateFields() || !r.validIngressFields() || !r.validServiceReadFields() || !r.validStandaloneFileFields() || !r.validPublicReadFields() {
		return false
	}
	if control.PublicReadMethod(r.Method) || r.Method == "standalone-list" || r.Method == "standalone-get" || r.Method == "volume-file-plan" || r.Method == "volume-file-status" || r.Method == "tenant-storage" || r.Method == "certificates" || r.Method == "ingresses" || r.Method == "service-call" || r.Method == "cd-probe" {
		return true
	}
	if r.Method == "events" {
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, Events: r.Events}
		return r.Events != nil && r.Events.Valid() && r.Tenant == r.Events.Tenant && reflect.DeepEqual(r, want)
	}
	if r.Events != nil {
		return false
	}
	if !r.validLookupFields() {
		return false
	}
	if r.After != "" {
		switch r.Method {
		case "image-build-cache", "image-build-logs", "build-context-content", "image-builds", "app-cd-history", "raft-status", "node-summary", "node-disks", "node-tenant-usage", "mesh-links", "app-revisions", "tasks", "image-usages", "registry-catalog", "registry-prune-preview", "registry-prune-results", "external-registry-pulls", "users", "tenant-members", "tenant-retirement", "members", "node-storage", "resources", "volumes", "volume-backups", "volume-restores", "apps", "app-uploads", "vault", "lifecycles", "registries", "external-registries":
		default:
			return false
		}
		if len(r.After) > 512 || r.Method == "members" && !lifecycle.ValidID(r.After) {
			return false
		}
	}
	if r.Method == "node-force-remove-plan" {
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, NodeForce: r.NodeForce}
		return r.NodeForce != nil && r.NodeForce.Valid() && reflect.DeepEqual(r, want)
	}
	if r.Method == "node-diagnostics" || r.Method == "node-remove-plan" || r.Method == "node-demote-plan" {
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Node: r.Node}
		return lifecycle.ValidID(r.Node) && reflect.DeepEqual(r, want)
	}
	if r.Method == "node-invitation" {
		if !lifecycle.ValidID(r.Node) {
			return false
		}
	} else if r.Method == "node-storage" || r.Method == "tasks" || r.Method == "node-summary" || r.Method == "node-disks" || r.Method == "node-tenant-usage" || r.Method == "mesh-links" {
		if r.Node != "" && !lifecycle.ValidID(r.Node) {
			return false
		}
	} else if r.Node != "" {
		return false
	}
	if r.Method == "raft-status" && (r.Tenant != "" || r.Node != "") {
		return false
	}
	if r.Method == "node-tenant-usage" && (r.Node == "" || r.Tenant != "") {
		return false
	}
	if r.App != "" && (r.Method != "tasks" || !lifecycle.ValidID(r.App)) {
		return false
	}
	if (r.Method == "my-credentials" || r.Method == "users") && r.Tenant != "" || r.Method == "tenant-members" && r.Tenant == "" {
		return false
	}
	if r.NodeStorage != nil && r.Method != "node-storage-space" {
		return false
	}
	return true
}

// Both the transport entry and direct query execution reject payloads for a
// different method; share that rule without moving any authorization checks.
func (r Request) validLookupFields() bool {
	if r.State != "" && r.Method != "node-shell-sessions" {
		return false
	}
	if (r.NodeDrain != nil) != (r.Method == "node-drain-plan" || r.Method == "node-drain-status") {
		return false
	}
	if r.NodeDrain != nil {
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, NodeDrain: r.NodeDrain}
		valid := r.NodeDrain.Valid()
		if r.Method == "node-drain-status" {
			valid = r.NodeDrain.ValidStatus()
		}
		return valid && reflect.DeepEqual(r, want)
	}

	if (r.NodeForce != nil) != (r.Method == "node-force-remove-plan") {
		return false
	}
	if !r.validImageBuildFields() {
		return false
	}
	prune := r.Method == "registry-prune-preview" || r.Method == "registry-prune-results"
	if (r.RegistryPrune != nil) != prune {
		return false
	}
	if prune {
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, After: r.After, RegistryPrune: r.RegistryPrune}
		if r.Tenant == "" || !r.RegistryPrune.Valid(r.Method == "registry-prune-results") || !reflect.DeepEqual(r, want) {
			return false
		}
	}
	maintenance := r.Method == "registry-maintenance-plan" || r.Method == "registry-maintenance-status"
	if (r.RegistryMaintenance != nil) != maintenance {
		return false
	}
	if maintenance {
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, RegistryMaintenance: r.RegistryMaintenance}
		if r.Tenant == "" || (!r.RegistryMaintenance.Valid(r.Method == "registry-maintenance-plan") || r.RegistryMaintenance.Action == control.RegistryPruneAction) || !reflect.DeepEqual(r, want) {
			return false
		}
	}
	if (r.RegistryCatalog != nil) != (r.Method == "registry-catalog") || r.RegistryCatalog != nil && (r.Tenant == "" || !r.RegistryCatalog.Valid()) {
		return false
	}
	if r.RegistryCatalog != nil {
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, After: r.After, RegistryCatalog: r.RegistryCatalog}
		if _, _, err := registryclient.CatalogueCursor(r.After); err != nil || !reflect.DeepEqual(r, want) {
			return false
		}
	}

	if r.Method == "external-registry-pulls" {
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, After: r.After}
		return r.Tenant != "" && len(r.After) <= 512 && reflect.DeepEqual(r, want)
	}

	if !r.validCDReadFields() {
		return false
	}
	if (r.CDToggle != nil) != (r.Method == "app-cd-toggle-plan") || r.CDToggle != nil && (r.Tenant == "" || r.Node != "" || r.After != "" || !r.CDToggle.Valid()) {
		return false
	}
	if (r.ImageCache != nil) != (r.Method == "image-cache-plan" || r.Method == "image-cache-status") || r.ImageCache != nil && (r.Tenant != "" || r.Node != "" || r.After != "" || !r.ImageCache.Valid(r.Method == "image-cache-plan")) {
		return false
	}
	if (r.Tunnel != nil) != (r.Method == "tunnel-reconnect-plan" || r.Method == "tunnel-reconnect-status") || r.Tunnel != nil && (r.Tenant != "" || r.Node != "" || r.After != "" || !r.Tunnel.Valid(r.Method == "tunnel-reconnect-plan")) {
		return false
	}
	if (r.ImageUsage != nil) != (r.Method == "image-usages") || r.ImageUsage != nil && (r.Tenant == "" || r.Node != "" || !r.ImageUsage.Valid()) {
		return false
	}
	if r.ImageUsage != nil && r.After != "" {
		if _, _, err := control.ImageUsagesCursor(r.After); err != nil {
			return false
		}
	}
	if (r.ImageResolve != nil) != (r.Method == "image-resolve") || r.ImageResolve != nil && (r.Tenant == "" || r.Node != "" || r.After != "" || !r.ImageResolve.Valid()) {
		return false
	}
	if (r.ExternalRegistryProbe != nil) != (r.Method == "registry-login-test") || r.ExternalRegistryProbe != nil && (r.Tenant == "" || r.Node != "" || r.After != "" || !r.ExternalRegistryProbe.Valid()) {
		return false
	}
	if (r.ExternalRegistryBind != nil) != (r.Method == "external-registry-bind-plan") || r.ExternalRegistryBind != nil && (r.Tenant == "" || r.Node != "" || r.After != "" || !r.ExternalRegistryBind.Valid()) {
		return false
	}
	if (r.RegistryAction != nil) != (r.Method == "registry-action-plan") || r.RegistryAction != nil && (r.Tenant == "" || r.After != "" || r.Node != "" || !r.RegistryAction.Valid()) {
		return false
	}
	if (r.Compact != nil) != (r.Method == "raft-compact-plan" || r.Method == "raft-compact-status") || r.Compact != nil && (r.Tenant != "" || r.After != "" || r.Node != "" || !r.Compact.Valid(r.Method == "raft-compact-plan")) {
		return false
	}
	if r.App != "" && (r.Method != "tasks" || !lifecycle.ValidID(r.App)) {
		return false
	}
	if (r.AppSource != nil) != (r.Method == "app-source" || r.Method == "app-revisions") || r.AppSource != nil && (r.Tenant == "" || r.Node != "" || !r.AppSource.Valid(r.Method == "app-revisions") || r.Method == "app-source" && r.After != "") {
		return false
	}
	return (r.TaskRestart != nil) == (r.Method == "task-restart-plan" || r.Method == "task-restart-status") && (r.TaskRestart == nil || r.Tenant != "" && r.After == "" && r.Node == "" && r.TaskRestart.Valid(r.Method == "task-restart-plan")) && (r.LogClear != nil) == (r.Method == "app-log-clear-plan" || r.Method == "app-log-clear-status") &&
		(r.LogClear == nil || r.Tenant != "" && r.After == "" && r.Node == "" && r.LogClear.Valid(r.Method == "app-log-clear-plan")) && (r.TargetUser != "") == (r.Method == "user-credentials") &&
		(r.TargetUser == "" || len(r.TargetUser) <= 63 && r.Tenant == "" && r.After == "" && r.Node == "") &&
		(r.Container != nil) == (r.Method == "container-observe") &&
		(r.Container == nil || r.Container.Validate() == nil && r.Tenant != "" && r.After == "" && r.Node == "") &&
		(r.Registry != nil) == (r.Method == "registry-credential")
}

func (r Request) validServiceReadFields() bool {
	if r.Method == "service-call" {
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, ServiceCall: r.ServiceCall, ServiceInput: r.ServiceInput}
		return r.Tenant != "" && r.ServiceCall != nil && r.ServiceCall.Valid() && r.ServiceCall.Body == nil && r.ServiceInput != nil && r.ServiceInput.Valid() && reflect.DeepEqual(r, want)
	}
	if r.Method == "cd-probe" {
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, CDProbe: r.CDProbe}
		return r.Tenant != "" && r.CDProbe != nil && r.CDProbe.Valid() && reflect.DeepEqual(r, want)
	}
	return r.ServiceCall == nil && r.ServiceInput == nil && r.CDProbe == nil
}
