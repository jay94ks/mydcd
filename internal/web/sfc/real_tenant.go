// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"encoding/json"
	"io"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/certstore"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/servicecall"
	"github.com/jay94ks/seafield/internal/userauth"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// Tenant resource, image build, registry, certificate, ingress and file
// calls of the real adapter (W1.2 step 2): the userauth.Client calls the
// CLI makes, in the product types.

// --- volumes and files ---

func (c *realConn) Volumes(ctx context.Context, tenant, after string) (Page[VolumeView], error) {
	reply, err := realCall(ctx, c, "volumes", func(u userauth.Client, s access.Session) (userauth.VolumesPage, error) {
		return u.VolumePage(ctx, c.peer, s, tenant, after)
	})
	if err != nil {
		return Page[VolumeView]{}, err
	}
	return Page[VolumeView]{Items: reply.Items, Next: reply.Next, Revision: reply.RootRevision}, nil
}

func (c *realConn) VolumeFilePlan(ctx context.Context, tenant string, q control.VolumeFileQuery) (control.VolumeFilePlan, error) {
	return realCall(ctx, c, "volume-file-plan", func(u userauth.Client, s access.Session) (control.VolumeFilePlan, error) {
		return u.VolumeFilePlan(ctx, c.peer, s, tenant, q)
	})
}

func (c *realConn) VolumeFileStatus(ctx context.Context, tenant, id string) (control.VolumeFileView, error) {
	return realCall(ctx, c, "volume-file-status", func(u userauth.Client, s access.Session) (control.VolumeFileView, error) {
		return u.VolumeFileStatus(ctx, c.peer, s, tenant, id)
	})
}

// VolumeFile streams the native part of an accepted file change once, as
// `sfcli volume file` does: the job is the stored original and its payload.
func (c *realConn) VolumeFile(ctx context.Context, raw SignedOp, source io.Reader, to io.Writer) (userauth.VolumeFileReply, error) {
	const m = "volume-file"
	op, err := DecodeOperation(raw)
	if err != nil {
		return userauth.VolumeFileReply{}, fail(m, CodeInvalid, "malformed signed operation")
	}
	var q control.VolumeFileChange
	switch op.Change.Action {
	case ActionPutVolumeFile, ActionGetVolumeFile, ActionListVolumeFiles, ActionDeleteVolumeFile:
		if json.Unmarshal(op.Change.Payload, &q) != nil {
			return userauth.VolumeFileReply{}, fail(m, CodeInvalid, "payload")
		}
	default:
		return userauth.VolumeFileReply{}, fail(m, CodeInvalid, "not a volume file change")
	}
	job := control.VolumeFileJob{ID: control.VolumeFileID(op), Method: op.Change.Action, Origin: op, Request: q}
	return realCall(ctx, c, m, func(u userauth.Client, s access.Session) (userauth.VolumeFileReply, error) {
		return u.VolumeFile(ctx, c.peer, s, job, source, to)
	})
}

// --- vault plans ---

func (c *realConn) PlanVaultApprovals(ctx context.Context, tenant string, q control.VaultApprovalPlanRequest) (control.VaultApprovalPlan, error) {
	return realCall(ctx, c, "vault-approval-plan", func(u userauth.Client, s access.Session) (control.VaultApprovalPlan, error) {
		return u.PlanVaultApprovals(ctx, c.peer, s, tenant, q)
	})
}

func (c *realConn) PlanVaultWrite(ctx context.Context, tenant string, q control.VaultWritePlanRequest) (control.VaultWritePlan, error) {
	return realCall(ctx, c, "vault-write-plan", func(u userauth.Client, s access.Session) (control.VaultWritePlan, error) {
		return u.PlanVaultWrite(ctx, c.peer, s, q)
	})
}

// --- lifecycle (state check) sources ---

func (c *realConn) LifecycleSourceStage(ctx context.Context, node string, d checker.SourceDescriptor, upload [32]byte, source []byte) (userauth.LifecycleStageResult, error) {
	return realCall(ctx, c, "lifecycle-source-stage", func(u userauth.Client, s access.Session) (userauth.LifecycleStageResult, error) {
		return u.StageLifecycleSource(ctx, c.peer, s, node, d, upload, source)
	})
}

func (c *realConn) LifecycleModuleStage(ctx context.Context, node string, d checker.SourceDescriptor, upload [32]byte, module checker.ModuleArchive) (userauth.LifecycleStageResult, error) {
	return realCall(ctx, c, "lifecycle-module-stage", func(u userauth.Client, s access.Session) (userauth.LifecycleStageResult, error) {
		return u.StageLifecycleModule(ctx, c.peer, s, node, d, upload, module)
	})
}

func (c *realConn) LifecycleSourceRecover(ctx context.Context, node string, d checker.SourceDescriptor, upload [32]byte) (userauth.LifecycleStageResult, error) {
	return realCall(ctx, c, "lifecycle-source-recover", func(u userauth.Client, s access.Session) (userauth.LifecycleStageResult, error) {
		return u.RecoverLifecycleSource(ctx, c.peer, s, node, d, upload)
	})
}

func (c *realConn) LifecycleModuleRecover(ctx context.Context, node string, d checker.SourceDescriptor, upload [32]byte, pin checker.ModulePin) (userauth.LifecycleStageResult, error) {
	return realCall(ctx, c, "lifecycle-module-recover", func(u userauth.Client, s access.Session) (userauth.LifecycleStageResult, error) {
		return u.RecoverLifecycleModule(ctx, c.peer, s, node, d, upload, pin)
	})
}

func (c *realConn) LifecycleSourcePage(ctx context.Context, tenant string, q control.LifecycleSourceQuery) (checker.SourcePage, error) {
	return realCall(ctx, c, "lifecycle-source", func(u userauth.Client, s access.Session) (checker.SourcePage, error) {
		return u.LifecycleSourcePage(ctx, c.peer, s, tenant, q)
	})
}

// --- apps: CD fields, images, diagnostics ---

func (c *realConn) AppDeliveryField(ctx context.Context, tenant string, q control.AppCDFieldRequest) (AppCDField, error) {
	return realCall(ctx, c, "app-cd-field", func(u userauth.Client, s access.Session) (control.AppCDField, error) {
		return u.AppDeliveryField(ctx, c.peer, s, tenant, q)
	})
}

func (c *realConn) AppDeliveryRegistration(ctx context.Context, tenant, app string, sel control.AppApprovalSelection) (control.AppCDApprovalRegistration, error) {
	return realCall(ctx, c, "app-cd-registration", func(u userauth.Client, s access.Session) (control.AppCDApprovalRegistration, error) {
		return u.AppDeliveryRegistration(ctx, c.peer, s, tenant, app, sel)
	})
}

// ClearLogs: `logs-clear` through the connected server, which passes it to
// every member server.
func (c *realConn) ClearLogs(ctx context.Context, tenant string, q LogsClear) (control.LogsClearReply, error) {
	return realCall(ctx, c, "logs-clear", func(u userauth.Client, s access.Session) (control.LogsClearReply, error) {
		return u.ClearLogs(ctx, c.peer, s, q.control(tenant))
	})
}

// StoredLogs: `stored-logs` (node empty = every member server).
func (c *realConn) StoredLogs(ctx context.Context, tenant string, q LogsClear, node string) (control.StoredLogsReply, error) {
	return realCall(ctx, c, "stored-logs", func(u userauth.Client, s access.Session) (control.StoredLogsReply, error) {
		return u.StoredLogs(ctx, c.peer, s, control.StoredLogsQuery{LogsClear: q.control(tenant), Node: node})
	})
}

func (c *realConn) ResolveImage(ctx context.Context, tenant string, q control.ImageResolveQuery) (control.ImageResolveResult, error) {
	return realCall(ctx, c, "image-resolve", func(u userauth.Client, s access.Session) (control.ImageResolveResult, error) {
		return u.ResolveImage(ctx, c.peer, s, tenant, q)
	})
}

func (c *realConn) ProbeCD(ctx context.Context, tenant string, q deployment.GitProbeRequest) (deployment.GitProbeResult, error) {
	return realCall(ctx, c, "cd-probe", func(u userauth.Client, s access.Session) (deployment.GitProbeResult, error) {
		return u.ProbeCD(ctx, c.peer, s, tenant, q)
	})
}

func (c *realConn) CallService(ctx context.Context, tenant string, q servicecall.Request) (servicecall.Result, error) {
	return realCall(ctx, c, "service-call", func(u userauth.Client, s access.Session) (servicecall.Result, error) {
		return u.CallService(ctx, c.peer, s, tenant, q)
	})
}

func (c *realConn) TaskRestartPlan(ctx context.Context, tenant string, q control.TaskRestartQuery) (control.TaskRestartPlan, error) {
	const m = "task-restart-plan"
	reply, err := realCall(ctx, c, m, func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.QueryTaskRestart(ctx, c.peer, s, tenant, true, q)
	})
	if err != nil {
		return control.TaskRestartPlan{}, err
	}
	if reply.TaskRestartPlan == nil {
		return control.TaskRestartPlan{}, missingReply(m)
	}
	return *reply.TaskRestartPlan, nil
}

func (c *realConn) TaskRestartStatus(ctx context.Context, tenant string, q control.TaskRestartQuery) (control.TaskRestartStatus, error) {
	const m = "task-restart-status"
	reply, err := realCall(ctx, c, m, func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.QueryTaskRestart(ctx, c.peer, s, tenant, false, q)
	})
	if err != nil {
		return control.TaskRestartStatus{}, err
	}
	if reply.TaskRestartStatus == nil {
		return control.TaskRestartStatus{}, missingReply(m)
	}
	return *reply.TaskRestartStatus, nil
}

// --- external registries and registry images ---

func (c *realConn) PlanExternalRegistryBind(ctx context.Context, tenant string, q control.ExternalRegistryBindQuery) (control.ExternalRegistryBindPlan, error) {
	return realCall(ctx, c, "external-registry-bind-plan", func(u userauth.Client, s access.Session) (control.ExternalRegistryBindPlan, error) {
		return u.PlanExternalRegistryBind(ctx, c.peer, s, tenant, q)
	})
}

func (c *realConn) ProbeExternalRegistry(ctx context.Context, tenant string, q control.ExternalRegistryProbeQuery) (control.ExternalRegistryProbeResult, error) {
	return realCall(ctx, c, "registry-login-test", func(u userauth.Client, s access.Session) (control.ExternalRegistryProbeResult, error) {
		return u.ProbeExternalRegistry(ctx, c.peer, s, tenant, q)
	})
}

func (c *realConn) RegistryPulls(ctx context.Context, tenant, after string) (control.RegistryPullPage, error) {
	return realCall(ctx, c, "external-registry-pulls", func(u userauth.Client, s access.Session) (control.RegistryPullPage, error) {
		return u.RegistryPulls(ctx, c.peer, s, tenant, after)
	})
}

func (c *realConn) ImageUsages(ctx context.Context, tenant string, q control.ImageUsageQuery, after string) (control.ImageUsagesPage, error) {
	return realCall(ctx, c, "image-usages", func(u userauth.Client, s access.Session) (control.ImageUsagesPage, error) {
		return u.ImageUsages(ctx, c.peer, s, tenant, q, after)
	})
}

func (c *realConn) RegistryCatalogue(ctx context.Context, tenant string, q control.RegistryCatalogueQuery, after string) (control.RegistryCatalogueResult, error) {
	return realCall(ctx, c, "registry-catalog", func(u userauth.Client, s access.Session) (control.RegistryCatalogueResult, error) {
		return u.RegistryCatalogue(ctx, c.peer, s, tenant, q, after)
	})
}

func (c *realConn) PlanRegistryMaintenance(ctx context.Context, tenant string, q control.RegistryMaintenanceQuery) (control.RegistryMaintenancePlan, error) {
	return realCall(ctx, c, "registry-maintenance-plan", func(u userauth.Client, s access.Session) (control.RegistryMaintenancePlan, error) {
		return u.PlanRegistryMaintenance(ctx, c.peer, s, tenant, q)
	})
}

func (c *realConn) RegistryMaintenanceStatus(ctx context.Context, tenant, operation string) (control.RegistryMaintenanceStatus, error) {
	return realCall(ctx, c, "registry-maintenance-status", func(u userauth.Client, s access.Session) (control.RegistryMaintenanceStatus, error) {
		return u.RegistryMaintenanceStatus(ctx, c.peer, s, tenant, operation)
	})
}

func (c *realConn) RegistryPrune(ctx context.Context, tenant string, q control.RegistryPruneQuery, after string, results bool) (control.RegistryPruneView, error) {
	m := "registry-prune-preview"
	if results {
		m = "registry-prune-results"
	}
	return realCall(ctx, c, m, func(u userauth.Client, s access.Session) (control.RegistryPruneView, error) {
		return u.RegistryPrune(ctx, c.peer, s, tenant, q, after, results)
	})
}

// --- image builds ---

func (c *realConn) ImageBuilds(ctx context.Context, tenant string, q control.ImageBuildQuery, after string) (control.ImageBuildPage, error) {
	return realCall(ctx, c, "image-builds", func(u userauth.Client, s access.Session) (control.ImageBuildPage, error) {
		return u.ImageBuilds(ctx, c.peer, s, tenant, q, after)
	})
}

func (c *realConn) BuildContextContent(ctx context.Context, tenant string, q imagebuild.ContentQuery, after string) (control.ImageBuildContentPage, error) {
	return realCall(ctx, c, "build-context-content", func(u userauth.Client, s access.Session) (control.ImageBuildContentPage, error) {
		return u.BuildContextContent(ctx, c.peer, s, tenant, q, after)
	})
}

func (c *realConn) CheckBuildContext(ctx context.Context, tenant string, q control.ImageBuildSourceQuery) (control.ImageBuildSourceResult, error) {
	return realCall(ctx, c, "check-build-context", func(u userauth.Client, s access.Session) (control.ImageBuildSourceResult, error) {
		return u.CheckBuildContext(ctx, c.peer, s, tenant, q)
	})
}

func (c *realConn) PlanImageBuildJob(ctx context.Context, tenant string, q control.ImageBuildJobQuery) (control.ImageBuildJobPlan, error) {
	return realCall(ctx, c, "image-build-job-plan", func(u userauth.Client, s access.Session) (control.ImageBuildJobPlan, error) {
		return u.PlanImageBuildJob(ctx, c.peer, s, tenant, q)
	})
}

func (c *realConn) draft(ctx context.Context, f func(userauth.Client, access.Session) (imagebuild.DraftResponse, error)) (imagebuild.DraftResponse, error) {
	return realCall(ctx, c, "build-draft", f)
}

func (c *realConn) BuildDraft(ctx context.Context, tenant string, q imagebuild.DraftRequest) (imagebuild.DraftResponse, error) {
	return c.draft(ctx, func(u userauth.Client, s access.Session) (imagebuild.DraftResponse, error) {
		return u.BuildDraft(ctx, c.peer, s, tenant, q)
	})
}

func (c *realConn) EditBuildDraft(ctx context.Context, scope imagebuild.DraftScope, edit imagebuild.DraftEdit, data []byte) (imagebuild.DraftResponse, error) {
	return c.draft(ctx, func(u userauth.Client, s access.Session) (imagebuild.DraftResponse, error) {
		return u.EditBuildDraft(ctx, c.peer, s, scope, edit, data)
	})
}

func (c *realConn) PutDraftFilePart(ctx context.Context, scope imagebuild.DraftScope, edit imagebuild.DraftEdit, index uint32, data []byte) (imagebuild.DraftResponse, error) {
	return c.draft(ctx, func(u userauth.Client, s access.Session) (imagebuild.DraftResponse, error) {
		return u.PutDraftFilePart(ctx, c.peer, s, scope, edit, index, data)
	})
}

func (c *realConn) CommitDraftFile(ctx context.Context, scope imagebuild.DraftScope, edit imagebuild.DraftEdit) (imagebuild.DraftResponse, error) {
	return c.draft(ctx, func(u userauth.Client, s access.Session) (imagebuild.DraftResponse, error) {
		return u.CommitDraftFile(ctx, c.peer, s, scope, edit)
	})
}

func (c *realConn) DraftFileStatus(ctx context.Context, scope imagebuild.DraftScope, edit imagebuild.DraftEdit, offset uint32) (imagebuild.DraftResponse, error) {
	return c.draft(ctx, func(u userauth.Client, s access.Session) (imagebuild.DraftResponse, error) {
		return u.DraftFileStatus(ctx, c.peer, s, scope, edit, offset)
	})
}

func (c *realConn) DraftEditResult(ctx context.Context, scope imagebuild.DraftScope, edit imagebuild.DraftEdit) (imagebuild.DraftResponse, error) {
	return c.draft(ctx, func(u userauth.Client, s access.Session) (imagebuild.DraftResponse, error) {
		return u.DraftEditResult(ctx, c.peer, s, scope, edit)
	})
}

func (c *realConn) FreezeBuildDraft(ctx context.Context, plan imagebuild.DraftFreezePlan) (imagebuild.DraftResponse, error) {
	return c.draft(ctx, func(u userauth.Client, s access.Session) (imagebuild.DraftResponse, error) {
		return u.FreezeBuildDraft(ctx, c.peer, s, plan)
	})
}

func (c *realConn) DraftFreezeResult(ctx context.Context, plan imagebuild.DraftFreezePlan) (imagebuild.DraftResponse, error) {
	return c.draft(ctx, func(u userauth.Client, s access.Session) (imagebuild.DraftResponse, error) {
		return u.DraftFreezeResult(ctx, c.peer, s, plan)
	})
}

func (c *realConn) PutBuildZIPPart(ctx context.Context, scope imagebuild.UploadScope, expected uint64, index uint32, data []byte, record ...bool) (control.ImageBuildIOResult, error) {
	return realCall(ctx, c, "build-zip-transfer", func(u userauth.Client, s access.Session) (control.ImageBuildIOResult, error) {
		return u.PutBuildZIPPart(ctx, c.peer, s, scope, expected, index, data, record...)
	})
}

func (c *realConn) SealBuildZIP(ctx context.Context, scope imagebuild.UploadScope, expected uint64) (control.ImageBuildIOResult, error) {
	return realCall(ctx, c, "build-zip-transfer", func(u userauth.Client, s access.Session) (control.ImageBuildIOResult, error) {
		return u.SealBuildZIP(ctx, c.peer, s, scope, expected)
	})
}

func (c *realConn) ImageBuildLogs(ctx context.Context, tenant string, q imagebuild.LogQuery, after string) (control.ImageBuildLogPage, error) {
	return realCall(ctx, c, "image-build-logs", func(u userauth.Client, s access.Session) (control.ImageBuildLogPage, error) {
		return u.ImageBuildLogs(ctx, c.peer, s, tenant, q, after)
	})
}

func (c *realConn) ImageBuildCacheUsage(ctx context.Context, tenant string, q imagebuild.CacheQuery, after string) (control.ImageBuildCachePage, error) {
	return realCall(ctx, c, "image-build-cache", func(u userauth.Client, s access.Session) (control.ImageBuildCachePage, error) {
		return u.ImageBuildCacheUsage(ctx, c.peer, s, tenant, q, after)
	})
}

// --- certificates and ingress ---

func (c *realConn) QueryCertificates(ctx context.Context, q control.CertificateQuery) (control.CertificatePage, error) {
	return realCall(ctx, c, "certificates", func(u userauth.Client, s access.Session) (control.CertificatePage, error) {
		return u.QueryCertificates(ctx, c.peer, s, q)
	})
}

// WriteCertificate sends the protected chain and key once; they are not
// kept. Recover (in.Recover) re-reads the receipt of the same request.
func (c *realConn) WriteCertificate(ctx context.Context, in userauth.CertificateInput) (certstore.Certificate, error) {
	return realCall(ctx, c, "certificate-input", func(u userauth.Client, s access.Session) (certstore.Certificate, error) {
		return u.WriteCertificate(ctx, c.peer, s, in)
	})
}

func (c *realConn) QueryIngresses(ctx context.Context, q control.IngressQuery) (control.IngressPage, error) {
	return realCall(ctx, c, "ingresses", func(u userauth.Client, s access.Session) (control.IngressPage, error) {
		return u.Ingresses(ctx, c.peer, s, q)
	})
}
