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
	defineNodeRead((*Runtime).nodeReadImageBuildPublicationOwner, false, "image-build-publication-owner")
	defineNodeRead((*Runtime).nodeReadImageBuildSecretInputs, false, "image-build-secret-inputs")
	defineNodeRead((*Runtime).nodeReadImageBuildRegistryPermit, false, "image-build-registry-permit")
	defineNodeRead((*Runtime).nodeReadImageBuildBaseWork, false, "image-build-base-work")
	defineNodeRead((*Runtime).nodeReadImageBuildBaseTlsOwner, false, "image-build-base-tls-owner")
	defineNodeRead((*Runtime).nodeReadImageBuildRegistryTlsOwner, false, "image-build-registry-tls-owner")
	defineNodeRead((*Runtime).nodeReadImageBuildBaseTokenOwner, false, "image-build-base-token-owner")
	defineNodeRead((*Runtime).nodeReadImageBuildBaseOwner, false, "image-build-base-owner")
	defineNodeRead((*Runtime).nodeReadImageBuildCachePruneWork, false, "image-build-cache-prune-work")
	defineNodeRead((*Runtime).nodeReadImageBuildJobWork, false, "image-build-job-work")
	defineNodeRead((*Runtime).nodeReadImageBuildCachesOwner, false, "image-build-caches-owner")
	defineNodeRead((*Runtime).nodeReadImageBuildCacheOwner, false, "image-build-cache-owner")
	defineNodeRead((*Runtime).nodeReadImageBuildLogsOwner, false, "image-build-logs-owner")
	defineNodeRead((*Runtime).nodeReadImageBuildContentOwner, false, "image-build-content-owner")
	defineNodeRead((*Runtime).nodeReadImageBuildGitOwner, false, "image-build-git-owner")
	defineNodeRead((*Runtime).nodeReadImageBuildDraftOwner, false, "image-build-draft-owner")
	defineNodeRead((*Runtime).nodeReadImageBuildSourceOwner, false, "image-build-source-owner")
	defineNodeRead((*Runtime).nodeReadImageBuildArtifactWork, false, "image-build-artifact-work")
	defineNodeRead((*Runtime).nodeReadImageBuildPartPermit, false, "image-build-part-permit")
	defineNodeRead((*Runtime).nodeReadImageBuildIoPermit, false, "image-build-io-permit")
	defineNodeRead((*Runtime).nodeReadImageBuildOwner, false, "image-build-owner")
}

func (r *Runtime) nodeReadImageBuildPublicationOwner(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	peer, known := r.Mesh.Peer(sfcp.Identity(caller))
	if err != nil || !known || !peer.Member {
		return nil, sfcp.ErrAdmission
	}
	q, err := schema.Decode[control.ImageBuildPublicationQuery](input)
	if err != nil {
		return nil, sfcp.ErrAdmission
	}
	result, err := r.imageBuildPublicationOwner(ctx, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}

func (r *Runtime) nodeReadImageBuildSecretInputs(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	q, decodeErr := schema.Decode[control.ImageBuildSecretRequest](input)
	if err != nil || decodeErr != nil || v.Local {
		return nil, sfcp.ErrAdmission
	}
	q.At = time.Now().Unix()
	work, err := r.controlPolicy.ImageBuildSecretInputs(v.State, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(work)
}

func (r *Runtime) nodeReadImageBuildRegistryPermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	q, decodeErr := schema.Decode[control.ImageBuildRegistryRequest](input)
	if err != nil || decodeErr != nil || v.Local {
		return nil, sfcp.ErrAdmission
	}
	q.At = time.Now().Unix()
	permit, err := r.controlPolicy.ImageBuildRegistryPermit(v.State, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(permit)
}

func (r *Runtime) nodeReadImageBuildBaseWork(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	q, decodeErr := schema.Decode[control.ImageBuildBaseQuery](input)
	if err != nil || decodeErr != nil || v.Local {
		return nil, sfcp.ErrAdmission
	}
	q.At = time.Now().Unix()
	read, err := r.controlPolicy.ImageBuildBaseRead(v.State, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(read)
}

func (r *Runtime) nodeReadImageBuildBaseTlsOwner(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	peer, known := r.Mesh.Peer(sfcp.Identity(caller))
	read, decodeErr := schema.Decode[control.ImageBuildBaseRead](input)
	if err != nil || decodeErr != nil || !known || !peer.Member || read.Builder != caller {
		return nil, sfcp.ErrAdmission
	}
	trust, err := r.imageBuildBaseTrustOwner(ctx, read)
	if err != nil {
		return nil, err
	}
	return json.Marshal(trust)
}

func (r *Runtime) nodeReadImageBuildRegistryTlsOwner(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	peer, known := r.Mesh.Peer(sfcp.Identity(caller))
	permit, decodeErr := schema.Decode[control.ImageBuildRegistryPermit](input)
	if err != nil || decodeErr != nil || !known || !peer.Member || permit.Subject.Node != caller {
		return nil, sfcp.ErrAdmission
	}
	trust, err := r.imageBuildRegistryTrustOwner(ctx, permit)
	if err != nil {
		return nil, err
	}
	return json.Marshal(trust)
}

func (r *Runtime) nodeReadImageBuildBaseTokenOwner(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	peer, known := r.Mesh.Peer(sfcp.Identity(caller))
	q, decodeErr := schema.Decode[control.ImageBuildBaseTokenRequest](input)
	if err != nil || decodeErr != nil || !known || !peer.Member || q.Read.Builder != caller {
		return nil, sfcp.ErrAdmission
	}
	token, err := r.imageBuildBaseTokenOwner(ctx, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(token)
}

func (r *Runtime) nodeReadImageBuildBaseOwner(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	peer, known := r.Mesh.Peer(sfcp.Identity(caller))
	read, decodeErr := schema.Decode[control.ImageBuildBaseRead](input)
	if err != nil || decodeErr != nil || !known || !peer.Member || read.Builder != caller {
		return nil, sfcp.ErrAdmission
	}
	result, err := r.resolveImageBuildBaseOwner(ctx, read)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}

func (r *Runtime) nodeReadImageBuildCachePruneWork(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	q, decodeErr := schema.Decode[control.ImageBuildCachePruneWorkQuery](input)
	if err != nil || decodeErr != nil || v.Local {
		return nil, sfcp.ErrAdmission
	}
	q.At = time.Now().Unix()
	work, err := r.controlPolicy.ImageBuildCachePruneWork(v.State, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(work)
}

func (r *Runtime) nodeReadImageBuildJobWork(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	q, decodeErr := schema.Decode[control.ImageBuildJobWorkQuery](input)
	if err != nil || decodeErr != nil || v.Local {
		return nil, sfcp.ErrAdmission
	}
	q.At = time.Now().Unix()
	work, err := r.controlPolicy.ImageBuildJobWork(v.State, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(work)
}

func (r *Runtime) nodeReadImageBuildCachesOwner(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	peer, known := r.Mesh.Peer(sfcp.Identity(caller))
	if err != nil || !known || !peer.Member {
		return nil, sfcp.ErrAdmission
	}
	read, err := schema.Decode[control.ImageBuildCacheInventoryRead](input)
	if err != nil {
		return nil, sfcp.ErrAdmission
	}
	out, err := r.imageBuildCacheInventoryOwner(ctx, read)
	if err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

func (r *Runtime) nodeReadImageBuildCacheOwner(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	peer, known := r.Mesh.Peer(sfcp.Identity(caller))
	if err != nil || !known || !peer.Member {
		return nil, sfcp.ErrAdmission
	}
	read, err := schema.Decode[control.ImageBuildCacheRead](input)
	if err != nil {
		return nil, sfcp.ErrAdmission
	}
	out, err := r.imageBuildCacheOwner(ctx, read)
	if err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

func (r *Runtime) nodeReadImageBuildLogsOwner(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	peer, known := r.Mesh.Peer(sfcp.Identity(caller))
	if err != nil || !known || !peer.Member {
		return nil, sfcp.ErrAdmission
	}
	read, err := schema.Decode[control.ImageBuildLogRead](input)
	if err != nil {
		return nil, sfcp.ErrAdmission
	}
	out, err := r.imageBuildLogsOwner(ctx, read)
	if err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

func (r *Runtime) nodeReadImageBuildContentOwner(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	peer, known := r.Mesh.Peer(sfcp.Identity(caller))
	if err != nil || !known || !peer.Member {
		return nil, sfcp.ErrAdmission
	}
	read, err := schema.Decode[control.ImageBuildContentRead](input)
	if err != nil {
		return nil, sfcp.ErrAdmission
	}
	out, err := r.imageBuildContentOwner(ctx, read)
	if read.Query.Part == "file" {
		reply := imageBuildFileOwnerReply{Code: imageBuildFileReadCode(err)}
		if err == nil {
			reply.Content = &out
		}
		return json.Marshal(reply)
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

func (r *Runtime) nodeReadImageBuildGitOwner(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	peer, known := r.Mesh.Peer(sfcp.Identity(caller))
	if err != nil || !known || !peer.Member {
		return nil, sfcp.ErrAdmission
	}
	call, err := schema.Decode[control.ImageBuildGitCall](input)
	if err != nil {
		return nil, sfcp.ErrAdmission
	}
	out, err := r.saveImageBuildGitOwner(ctx, call)
	if err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

func (r *Runtime) nodeReadImageBuildDraftOwner(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	peer, known := r.Mesh.Peer(sfcp.Identity(caller))
	if err != nil || !known || !peer.Member {
		return nil, sfcp.ErrAdmission
	}
	call, err := schema.Decode[control.ImageBuildDraftCall](input)
	if err != nil {
		return nil, sfcp.ErrAdmission
	}
	out, err := r.imageBuildDraftOwner(ctx, call)
	if call.Request.Kind == "file" {
		reply := imageBuildFileOwnerReply{Code: imageBuildFileReadCode(err)}
		if err == nil {
			reply.Draft = &out
		}
		return json.Marshal(reply)
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

func (r *Runtime) nodeReadImageBuildSourceOwner(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	peer, known := r.Mesh.Peer(sfcp.Identity(caller))
	if err != nil || !known || !peer.Member {
		return nil, sfcp.ErrAdmission
	}
	read, err := schema.Decode[control.ImageBuildSourceRead](input)
	if err != nil {
		return nil, sfcp.ErrAdmission
	}
	out, err := r.checkImageBuildSourceOwner(ctx, read)
	if err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

func (r *Runtime) nodeReadImageBuildArtifactWork(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	q, decodeErr := schema.Decode[control.ImageBuildArtifactSelection](input)
	if err != nil || decodeErr != nil || v.Local {
		return nil, sfcp.ErrAdmission
	}
	work, err := r.controlPolicy.ImageBuildArtifactWork(v.State, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(work)
}

func (r *Runtime) nodeReadImageBuildPartPermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	q, decodeErr := schema.Decode[control.ImageBuildPartPermitCall](input)
	now := time.Now().Unix()
	if err != nil || decodeErr != nil || v.Local || !access.Recent(q.At, now, 30) {
		return nil, sfcp.ErrAdmission
	}
	work, err := r.controlPolicy.ImageBuildPartPermit(v.State, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(work)
}

func (r *Runtime) nodeReadImageBuildIoPermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	q, decodeErr := schema.Decode[control.ImageBuildIOCall](input)
	now := time.Now().Unix()
	if err != nil || decodeErr != nil || v.Local || !access.Recent(q.At, now, 30) {
		return nil, sfcp.ErrAdmission
	}
	work, err := r.controlPolicy.ImageBuildIOPermit(v.State, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(work)
}

func (r *Runtime) nodeReadImageBuildOwner(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	peer, known := r.Mesh.Peer(sfcp.Identity(caller))
	if err != nil || !known || !peer.Member {
		return nil, sfcp.ErrAdmission
	}
	q, err := schema.Decode[control.ImageBuildIOCall](input)
	if err != nil {
		return nil, sfcp.ErrAdmission
	}
	out, err := r.imageBuildTransferOwner(ctx, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(out)
}
