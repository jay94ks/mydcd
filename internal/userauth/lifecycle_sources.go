// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"reflect"
	"time"
	"unicode/utf8"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

type LifecycleStageResult struct {
	Node        string
	Owner       [32]byte
	Descriptor  checker.SourceDescriptor
	Upload      [32]byte
	Source      *checker.SourceFact        `json:",omitempty"`
	Module      *checker.ModuleFact        `json:",omitempty"`
	Diagnostics []checker.SourceDiagnostic `json:",omitempty"`
}

func (r LifecycleStageResult) MetadataValid() bool {
	return safeID(r.Node) && r.Owner != ([32]byte{}) && r.Descriptor.Validate() == nil && r.Upload != ([32]byte{})
}
func (r LifecycleStageResult) Valid(module bool) bool {
	if !safeID(r.Node) || r.Owner == ([32]byte{}) || r.Descriptor.Validate() != nil || r.Upload == ([32]byte{}) || len(r.Diagnostics) > checker.MaxSourceDiagnostics {
		return false
	}
	for _, d := range r.Diagnostics {
		if !d.Valid() {
			return false
		}
	}
	if len(r.Diagnostics) > 0 {
		return !module && r.Source == nil && r.Module == nil
	}
	if module {
		return r.Source == nil && r.Module != nil && r.Module.Verify() == nil && r.Module.Owner == r.Owner && r.Module.Tenant == r.Descriptor.Tenant
	}
	return r.Module == nil && r.Source != nil && r.Source.Verify() == nil && r.Source.Owner == r.Owner && r.Source.Tenant == r.Descriptor.Tenant && r.Source.ContentDigest() == r.Descriptor.ContentDigest() && r.Source.Upload != nil && *r.Source.Upload == r.Upload
}

func (r Request) lifecycleEditorRequest() bool {
	return r.Method == "lifecycle-source-stage" || r.Method == "lifecycle-module-stage" || r.Method == "lifecycle-source-recover" || r.Method == "lifecycle-module-recover"
}
func (r Request) validLifecycleSourceFields() bool {
	if !r.lifecycleEditorRequest() {
		return false
	}
	module := r.Method == "lifecycle-module-stage" || r.Method == "lifecycle-module-recover"
	recover := r.Method == "lifecycle-source-recover" || r.Method == "lifecycle-module-recover"
	want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, Node: r.Node, CheckerSource: r.CheckerSource, CheckerModule: r.CheckerModule, CheckerUpload: r.CheckerUpload}
	return r.Tenant != "" && (r.Node == "" && !recover || safeID(r.Node)) && r.CheckerSource != nil && r.CheckerSource.Validate() == nil && r.CheckerSource.Tenant == r.Tenant && r.CheckerUpload != nil && *r.CheckerUpload != ([32]byte{}) && (r.CheckerModule != nil) == module && (!module || moduleInput(*r.CheckerSource, *r.CheckerModule)) && reflect.DeepEqual(r, want)
}

func (c Client) stageLifecycle(ctx context.Context, peer sfcp.Peer, session access.Session, node, method string, d checker.SourceDescriptor, pin *checker.ModulePin, upload [32]byte, data []byte) (LifecycleStageResult, error) {
	request := Request{Method: method, Tenant: d.Tenant, Node: node, CheckerSource: &d, CheckerModule: pin, CheckerUpload: &upload}
	if c.Verify(session) != nil || !request.validLifecycleSourceFields() || c.Self == nil || session.Key != c.Self.Public {
		return LifecycleStageResult{}, sfcp.ErrAdmission
	}
	recover := method == "lifecycle-source-recover" || method == "lifecycle-module-recover"
	length, digest := d.Length, d.Digest
	if pin != nil {
		length, digest = pin.Length, pin.Digest
	}
	if !recover && (uint64(len(data)) != length || sha256.Sum256(data) != digest) {
		return LifecycleStageResult{}, sfcp.ErrAdmission
	}
	var reply Reply
	var err error
	if recover {
		body, e := requestBody(request)
		if e != nil {
			return LifecycleStageResult{}, e
		}
		reply, _, err = c.exchange(ctx, peer, func(conn *sfcp.Session) (Envelope, error) {
			return Envelope{Body: body, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}, nil
		}, false)
	} else {
		reply, err = c.stageCheckerArtifact(ctx, peer, session, request, data)
	}
	if err != nil {
		if meta := reply.LifecycleStage; meta != nil && meta.MetadataValid() && meta.Upload == upload && meta.Descriptor.Tenant == d.Tenant && meta.Descriptor.ContentDigest() == d.ContentDigest() && (node == "" || meta.Node == node) {
			return *meta, err
		}
		return LifecycleStageResult{}, err
	}
	result := reply.LifecycleStage
	if result == nil || !result.Valid(pin != nil) || result.Descriptor.ContentDigest() != d.ContentDigest() || result.Descriptor.Tenant != d.Tenant || result.Upload != upload || node != "" && result.Node != node || result.Source != nil && result.Source.Cluster != c.Cluster || result.Module != nil && (result.Module.Cluster != c.Cluster || result.Module.Module != *pin) {
		return LifecycleStageResult{}, sfcp.ErrFrame
	}
	return *result, nil
}
func (c Client) StageLifecycleSource(ctx context.Context, peer sfcp.Peer, session access.Session, node string, d checker.SourceDescriptor, upload [32]byte, data []byte) (LifecycleStageResult, error) {
	return c.stageLifecycle(ctx, peer, session, node, "lifecycle-source-stage", d, nil, upload, data)
}
func (c Client) StageLifecycleModule(ctx context.Context, peer sfcp.Peer, session access.Session, node string, d checker.SourceDescriptor, upload [32]byte, module checker.ModuleArchive) (LifecycleStageResult, error) {
	return c.stageLifecycle(ctx, peer, session, node, "lifecycle-module-stage", d, &module.Pin, upload, module.ZIP)
}
func (c Client) RecoverLifecycleSource(ctx context.Context, peer sfcp.Peer, session access.Session, node string, d checker.SourceDescriptor, upload [32]byte) (LifecycleStageResult, error) {
	return c.stageLifecycle(ctx, peer, session, node, "lifecycle-source-recover", d, nil, upload, nil)
}
func (c Client) RecoverLifecycleModule(ctx context.Context, peer sfcp.Peer, session access.Session, node string, d checker.SourceDescriptor, upload [32]byte, pin checker.ModulePin) (LifecycleStageResult, error) {
	return c.stageLifecycle(ctx, peer, session, node, "lifecycle-module-recover", d, &pin, upload, nil)
}

func (s Service) streamLifecycleSource(ctx context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame, header [32]byte, envelope Envelope, request Request, binding userBinding) error {
	inputDone := false
	respond := func(reply Reply) error {
		err := s.respond(stream, frame, header, reply)
		if err == nil && !inputDone && reply.Code != "continue" {
			return streamEOF(stream)
		}
		return err
	}
	if envelope.Session == nil || !request.validLifecycleSourceFields() {
		return respond(Reply{Schema: 1, Code: "denied"})
	}
	recover := request.Method == "lifecycle-source-recover" || request.Method == "lifecycle-module-recover"
	module := request.Method == "lifecycle-module-stage" || request.Method == "lifecycle-module-recover"
	current, view, allowed := s.planStreamView(ctx, binding, request, envelope, s.Engine.IsLeader())
	if allowed.Code != "ok" {
		return respond(allowed)
	}
	selected, err := current.Policy.LifecycleProviderFor(view.State, *envelope.Session, time.Now().Unix(), *request.CheckerSource, request.Node, s.Self.Public, recover)
	if err != nil {
		return respond(Reply{Schema: 1, Code: checkerArtifactFailure(err)})
	}
	if envelope.Relay != nil && selected.Owner != s.Self.Public {
		return respond(Reply{Schema: 1, Code: "denied"})
	}
	publication := s.CheckerSources
	if selected.Owner == s.Self.Public {
		if publication == nil {
			return respond(Reply{Schema: 1, Code: "unavailable"})
		}
		finish, cause := publication.BeginPublication(ctx, *envelope.Session, *request.CheckerSource, *request.CheckerUpload, recover)
		if cause != nil {
			return respond(Reply{Schema: 1, Code: checkerArtifactFailure(cause)})
		}
		defer finish()
	}
	metadata := LifecycleStageResult{Node: selected.Node, Owner: selected.Owner, Descriptor: request.CheckerSource.Clone(), Upload: *request.CheckerUpload}
	if !recover {
		if err = respond(Reply{Schema: 1, Code: "continue", LifecycleStage: &metadata}); err != nil {
			return err
		}
	}
	var data []byte
	if recover {
		if err = streamEOF(stream); err != nil {
			return err
		}
	} else {
		length, digest, limit := request.CheckerSource.Length, request.CheckerSource.Digest, checker.MaxScriptBytes
		if module {
			length, digest, limit = request.CheckerModule.Length, request.CheckerModule.Digest, checker.MaxModuleBytes
		}
		data, err = readUserInput(conn, stream, frame.Request, header, int(length), digest, limit)
		if err != nil {
			return err
		}
		defer clear(data)
	}
	inputDone = true
	if selected.Owner != s.Self.Public {
		peer, ok := s.Mesh.Peer(sfcp.Identity(selected.Owner))
		if !ok || !peer.Member || peer.ID != selected.Node {
			return respond(Reply{Schema: 1, Code: "unavailable"})
		}
		client := Client{Mesh: s.Mesh, Self: s.Self, Cluster: s.Policy.Cluster}
		makeEnvelope := func(next *sfcp.Session) (Envelope, error) {
			copy := envelope
			copy.Relay = &Relay{Node: s.Self.Public, Target: selected.Owner, Caller: binding.key, Challenge: binding.challenge, Connection: next.PeerChallenge()}
			copy.Relay.Signature = ed25519.Sign(s.Self.Private, RelayBytes(s.Policy.Cluster, copy))
			return copy, nil
		}
		var reply Reply
		if recover {
			reply, _, err = client.exchangeKind(ctx, peer, makeEnvelope, false, 3)
		} else {
			reply, err = client.stageCheckerExchange(ctx, peer, data, 3, makeEnvelope)
		}
		if err != nil && reply.Code == "" {
			reply.Schema, reply.Code = 1, "unknown"
		}
		reply.RelayedBy = s.Self.Actor()
		return respond(reply)
	}
	result := LifecycleStageResult{Node: selected.Node, Owner: selected.Owner, Descriptor: request.CheckerSource.Clone(), Upload: *request.CheckerUpload}
	if module {
		var fact checker.ModuleFact
		if recover {
			fact, err = publication.RecoverPublicationModule(ctx, *envelope.Session, *request.CheckerSource, *request.CheckerUpload, *request.CheckerModule)
		} else {
			fact, err = publication.StagePublicationModule(ctx, *envelope.Session, *request.CheckerSource, *request.CheckerUpload, checker.ModuleArchive{Pin: *request.CheckerModule, ZIP: data})
		}
		result.Module = &fact
	} else if recover {
		var fact checker.SourceFact
		fact, err = publication.RecoverPublication(ctx, *envelope.Session, *request.CheckerSource, *request.CheckerUpload)
		result.Source = &fact
	} else {
		result.Source, result.Diagnostics, err = publication.ValidatePublication(ctx, *envelope.Session, *request.CheckerSource, *request.CheckerUpload, data)
	}
	if err != nil {
		return respond(Reply{Schema: 1, Code: checkerArtifactFailure(err)})
	}
	if recover {
		if result.Source != nil {
			result.Owner = result.Source.Owner
		}
		if result.Module != nil {
			result.Owner = result.Module.Owner
		}
		currentOwner, cause := current.resourceOwner(view.State, selected.Node, result.Owner)
		if cause != nil || currentOwner != selected.Owner {
			return respond(Reply{Schema: 1, Code: "denied"})
		}
	}
	if !result.Valid(module) {
		return sfcp.ErrFrame
	}
	return respond(Reply{Schema: 1, Code: "ok", Tenant: request.Tenant, LifecycleStage: &result})
}

// LifecycleSourceQuery reads one page of a lifecycle script's source.
type LifecycleSourceQuery struct {
	Tenant string
	Source control.LifecycleSourceQuery
}

func (q LifecycleSourceQuery) Valid() bool { return lifecycle.ValidID(q.Tenant) && q.Source.Valid() }

// LifecycleSourceMethod needs ManageServices in the tenant (cleanup sessions
// too) and the lifecycle-source operation.
var LifecycleSourceMethod = define(Method[LifecycleSourceQuery, checker.SourcePage]{Name: "lifecycle-source"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q LifecycleSourceQuery) (checker.SourcePage, string) {
	c, err := s.Policy.Catalog(view.State)
	now := time.Now().Unix()
	if err != nil || c.AuthorizeSessionCleanup(session, s.Policy.Cluster, s.Policy.Issuer(session.Issuer), now, q.Tenant, access.ManageServices) != nil || c.OperationAllowed(session, "lifecycle-source") != nil {
		return checker.SourcePage{}, "denied"
	}
	if s.LifecycleSourceReader == nil {
		return checker.SourcePage{}, "unavailable"
	}
	read, err := s.Policy.LifecycleSourceVersion(view.State, session, now, q.Tenant, q.Source)
	if err != nil {
		return checker.SourcePage{}, checkerArtifactFailure(err)
	}
	page, err := s.LifecycleSourceReader(ctx, read)
	if err != nil {
		return checker.SourcePage{}, checkerArtifactFailure(err)
	}
	return page, "ok"
})

func (c Client) LifecycleSourcePage(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, q control.LifecycleSourceQuery) (checker.SourcePage, error) {
	page, err := call(ctx, c, peer, session, LifecycleSourceMethod, LifecycleSourceQuery{Tenant: tenant, Source: q})
	if err != nil {
		return checker.SourcePage{}, err
	}
	if !page.Valid() || page.Tenant != tenant || page.Name != q.Name || page.Revision != q.Revision || page.Offset != q.Offset {
		return checker.SourcePage{}, sfcp.ErrFrame
	}
	return page, nil
}

type LifecycleSourceText struct {
	Tenant, Name, Source string
	Revision             uint64
	Digest               [32]byte
}

func (c Client) LifecycleSource(ctx context.Context, peer sfcp.Peer, session access.Session, tenant, name string, revision uint64) (LifecycleSourceText, error) {
	var data []byte
	defer func() { clear(data) }()
	var first checker.SourcePage
	for offset := uint64(0); ; {
		page, err := c.LifecycleSourcePage(ctx, peer, session, tenant, control.LifecycleSourceQuery{Name: name, Revision: revision, Offset: offset})
		if err != nil {
			return LifecycleSourceText{}, err
		}
		if offset == 0 {
			first = page
		} else if page.Digest != first.Digest || page.Total != first.Total {
			return LifecycleSourceText{}, sfcp.ErrFrame
		}
		data = append(data, page.Data...)
		if page.Next == 0 {
			break
		}
		offset = page.Next
	}
	if uint64(len(data)) != first.Total || sha256.Sum256(data) != first.Digest || !utf8.Valid(data) {
		return LifecycleSourceText{}, sfcp.ErrFrame
	}
	return LifecycleSourceText{Tenant: tenant, Name: name, Revision: revision, Digest: first.Digest, Source: string(data)}, nil
}
