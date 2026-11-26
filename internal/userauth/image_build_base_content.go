// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/registryclient"
	"github.com/jay94ks/mydcd/internal/schema"
)

type ImageBuildBaseContentRequest struct {
	Schema    uint8
	Read      control.ImageBuildBaseContentRead
	ExpiresAt int64
	Nonce     [32]byte
}

func (q ImageBuildBaseContentRequest) valid(now int64) bool {
	return q.Schema == 1 && q.Read.Query.Valid() && q.Read.Query.Root == q.Read.Read.Target.Normalized && q.Read.Read.Query.Valid() && q.Read.Read.Builder != ([32]byte{}) && q.Nonce != ([32]byte{}) && q.ExpiresAt > now && q.ExpiresAt-now <= imageContentSeconds
}

// This is an authenticated member execution lane for an already accepted
// job, not a node CLI operation or a fresh user/session authorization.
func (s Service) handleImageBuildBaseContent(base context.Context, conn *mydcp.Session, stream mydcp.Stream, frame mydcp.Frame) error {
	header := sha256.Sum256(frame.Fields[0].Value)
	if !bytes.Equal(header[:], frame.Fields[1].Value) {
		return mydcp.ErrFrame
	}
	envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
	if err != nil {
		return mydcp.ErrFrame
	}
	defer clear(frame.Fields[0].Value)
	defer clear(envelope.Body)
	if err := streamEOF(stream); err != nil {
		return err
	}
	respond := func(code string) error {
		return imageContentReply(stream, frame, header, ImageContentReply{Code: code})
	}
	q, err := schema.Decode[ImageBuildBaseContentRequest](envelope.Body)
	if err != nil || !q.valid(time.Now().Unix()) || conn.RemoteAddr().Network() == "unix" || envelope.Session != nil || envelope.Relay != nil || len(envelope.Signature) != 0 || q.Read.Read.Builder != [32]byte(conn.Peer().Key) || conn.Admit(frame, mydcp.ImageContent, false) != nil {
		return respond("denied")
	}
	ctx, cancel := context.WithDeadline(base, time.Unix(q.ExpiresAt, 0))
	defer cancel()
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	if err := contentDeadline(stream, ctx); err != nil {
		return err
	}
	admit, done := context.WithTimeout(ctx, 5*time.Second)
	view, err := s.Engine.Read(admit, true)
	done()
	if err != nil || view.Local || s.Enabled != nil && !s.Enabled(view.State) {
		return respond("unavailable")
	}
	policy, err := s.Policy.Current(view.State)
	if err != nil {
		return respond("unsupported")
	}
	read, err := policy.CurrentImageBuildBaseContent(view.State, q.Read, time.Now().Unix())
	if err != nil || read.Target.Owner != s.Self.Public {
		return respond("denied")
	}
	if s.ImageBuildBaseContent == nil {
		return respond("unsupported")
	}
	source, err := s.ImageBuildBaseContent(ctx, q.Read)
	if source.Body != nil {
		defer source.Body.Close()
	}
	if err != nil || source.Body == nil || source.Authorize == nil || !source.Info.Valid(q.Read.Query.Selected()) {
		return respond("unavailable")
	}
	if source.Lifetime != nil {
		stopLifetime := context.AfterFunc(source.Lifetime, cancel)
		defer stopLifetime()
	}
	check := source.Authorize
	source.Authorize = func(call context.Context) error {
		if err := check(call); err != nil {
			return err
		}
		return conn.Admit(frame, mydcp.ImageContent, false)
	}
	return sendImageContent(ctx, stream, frame, header, source)
}

func (c Client) ReadImageBuildBaseContent(ctx context.Context, owner mydcp.Peer, read control.ImageBuildBaseContentRead, to io.Writer) (registryclient.ContentInfo, error) {
	q := ImageBuildBaseContentRequest{Schema: 1, Read: read, ExpiresAt: time.Now().Unix() + imageContentSeconds}
	if _, err := rand.Read(q.Nonce[:]); err != nil {
		return registryclient.ContentInfo{}, err
	}
	if c.Self == nil || c.Self.Public != read.Read.Builder || c.Cluster != read.Read.Cluster || !owner.Member || [32]byte(owner.Key) != read.Read.Target.Owner || !q.valid(time.Now().Unix()) {
		return registryclient.ContentInfo{}, mydcp.ErrAdmission
	}
	return c.imageContentTransfer(ctx, owner, q, q.Read.Query.Selected(), q.ExpiresAt, 5, func(_ *mydcp.Session, body []byte) (Envelope, error) {
		return Envelope{Body: body}, nil
	}, nil, to)
}
