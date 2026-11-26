// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"time"

	"github.com/jay94ks/mydcd/internal/mydcp"
)

func (s Service) forwardContainerSession(ctx context.Context, conn *mydcp.Session, stream mydcp.Stream, frame mydcp.Frame, digest [32]byte, envelope Envelope, binding userBinding, q ContainerSessionRequest) error {
	current := q.Intent.Target.Owner

	if s.Engine == nil {
		return containerSessionReply(stream, frame, digest, ContainerSessionReply{Code: "unavailable"})
	}
	view, err := s.Engine.Read(ctx, false)
	if err != nil {
		return containerSessionReply(stream, frame, digest, ContainerSessionReply{Code: "unavailable"})
	}
	current, err = s.resourceOwner(view.State, q.Intent.Target.Node, q.Intent.Target.Owner)
	if err != nil {
		return containerSessionReply(stream, frame, digest, ContainerSessionReply{Code: "denied"})
	}

	peer, ok := s.Mesh.Peer(mydcp.Identity(current))
	if !ok || !peer.Member || peer.Key == mydcp.Identity(s.Self.Public) {
		return containerSessionReply(stream, frame, digest, ContainerSessionReply{Code: "unavailable"})
	}
	c := Client{Mesh: s.Mesh, Self: s.Self, Cluster: s.Policy.Cluster}
	remote, reply, err := c.containerSessionExchange(ctx, peer, q, 3, 10*time.Second, func(conn *mydcp.Session, body []byte) (Envelope, error) {
		if !bytes.Equal(body, envelope.Body) {
			return Envelope{}, mydcp.ErrFrame
		}
		copy := envelope
		copy.Relay = &Relay{Node: s.Self.Public, Target: [32]byte(peer.Key), Caller: binding.key, Challenge: binding.challenge, Connection: conn.PeerChallenge()}
		copy.Relay.Signature = ed25519.Sign(s.Self.Private, RelayBytes(s.Policy.Cluster, copy))
		return copy, nil
	})
	if remote != nil {
		defer remote.Close()
	}
	if err != nil {
		code := "unavailable"
		var failure *Error
		if errors.As(err, &failure) && failure.Phase == mydcp.Completed {
			code = failure.Code
		}
		return containerSessionReply(stream, frame, digest, ContainerSessionReply{Code: code})
	}
	if q.Method != "open" {
		return containerSessionReply(stream, frame, digest, reply)
	}
	if err = containerSessionReply(stream, frame, digest, reply); err != nil {
		return err
	}
	local, err := newContainerChannel(ctx, conn, stream, frame.Request, *q.Intent, envelope.Session.ExpiresAt, false)
	if err != nil {
		return err
	}
	defer local.releaseContext()
	done := make(chan error, 2)
	pump := func(from, to *ContainerChannel) {
		for {
			r, err := from.Receive()
			if err != nil {
				done <- err
				return
			}
			if err = to.Send(r); err != nil {
				done <- err
				return
			}
			if r.Kind == "end" || r.Kind == "error" || r.Kind == "cancel" {
				done <- nil
				return
			}
		}
	}
	go pump(local, remote)
	go pump(remote, local)
	first := <-done
	local.StopReceive()
	_ = remote.Close()
	<-done
	if errors.Is(first, io.EOF) && ctx.Err() == nil {
		return nil
	}
	return first
}
