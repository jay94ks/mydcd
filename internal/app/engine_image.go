// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"io"
	"math"

	"github.com/jay94ks/seafield/internal/engineimage"
	"github.com/jay94ks/seafield/internal/engineops"
)

// engineImageRequest is a purpose 37 "manifest" or "blob" request: one item
// of a pulled image, read from Offset (seafield/docs/sfcd-socket.md).
type engineImageRequest struct {
	engineops.Request
	Repository string
	Digest     string
	Offset     uint64
}

// engineImageReply describes the item; its bytes from Offset follow as
// kind 4 chunks.
type engineImageReply struct {
	engineops.Reply
	ContentType string
	Size        int64
}

// engineImageEntries answers the engine from the node's pull tickets. A
// pull path issues a ticket (r.engineImages.Issue) before it asks the
// engine to pull, and releases it when the pull ends.
func (r *Runtime) engineImageEntries() []engineops.Entry {
	tickets := r.engineImages
	serve := func(op string) engineops.Entry {
		return engineops.StreamOp(engineops.Image, op, func(ctx context.Context, q engineImageRequest) (engineImageReply, io.ReadCloser, error) {
			return serveEngineImage(ctx, tickets, op, q)
		})
	}
	return []engineops.Entry{serve("manifest"), serve("blob")}
}

func serveEngineImage(ctx context.Context, tickets *engineimage.Tickets, op string, q engineImageRequest) (engineImageReply, io.ReadCloser, error) {
	if q.Offset > math.MaxInt64 {
		return engineImageReply{}, nil, engineops.Refuse(engineops.Invalid, nil)
	}
	a, body, err := tickets.Serve(ctx, engineimage.Query{Op: op, Repository: q.Repository, Digest: q.Digest, Offset: int64(q.Offset)})
	switch {
	case errors.Is(err, engineimage.ErrRefused):
		return engineImageReply{}, nil, engineops.Refuse(engineops.Refused, err)
	case errors.Is(err, engineimage.ErrNotFound):
		return engineImageReply{}, nil, engineops.Refuse(engineops.NotFound, err)
	case errors.Is(err, engineimage.ErrInvalid):
		return engineImageReply{}, nil, engineops.Refuse(engineops.Invalid, err)
	case err != nil:
		// The source could not be read now; nothing changed, so the engine
		// may ask again.
		return engineImageReply{}, nil, engineops.Refuse(engineops.NotReady, err)
	}
	return engineImageReply{ContentType: a.ContentType, Size: a.Size}, body, nil
}
