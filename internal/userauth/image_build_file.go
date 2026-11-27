// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// ReadBuildContextFile consumes the existing bounded User pages. Written bytes
// remain tentative until EOF, the original metadata and SHA-256 all agree.
func (c Client) ReadBuildContextFile(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, q imagebuild.ContentQuery, to io.Writer) (imagebuild.Entry, error) {
	if q.Part != "file" || !q.Valid() || q.Offset != 0 || to == nil {
		return imagebuild.Entry{}, sfcp.ErrAdmission
	}
	hash := sha256.New()
	var original imagebuild.Entry
	var tree [32]byte
	var offset uint64
	after := ""
	for {
		page, err := c.BuildContextContent(ctx, peer, session, tenant, q, after)
		if err != nil {
			return imagebuild.Entry{}, err
		}
		file := page.Page.File
		if file == nil || file.Offset != offset {
			return imagebuild.Entry{}, sfcp.ErrFrame
		}
		if after == "" {
			original, tree = file.Entry, page.Page.Tree
		} else if file.Entry != original || page.Page.Tree != tree {
			return imagebuild.Entry{}, sfcp.ErrFrame
		}
		n, err := io.MultiWriter(hash, to).Write(file.Data)
		if err != nil {
			return imagebuild.Entry{}, err
		}
		if n != len(file.Data) {
			return imagebuild.Entry{}, io.ErrShortWrite
		}
		offset += uint64(n)
		if file.Next == 0 {
			if offset != uint64(original.Bytes) || !bytes.Equal(hash.Sum(nil), original.Digest[:]) {
				return imagebuild.Entry{}, imagebuild.ErrDigest
			}
			return original, nil
		}
		after = page.Next
	}
}
