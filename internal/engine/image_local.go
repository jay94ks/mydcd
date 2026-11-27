// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"encoding/json"
	"io"

	cerrdefs "github.com/containerd/errdefs"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/moby/client"

	"github.com/jay94ks/seafield/internal/registryclient"
)

// LoadImage makes a verified local image (a cluster app image read from its
// bundle) present in the Engine: it inspects the exact config or manifest
// ID and loads the original graph only when neither is there. The caller
// has already checked the image digest against its pin.
func (c *Client) LoadImage(ctx context.Context, image v1.Image) (client.ImageInspectResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	archive, err := prepareExternalArchive(image)
	if err != nil {
		return client.ImageInspectResult{}, registryclient.Sanitize(err)
	}
	got, err := c.inspectExternalImage(ctx, archive)
	if err == nil || !cerrdefs.IsNotFound(err) {
		return got, err
	}
	if err = c.loadExternalImage(ctx, cancel, archive); err != nil {
		return got, err
	}
	return c.inspectExternalImage(ctx, archive)
}

// Legacy stores use C; containerd stores use the original platform manifest M.
// Neither a load log nor an unrelated digest is evidence of the source origin.
func (c *Client) inspectExternalImage(ctx context.Context, archive *externalArchive) (client.ImageInspectResult, error) {
	var got client.ImageInspectResult
	var err error
	for _, id := range []string{archive.config.Digest.String(), archive.manifest.Digest.String()} {
		got, err = c.API.ImageInspect(ctx, id)
		if err == nil {
			if got.ID != id {
				return got, ErrOwnership
			}
			return got, nil
		}
		if !cerrdefs.IsNotFound(err) {
			return got, err
		}
	}
	return got, err
}

func (c *Client) loadExternalImage(ctx context.Context, cancel context.CancelFunc, archive *externalArchive) (failure error) {
	if c.imageAPI == nil {
		return ErrOwnership
	}
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := archive.write(ctx, &archiveBudget{writer: writer, left: registryclient.MaxImageBytes + (32 << 20)})
		_ = writer.CloseWithError(err)
		done <- err
	}()
	defer func() {
		joined := false
		if failure == nil {
			select {
			case err := <-done:
				joined = true
				if err != nil {
					failure = registryclient.Sanitize(err)
				}
			case <-ctx.Done():
				failure = registryclient.Sanitize(ctx.Err())
			}
		}
		if failure != nil {
			cancel()
		}
		_ = reader.CloseWithError(failure)
		_ = writer.CloseWithError(failure)
		if !joined {
			<-done
		}
	}()
	stream, err := c.imageAPI.ImageLoad(ctx, reader, client.ImageLoadWithQuiet(true))
	if err != nil {
		return registryclient.Sanitize(err)
	}
	defer stream.Close()
	decoder := json.NewDecoder(&loadResponseBudget{reader: stream, left: 8 << 20})
	for {
		var message struct {
			Error       string
			ErrorDetail json.RawMessage
		}
		err := decoder.Decode(&message)
		if err == io.EOF {
			return nil
		}
		if err != nil || message.Error != "" || len(message.ErrorDetail) > 0 && string(message.ErrorDetail) != "null" {
			return &registryclient.Error{Code: "IMAGE_LOAD_FAILED"}
		}
	}
}

type archiveBudget struct {
	writer io.Writer
	left   int64
}

func (b *archiveBudget) Write(p []byte) (int, error) {
	if int64(len(p)) > b.left {
		return 0, &registryclient.Error{Code: "IMAGE_BUDGET"}
	}
	n, err := b.writer.Write(p)
	b.left -= int64(n)
	return n, err
}

type loadResponseBudget struct {
	reader io.Reader
	left   int64
}

func (b *loadResponseBudget) Read(p []byte) (int, error) {
	if b.left < 0 {
		return 0, &registryclient.Error{Code: "IMAGE_LOAD_FAILED"}
	}
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.reader.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return 0, &registryclient.Error{Code: "IMAGE_LOAD_FAILED"}
	}
	return n, err
}
