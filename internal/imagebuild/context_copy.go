// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"errors"
	"io"

	"github.com/moby/moby/client"
)

// CopyContext is one SDK effect into an already authorized original container
// input directory. Destination and archive prefix are product constants, never
// tenant paths. The caller persists its dispatch intent before calling and
// verifies/settles the original after any ambiguous reply; this never retries.
func CopyContext(ctx context.Context, api *client.Client, native string, body io.ReaderAt, scope UploadScope, seal SealReceipt) (Tree, error) {
	if api == nil || native == "" || body == nil || ctx == nil || !seal.Valid(scope) {
		return Tree{}, ErrInvalid
	}
	var tree Tree
	err := copyInputArchive(ctx, api, native, func(w io.Writer) error {
		var err error
		tree, err = WriteContextTAR(ctx, body, scope, seal, w)
		return err
	})
	if err != nil {
		return Tree{}, err
	}
	return tree, nil
}

func copyInputArchive(ctx context.Context, api *client.Client, native string, encode func(io.Writer) error) error {
	if ctx == nil || api == nil || native == "" || encode == nil {
		return ErrInvalid
	}
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := encode(writer)
		closeErr := writer.CloseWithError(err)
		done <- errors.Join(err, closeErr)
	}()
	_, err := api.CopyToContainer(ctx, native, client.CopyToContainerOptions{DestinationPath: "/input", Content: reader, CopyUIDGID: true, AllowOverwriteDirWithFile: false})
	// A failed/early response must unblock the encoder before returning. Both
	// success and failure join it; no background archive writer retains a pin.
	_ = reader.CloseWithError(io.ErrClosedPipe)
	encoded := <-done
	if err != nil || encoded != nil {
		// Docker HTTP errors can contain response bodies and host paths. Keep
		// only our bounded encoder cause and cancellation classification.
		return errors.Join(ErrStorage, ctx.Err(), encoded)
	}
	return nil
}
