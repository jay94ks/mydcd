// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/jay94ks/seafield/internal/reconcile"
	bkclient "github.com/moby/buildkit/client"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
)

// The same pinned, FD-relative private Unix endpoint is used by finite solves
// and cache maintenance. Readiness is not RPC dispatch or execution success.
func openBuildKitClient(ctx context.Context, directory *os.File) (*bkclient.Client, error) {
	var socket unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), "buildkit.sock", &socket, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil, reconcile.ErrPending
	} else if err != nil || socket.Mode&unix.S_IFMT != unix.S_IFSOCK || socket.Uid != nativeBuilderUID {
		return nil, ErrStorage
	}
	probe, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	socketPath := fmt.Sprintf("/proc/self/fd/%d/buildkit.sock", directory.Fd())
	dial := func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socketPath)
	}
	sdk, err := bkclient.New(probe, "unix://"+socketPath, bkclient.WithContextDialer(dial), bkclient.WithGRPCDialOption(grpc.WithDisableRetry()))
	if err != nil {
		return nil, reconcile.ErrPending
	}
	info, err := sdk.Info(probe)
	if err != nil {
		_ = sdk.Close()
		return nil, reconcile.ErrPending
	}
	if !buildKitCompatible(info) {
		_ = sdk.Close()
		return nil, ErrInvalid
	}
	return sdk, nil
}
