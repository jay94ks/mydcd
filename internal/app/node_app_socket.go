// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"fmt"
	"os"

	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/nodeapp"
)

// ListenManagement opens the host management socket, then one dedicated
// socket per enabled node app (devel/design/node-apps.md §3). A node app
// socket lives alone in nodeapp.RunDir, owned by the app's UID, and admits
// the same TLS and user login as the host socket. Runtime.Close closes all.
func (r *Runtime) ListenManagement(c config.Node) error {
	if err := r.Mesh.ListenUnix(c.Node.ManagementSocket); err != nil {
		return err
	}
	return listenNodeAppSockets(r.Mesh, c)
}

func listenNodeAppSockets(mesh *mydcp.Transport, c config.Node) error {
	for _, name := range c.NodeApps.Enabled() {
		uid, err := nodeAppUID(c, name)
		if err != nil {
			return err
		}
		if err = prepareRunDir(nodeapp.RunDir(c.Node.StateDir, name)); err != nil {
			return fmt.Errorf("node app %s run directory: %w", name, err)
		}
		if err = mesh.ListenUnixOwned(nodeapp.SocketPath(c.Node.StateDir, name), uid); err != nil {
			return fmt.Errorf("node app %s management socket: %w", name, err)
		}
	}
	return nil
}

func nodeAppUID(c config.Node, name string) (uint32, error) {
	if name == nodeapp.Web && c.NodeApps.Web != nil {
		return c.NodeApps.Web.UID, nil
	}
	return 0, fmt.Errorf("node app %s has no UID", name)
}

// prepareRunDir creates the run directory and its node-apps parents (0700)
// and makes the run directory itself 0755: the container user must enter
// this one bound directory, while the socket inside stays 0600 and owned by
// that user. Ownership and type are checked again by the socket listener.
func prepareRunDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("not a directory")
	}
	return os.Chmod(dir, 0755)
}
