// SPDX-License-Identifier: Apache-2.0

package app

import (
	"fmt"

	"github.com/jay94ks/mydcd/internal/config"
)

// CheckNodeApps refuses node.yaml node_apps this build cannot run
// yet: the node app owner (devel/design/node-apps.md §5 step 5) is
// not implemented, so an enabled node app must not start silently
// without its container.
func CheckNodeApps(c config.Node) error {
	if names := c.NodeApps.Enabled(); len(names) > 0 {
		return fmt.Errorf("node app %s is not available in this build yet", names[0])
	}
	return nil
}
