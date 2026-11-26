// SPDX-License-Identifier: Apache-2.0

package containerops

// ValidLogDriver accepts the finite Engine driver/plugin name in a native
// observation. Empty means an older peer supplied no driver fact; it never
// authorizes local log deletion. No logger options or backend credentials are
// copied from the Engine's HostConfig into the observation.
func ValidLogDriver(driver string) bool {
	if len(driver) > 256 {
		return false
	}
	for _, c := range driver {
		if c < '!' || c > '~' {
			return false
		}
	}
	return true
}

func LocalLogDriver(driver string) bool {
	return driver == "local" || driver == "json-file"
}
