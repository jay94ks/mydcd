// SPDX-License-Identifier: Apache-2.0

package userauth

import "github.com/jay94ks/mydcd/internal/mydcp"

// Classification never changes the original Cause, delivery phase or retry rules.
func transportCause(err error) string { return mydcp.TransportErrorCause(err) }
