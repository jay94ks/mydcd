// SPDX-License-Identifier: Apache-2.0

package mydc

import "github.com/jay94ks/mydcd/internal/userauth"

// REQ-48 (real): `server-version`, the sessionless finite User request
// {Schema:1, Method:"server-version", Nonce}. The reply is the connected
// mydcd itself: ServerVersion{Version:"1", Protocol:1, Commit?, BuildTime?
// (vcs.time, RFC 3339)}; it is not forwarded to the leader and needs no
// login (docs/reference/resource-queries.md '로그인 전 서버 판 조회').
type ServerVersion = userauth.ServerVersion
