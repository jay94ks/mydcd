// SPDX-License-Identifier: Apache-2.0

// Package sfcli is the only boundary through which the sfc-web daemon talks to
// sfcd. The daemon depends on the Client/Conn interfaces; two adapters
// implement them:
//
//   - the real adapter (later) reuses the sfcli CLI's SFCP Unix client and
//     speaks TLS/SFCP on /run/sfcd.sock;
//   - Fake (this package) is an in-memory adapter with seeded scenario data and
//     failure injection, used while REQUEST.md items are pending in sfcd.
//
// Authentication and operation types (Ticket, KeyProof, Session, Change,
// UserOperation, Result) are aliases of the real product types so that signing
// bytes and stored original operations are byte-compatible with sfcd. View
// types still defined here differ from sfcd's (R04 moves them to the real
// types). The per-method status table, generated from this interface, lives
// in apps/sfc-web/CLUSTER_METHODS.md.
//
// A Fake success is never evidence of a real sfcd success.
package sfc
