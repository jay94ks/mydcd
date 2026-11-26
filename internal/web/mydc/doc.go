// SPDX-License-Identifier: Apache-2.0

// Package mydc is the only boundary through which the mydc-web daemon talks to
// mydcd. The daemon depends on the Client/Conn interfaces; two adapters
// implement them:
//
//   - the real adapter (later) reuses the mydc CLI's MYDCP Unix client and
//     speaks TLS/MYDCP on /var/run/mydc.sock;
//   - Fake (this package) is an in-memory adapter with seeded scenario data and
//     failure injection, used while REQUEST.md items are pending in mydcd.
//
// Authentication and operation types (Ticket, KeyProof, Session, Change,
// UserOperation, Result) are aliases of the real product types so that signing
// bytes and stored original operations are byte-compatible with mydcd. View
// types still defined here differ from mydcd's (R04 moves them to the real
// types). The per-method status table, generated from this interface, lives
// in apps/mydc-web/CLUSTER_METHODS.md.
//
// A Fake success is never evidence of a real mydcd success.
package mydc
