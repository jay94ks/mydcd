// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
)

func commandHelp(out io.Writer) {
	fmt.Fprintln(out, "mydc server-version (selected daemon version/protocol over pinned TLS; no login or wallet)")
	fmt.Fprint(out, `Usage: mydc [global options] COMMAND [command options]

Where to connect and wallet (~/.mydc):
  context       add, list, use, show, set, remove, trust (mydc context --help)
  wallet        init, generate, import, list, public, passwd, status, recover

Accounts (auth: user):
  enroll-admin  Register the initial system administrator
  login         Authenticate with password, private-key or token; save in wallet
  whoami        Show the authenticated account
  logout        Revoke the selected session or query its original outcome

Cluster and tenant operations (auth: user):
  node          list, show, add, invite, promote, demote, cordon, uncordon, drain,
                isolate, restore, remove, renew, rotate-key, diagnostics, disks, tenants,
                shell, images, storage, quota (mydc node --help)
  cluster       status, mesh, reconnect, compact, cli-policy (mydc cluster --help)
  events        diagnostic events; -f follows (mydc events --help)
  manage        tasks, self-credentials, apply, result, resume, prune and resource reads
  app           list, show, check, diff, deploy, down, history, source, logs,
                exec, restart, clear-logs, top, stats, inspect (mydc app --help)
  secret        list, show, init, create, group, put, acl, move, revoke, retire,
                usages, write, approvals, profile, issuer (mydc secret --help)
  volume        list, show, create, delete, backup, restore, move, files (mydc volume --help)
  lifecycle     script, policy, check (mydc lifecycle --help)
  cd            show, set, sync, approve, reject, pause, resume, abandon, replan,
                history, diff, override, release (mydc cd --help)
  ingress       list, show, metrics, blocks, block, unblock, gateways, drain (mydc ingress --help)
  certificate   list, show, put, delete, rollback (mydc certificate --help)

Images (mydc COMMAND --help):
  registry      built-in registries and external image sources
  image         images in a registry: list, show, usages, delete
  build         image builds: context, draft, run, logs, cache, policy

Tenants, users and networks (mydc COMMAND --help; docs/cli):
  tenant        list, show, status, create, set, delete, members, member, resources, quota
  user          list, show, create, key, issue-password, issue-token, revoke-session
  network       list, show, create, update, delete, users (network.yaml)
  route         list, endpoints, propose, approve, withdraw

Operations sent from this computer:
  op            list, show, resume, prune (mydc op --help)

Configuration and installation:
  identity      create DIR (installation identity; not a user login)
  version       Show product version (also --version)

Place global options before COMMAND. Use mydc COMMAND --help for context,
wallet, account and operation command groups; node storage --help is separate.
Example: mydc --context CONTEXT --tenant TENANT app list
--cluster names a context (default: the current one); --tenant a tenant ID.
A context does not create a remote cluster, tenant or membership.
Multiple saved accounts require --user USER. Acceptance is not runtime health
or completed teardown; query status or the original result before resuming.
See docs/quick.md and docs/configuration/cli.md for setup and detailed examples.

Global --reason TEXT, --incident-id ID and --approved-by ACCOUNT_ID label new
signed user operations; labels do not replace approval signatures or alter a
stored original when querying/resuming it.

Global options:
`)
}
