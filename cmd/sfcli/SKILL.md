---
name: sfcli
description: Operate a Seafield Cluster cluster with the sfcli command line — deploy and inspect apps, manage tenants, users, networks, volumes, secrets, images and servers — safely from a script or an AI agent.
---

# Using the sfcli CLI

`sfcli` manages a Seafield Cluster cluster (servers running `sfcd`). Commands have the
shape `sfcli RESOURCE VERB [NAME] [options]`. `sfcli COMMAND --help` shows a
command's usage, sub-commands and options; read it before using a command you
have not used in this session. The user documentation is in `docs/cli/` of the
sfcd repository.

## Run without prompts

- Set `SFC_NONINTERACTIVE=1` in the environment. Then sfcli never asks a
  question: a command that needs an answer fails instead of waiting. There is
  no flag for this.
- `-y` answers yes to confirmation questions (deleting, restarting, taking an
  app down). Pass it only when the user asked for that exact change.
- Passwords are never given on the command line. Use the file or descriptor
  options the command documents (for example `SFC_WALLET_PASSWORD_FILE`, or
  `--group-password-fd REALM/GROUP=FD` for `app deploy`). If none is
  available, stop and ask the user.
- A node key cannot be trusted without checking: `sfcli context add` and
  `sfcli context trust` need `--key HEX` when there is no terminal. Get the key
  from the user (they read it with `sfcd identity` on the server); never
  guess or copy it from the command's own output.

## Read output as data

- `-o json` (or `-o yaml`) prints every value, including ones the table
  leaves out. Parse it instead of the table.
- Exit codes: `0` success, `1` failure, `2` bad command line, `4` the result is
  not known yet (see "Operations" below). `3` means the server refused a step
  (permission, conflict) for commands that document it, such as `app deploy`.
  Other codes are listed in each command's documentation.
- Error text goes to stderr.

## Where and as whom

- A context is one cluster: endpoint, default user and default tenant
  (`sfcli context list`, `sfcli context show`). `--context NAME` sends one
  command elsewhere; `--tenant NAME` works in another tenant ("작업 공간" in
  the web UI); `--user NAME` acts as another saved user.
- `sfcli whoami` shows the logged-in user, whether it is a system
  administrator, and its tenants. If a command fails because the session
  expired, ask the user to run `sfcli login`; do not try to log in yourself
  with a password.
- The server checks every request against the user's own permissions. Do not
  work around a permission error; report it.

## Operations: never send a change twice

Every change gets an operation ID before it is sent, and sfcli prints it.

- If a change command is cut off, times out, or exits with code `4`, do not
  run it again. Run `sfcli op show ID` to see whether it finished, and
  `sfcli op resume ID` to continue the same operation. The server runs one ID
  only once.
- `--id ID` sets the ID yourself. Running the same command again with the
  same `--id` shows or continues that operation instead of sending a new one.
- `sfcli op list` lists operations sent from this computer.
- Ctrl-C (or killing the process) stops only the waiting; the server keeps
  going.
- `--reason TEXT` (up to 512 characters) is recorded with the change. Say why
  you made it.

## Before changing anything

- Prefer a read first: `list`, `show`, `status`, `diff`.
- `sfcli app check -f app.yaml` reads the file without the server.
  `sfcli app diff -f app.yaml` shows what a deploy would change; deploy only
  after that matches what the user asked for.
- Deleting, `app down`, `app clear-logs`, `volume delete`, `node remove` and
  similar cannot be undone. Confirm with the user before running them, even
  when you could pass `-y`.

## Common commands

| Task | Command |
|---|---|
| Deploy or update an app | `sfcli app diff -f app.yaml`, then `sfcli app deploy -f app.yaml` |
| App state and logs | `sfcli app show APP`, `sfcli logs --app APP --container CONTAINER [--tail N]` (server-kept logs, incl. cluster apps: `sfcli logs --node NODE NAME`) |
| Run one command in a container | `sfcli app exec APP SERVICE -- COMMAND...` |
| Servers | `sfcli node list`, `sfcli node show NODE` |
| Cluster health | `sfcli cluster status`, `sfcli events` |
| Tenants and users | `sfcli tenant list`, `sfcli user list` |
| Networks | `sfcli network list`, `sfcli network show NAME` |
| Volumes | `sfcli volume list`, `sfcli volume show NAME` |
| Secrets | `sfcli secret list` (values are never printed back) |
| Images and builds | `sfcli image list`, `sfcli build --help` |
| Continuous deploy | `sfcli cd show APP` |
| A single container outside apps (debug shell, one-off job) | `sfcli standalone run NAME -f app.yaml --mode shell`, then `sfcli standalone attach NAME -i -t`; `sfcli standalone list` |
| Ingress and certificates | `sfcli ingress list`, `sfcli certificate list` |

## Secrets and private data

Never print, log or pass on secret values, private keys, tokens or passwords,
and never put them in a command line argument (other users of the computer can
see process arguments). Use the file and descriptor inputs the commands offer.
