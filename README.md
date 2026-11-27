<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/cluster/seafield-cluster-logo-on-dark-512.png">
    <img src="docs/brand/cluster/seafield-cluster-logo-512.png" width="260" alt="Seafield Cluster">
  </picture>
</p>

# Seafield Cluster

[![CI](https://github.com/jay94ks/seafield/actions/workflows/ci.yml/badge.svg)](https://github.com/jay94ks/seafield/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jay94ks/seafield?include_prereleases&sort=semver)](https://github.com/jay94ks/seafield/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/jay94ks/seafield.svg)](https://pkg.go.dev/github.com/jay94ks/seafield)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Seafield Cluster** deploys and runs Docker container apps across a small group of your own servers.
You describe an app once in a Compose-style `app.yaml`, and Seafield Cluster places its services on servers, wires up networks,
volumes and secrets, and keeps them running.

[한국어 README](README.ko.md)

> **Status: early preview (MVP).** Interfaces, file formats and wire protocols may change between releases
> without a migration path until 1.0.

## Features

- **One file per app.** A Compose-style `app.yaml` names services, placement, networks, volumes, secrets and the
  deployment policy.
- **Multi-tenant.** Workspaces (tenants) with users, roles and per-tenant budgets. Every request is authenticated
  and authorized by the cluster.
- **Raft-backed control plane.** Each server runs one `sfcd`; cluster state is agreed with Raft, and servers talk
  over SFCP, an authenticated QUIC protocol.
- **Batteries included.** Built-in image registry and builds, HTTP ingress with certificates, overlay
  networks between servers, Git-driven continuous deployment, and lifecycle checks written in Go.
- **CLI and web UI.** `sfcli` for scripts and terminals, `sfc-web` for a browser dashboard.

## Components

| Binary | Role |
|---|---|
| `sfcd` | Server agent. One per server: cluster membership, state, Docker and host resources |
| `sfcli` | Command-line client. Talks to a local or remote `sfcd` |
| `sfc-web` | Web UI daemon. Runs as a managed app on a server and calls `sfcd` with each user's own session |

## Quick start

Requirements: Linux (amd64 or arm64), Docker Engine 28.0 or newer on servers that run apps, and UDP port 7443
open between servers.

```sh
# Download sfcli and sfcd from the latest release, then:
sfcli identity create /etc/sfc/admin-identity
sfcd --config /etc/sfc/node.yaml check
```

The full walk-through, from a single-server cluster to adding and removing servers, is in
[docs/quick.md](docs/quick.md). A complete example app (PHP + MySQL) is in [docs/examples](docs/examples/README.md).

## Documentation

| Topic | Where |
|---|---|
| Getting started | [docs/quick.md](docs/quick.md) |
| CLI reference | [docs/cli](docs/cli/README.md) |
| `app.yaml` and cluster settings | [docs/architecture/app-and-cluster-spec.md](docs/architecture/app-and-cluster-spec.md) |
| Configuration | [docs/configuration/cli.md](docs/configuration/cli.md) |
| API and protocol | [docs/reference](docs/reference/README.md), [SFCP](docs/protocol/sfcp.md) |
| Architecture | [docs/architecture](docs/architecture/README.md) |

Documentation is written in Korean for now.

## Building from source

```sh
git clone https://github.com/jay94ks/seafield.git
cd sfcd
make            # builds bin/sfcd, bin/sfcli, bin/sfc-web (with the web UI)
make test       # unit tests
```

Go 1.27 and Node.js 22 are required. See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow.

## Contributing

Bug reports, ideas and pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and our
[Code of Conduct](CODE_OF_CONDUCT.md) first. To report a security issue, follow [SECURITY.md](SECURITY.md) and
do not open a public issue.

## License

Seafield Cluster is licensed under the [Apache License 2.0](LICENSE). Modified third-party code under `3rd-party/` keeps its
own license, and the Seafield container engine under `seafield/` is a patch set on Apache-2.0 [moby/moby](https://github.com/moby/moby); see [NOTICE](NOTICE). Each release ships `THIRD_PARTY_NOTICES` and an SPDX SBOM.
