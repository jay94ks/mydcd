# Security Policy

## Supported versions

Seafield Cluster is in early preview. Only the latest release receives security fixes.

| Version | Supported |
|---|---|
| latest `0.x` release | ✅ |
| older releases | ❌ |

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub:
[Report a vulnerability](https://github.com/jay94ks/seafield/security/advisories/new)
(Security tab → "Report a vulnerability").

Please include:

- the affected version or commit,
- what an attacker can do and what access they need (for example: a tenant user, a node key, network access to
  UDP 7443),
- steps or a proof of concept to reproduce it.

## What to expect

- We acknowledge a report within 7 days.
- We confirm or reject the issue and share a fix plan within 30 days.
- We publish a GitHub Security Advisory with the fixed release, and credit the reporter unless they prefer
  otherwise.

## Scope

In scope: `sfcd`, `sfcli`, `sfc-web`, the SFCP protocol, the lifecycle sandbox, and the container images
released from this repository.

Out of scope: vulnerabilities in third-party dependencies that are not reachable through Seafield Cluster (report those
upstream), and issues that need an attacker who already holds a cluster administrator key.
