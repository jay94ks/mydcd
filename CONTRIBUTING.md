# Contributing to MyDC

Thanks for your interest in MyDC. This guide explains how to report problems, propose changes and send pull
requests. 한국어로 써도 괜찮습니다 — issues and pull requests may be written in English or Korean.

## Before you start

- Search [existing issues](https://github.com/jay94ks/mydcd/issues) first.
- For anything larger than a small fix (a new feature, a new file format field, a protocol change), open a
  feature request and agree on the direction before writing code. MyDC is in its MVP stage and keeps its scope
  small on purpose.
- Security problems go through [SECURITY.md](SECURITY.md), never a public issue.

## Development setup

Requirements: Linux, Go 1.27, Node.js 22, and Docker Engine 28.0+ for tests that touch Docker.

```sh
git clone https://github.com/jay94ks/mydcd.git
cd mydcd
make            # build all binaries into bin/
make test       # go test ./... with the race-free defaults used in CI
make lint       # gofmt, go vet, SPDX header and link checks
```

The web UI lives in `apps/mydc-web/web` (React + TypeScript + Vite):

```sh
cd apps/mydc-web/web
npm ci
npm run dev     # local dev server
npm test
```

## Repository layout

| Path | Contents |
|---|---|
| `cmd/` | Entry points of `mydcd`, `mydc`, `mydc-web` |
| `internal/` | Product code |
| `lifecycle/v1` | Go SDK for lifecycle check scripts |
| `apps/` | Container images: the web UI daemon, the lifecycle compiler, sample apps |
| `docs/` | User documentation, references, protocol and architecture |
| `3rd-party/` | Pinned and minimally patched third-party sources (see `3rd-party/README.md`) |
| `tests/` | Test fixtures shared by package tests |

## Design rules

These keep MyDC predictable. Pull requests that break them will be asked to change.

- **Authorization belongs to `mydcd`.** The CLI and the web UI never make permission decisions themselves.
- **State transitions are deterministic.** Reducers and validators do not read clocks, randomness, the network or
  the OS. External effects (Docker and so on) are kept apart from committing state.
- **Raft only for what every server must agree on.** Liveness renewals, progress, metrics and logs travel over
  MYDCP and stay in memory.
- **Operations are settled by ID.** When a result is unknown after a timeout, the client asks about or resumes the
  same operation ID. It never retries under a new ID.
- **Fix causes, not symptoms.** Do not raise timeouts or limits, or ignore errors, to make a failure go away.
- **No new components without agreement.** Propose them in an issue first.

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Keep each pull request to one topic. Mechanical changes (renames, formatting) go in their own pull request.
3. Add or update tests for behavior you change. Never skip or disable a test to make CI pass.
4. Run `make lint test` locally.
5. Every new source file starts with an SPDX line, after any shebang:

   ```go
   // SPDX-License-Identifier: Apache-2.0
   ```

   `python3 -I tools/check-spdx.py --fix` adds it where it is missing. Files under `3rd-party/` keep their
   upstream headers.
6. Sign off every commit (Developer Certificate of Origin, see below): `git commit -s`.
7. Fill in the pull request template. CI must be green before review.

How changes land: MyDC is developed in a separate upstream repository and published here. A maintainer applies an
accepted pull request upstream, and it appears here in the next sync with credit to you in the commit trailer and
the release notes. Your pull request is then closed with a link to that sync.

## Developer Certificate of Origin

By signing off a commit you certify the [Developer Certificate of Origin 1.1](https://developercertificate.org/):
that you wrote the change or otherwise have the right to submit it under the project's license. Add the line
below to each commit message (`git commit -s` does it for you), using your real name or a name you are known by:

```
Signed-off-by: Your Name <you@example.com>
```

## Commit messages

- Start with the area, then a short imperative summary: `ingress: keep the old route until the new one is ready`.
- Explain *why* in the body when the change is not obvious.

## License

By contributing you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
