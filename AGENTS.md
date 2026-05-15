# AGENTS.md

This file provides guidance to coding agents (e.g. Claude Code, claude.ai/code) when working with code in this repository.

## Repository purpose

Go module `kubestash.dev/cli` — the [KubeStash](https://kubestash.com/) command-line, distributed as a **`kubectl` plugin** (binary name `kubectl-kubestash`). Operators reach for this for the bits of KubeStash that don't fit cleanly as CRDs: ad-hoc restore, trigger-on-demand, snapshot download/view, repository unlock, debug introspection, cloning, encryption-key management, and v1→v2 manifest conversion.

Sub-commands (registered in `pkg/root.go`):

- `copy` — copy a snapshot/secret/volumesnapshot.
- `trigger-backup` — manually trigger a `BackupConfiguration`.
- `pause` / `resume` — pause/resume a `BackupConfiguration` or `BackupBatch`.
- `download` — download snapshot data to a local path.
- `manifest view` / `manifest restore` — inspect or apply manifest-only snapshots.
- `unlock-repository` — clear stale restic locks.
- `debug` — `debug backup`, `debug restore`, `debug operator`, `debug backupstorage`.
- `clone` — `clone pvc` (and other resource clones).
- `key` — `key add`, `key list`, `key remove`, `key update` (manage encryption keys on a `BackupStorage`).
- `convert` — convert legacy Stash manifests to KubeStash.

Plus `version` and `completion`.

## Architecture

- `cmd/kubectl-kubestash/main.go` — entry point; calls `pkg.NewCmd()`.
- `pkg/` — one file per top-level subcommand, plus `*_<subverb>.go` for nested verbs (e.g. `add_key.go`, `clone_pvc.go`, `debug_backup.go`, `copy_secret.go`, `copy_volumesnapshot.go`). `root.go` registers them; `util.go`, `constants.go`, `completion.go` are shared.
- `pkg/common/` — shared types and helpers used across subcommands:
  - `types.go`, `helpers.go`.
  - `dump/` — manifest-only "view" / "restore" payload generation.
- `hack/`, `Makefile` — AppsCode build harness (everything runs inside `ghcr.io/appscode/golang-dev`). This binary builds for **5 platforms**: linux amd64/arm/arm64 plus `windows/amd64`, `darwin/amd64`, `darwin/arm64` (kubectl plugins need to run on operator workstations).
- `vendor/` — checked-in deps.

The binary uses the conventional `kubectl-kubestash` name so it auto-attaches under `kubectl kubestash` once on `$PATH`. There is no Docker image — this is a host CLI.

Note: `GO_PKG := stash.appscode.dev` in the Makefile is a **historical** leftover from the Stash → KubeStash split; the Go module is `kubestash.dev/cli`. Leave the Makefile alone unless you're doing a coordinated cleanup.

## Common commands

All Make targets run inside `ghcr.io/appscode/golang-dev` — Docker must be running.

- `make ci` — CI pipeline (verify-license, lint, build).
- `make build` — build the host binary into `bin/<os>_<arch>/kubectl-kubestash`.
- `make all-build` — build for every `BIN_PLATFORMS` (linux amd64/arm/arm64 + windows/amd64 + darwin/amd64 + darwin/arm64).
- `make fmt`, `make lint`, `make unit-tests` / `make test` — standard.
- `make verify` — `verify-gen verify-modules`; `go mod tidy && go mod vendor` must leave the tree clean.
- `make add-license` / `make check-license` — manage license headers.

There is **no container target**; this CLI does not ship as an image.

Run a single Go test (requires a local Go toolchain):

```
go test ./pkg/... -run TestName -v
```

To use the CLI locally after building:

```
PATH=$PWD/bin/<os>_<arch>:$PATH kubectl kubestash --help
```

## Conventions

- Module path is `kubestash.dev/cli` (vanity URL). The Makefile's `GO_PKG := stash.appscode.dev` is **historical** — do not "fix" it without a coordinated build-tooling change.
- License: `LICENSE.md` (AppsCode). New files need the standard "Copyright AppsCode Inc. and Contributors" header (`make add-license`).
- Sign off commits (`git commit -s`); contributions follow the DCO (`DCO` file).
- Vendor directory is checked in — `go mod tidy && go mod vendor` must leave the tree clean (enforced by `verify-modules`).
- Binary name is `kubectl-kubestash` so kubectl picks it up as a plugin; do not rename without also moving the `cmd/` directory.
- New subcommand: add a `pkg/<name>.go` (or `pkg/<name>_<sub>.go` for nested verbs), register it in `pkg/root.go`'s `NewCmd()`, and reuse `pkg/common/` helpers rather than re-implementing kube client setup or output formatting.
- Builds linux/windows/darwin host binaries; do not pull in linux-only or cgo deps.
- API types come from `kubestash.dev/apimachinery`; do not redefine them here.
