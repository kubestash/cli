# Agents Guide

This repository is the `gomodules.xyz/restic` Go package. It is a wrapper around
the external `restic` CLI. It does not implement backup storage or snapshot logic
itself; it builds the right restic command lines, injects provider-specific
environment variables, runs commands through `gomodules.xyz/go-sh`, and converts
restic output into Go structs used by Kubernetes controllers.

## Package Shape

- `config.go` defines `ResticWrapper`, setup options, public operation options,
  wrapper construction, shell configuration, environment helpers, and deep copy
  logic for concurrent work.
- `backend.go` defines backend storage configuration and backend-specific CLI
  flags such as `--cacert`, `--insecure-tls`, and provider connection options.
- `setup.go` prepares backend environment variables from storage and encryption
  secrets. It supports local, S3, Azure, and GCS repository URLs.
- `commands.go` contains low-level restic command builders and the central
  `run` method.
- `backup.go`, `restore.go`, `snapshot.go`, `key.go`, and `unlock.go` expose
  higher-level workflows for callers.
- `output.go` parses restic JSON/text output into package status structs.
- `types.go` contains backup and restore status types returned to callers.
- `constants.go` centralizes environment variable names used by restic and
  storage providers.
- `restic_test.go` exercises local repositories, stdin backup/dump, scheduling
  options, timeout handling, multiple backends, and deep copy behavior.

The `vendor/` directory is checked in. Prefer `GOFLAGS=-mod=vendor` behavior and
avoid changing vendored files unless the task is explicitly about vendoring.

## Runtime Model

`NewResticWrapper` or `NewResticWrapperFromShell` creates a wrapper with:

- a `go-sh` shell session,
- `ScratchDir` as the working directory,
- command echoing enabled,
- pipe failure handling enabled,
- `RESTIC_PROGRESS_FPS=0.1`,
- optional restic cache directory under `<ScratchDir>/restic-cache`,
- backend environment maps populated for every configured backend,
- an in-memory backend index by `Backend.Repository`.

Every restic operation looks up a backend by logical repository name, appends
that backend's environment map to the command arguments, then calls `run`.

The logical `Backend.Repository` is the package-level identifier passed to
methods like `RunRestore(repository, ...)`, `ListSnapshots(repository, ...)`, and
`InitializeRepository(repository)`. The actual restic repository URL is stored
in `Backend.Envs[RESTIC_REPOSITORY]`.

## Backend Setup

Each backend needs a populated `StorageConfig` before setup:

- local: `RESTIC_REPOSITORY=<bucket>/<directory>`
- S3: `RESTIC_REPOSITORY=s3:<endpoint>/<bucket>/<prefix>/<directory>`
- Azure: `RESTIC_REPOSITORY=azure:<bucket>:/<prefix>/<directory>`
- GCS: `RESTIC_REPOSITORY=gs:<bucket>:/<prefix>/<directory>`

`EncryptionSecret` must provide `RESTIC_PASSWORD`. Provider credentials are read
from `StorageSecret` when needed. CA data is read from `CA_CERT_DATA`, written to
a temporary file under the backend temp directory, and used with `--cacert`.

There is a `ConfigResolver StorageConfigResolver` field on `Backend`, and
`setupEnvsForBackend` invokes it when present before validating
`Backend.StorageConfig`.

## Command Execution

`run(commands ...Command)` is the single execution path:

1. It wires stderr to both `os.Stderr` and an internal buffer.
2. It applies `SetupOptions.Timeout` to the shell session.
3. It wraps restic commands in `nice` and/or `ionice` when configured.
4. It builds either normal commands or leaf commands when multiple restic
   commands are in one pipeline.
5. It executes through `go-sh` and returns stdout bytes.
6. On failure, it formats the captured stderr into a shorter Go error.

Pipelines are represented as `[]Command`. For stdin backup, caller-provided
commands run before `restic backup --stdin`. For dump, `restic dump` runs before
caller-provided stdout pipe commands.

## Backup Flow

`RunBackup` runs one backup request and returns `[]BackupOutput`.

For path backups:

1. It initializes one host stats object per configured backend.
2. For every path in `BackupOptions.BackupPaths`, it calls low-level `backup`.
3. Low-level backup builds one `restic backup <path> --quiet --json` command per
   backend.
4. It adds host, exclude patterns, caller-supplied args, cache flags, CA/TLS
   flags, max connection options, and backend envs.
5. `extractBackupInfo` parses restic JSON summary records into `SnapshotStats`.
6. Stats are upserted into the corresponding backend output.

For stdin backups:

1. `BackupOptions.StdinPipeCommands` are used as the producer pipeline.
2. The wrapper appends `restic backup --stdin --json`.
3. `--stdin-filename` is added when `StdinFileName` is set.
4. Parsed snapshot stats use the stdin file name as the backed-up path label.

`RunParallelBackup` runs multiple `BackupOptions` concurrently with a caller
provided concurrency limit. It uses `ResticWrapper.Copy()` per goroutine because
the shell session is mutable and must not be shared concurrently.

## Restore And Dump Flow

`RunRestore(repository, options)` restores from one repository.

- If `RestoreOptions.Snapshots` is non-empty, each snapshot is restored directly.
  Source host and restore paths are ignored in this mode.
- Otherwise, each path in `RestoreOptions.RestorePaths` is restored from
  `SourceHost`.
- Empty destination defaults to `/`.
- Includes, excludes, extra args, cache flags, CA/TLS flags, max connection
  options, and backend envs are appended to the restic command.

`Dump(repository, options)` reads a single file from a snapshot using
`restic dump`. Empty snapshot defaults to `latest`, and empty file name defaults
to `stdin`. `ParallelDump` performs the same operation for multiple hosts using
wrapper copies.

`DownloadSnapshot` is a thin alias around the restore flow and returns only an
error.

## Repository, Snapshot, Key, And Lock Operations

- `InitializeRepository` runs `restic init`.
- `RepositoryAlreadyExist` runs `restic snapshots --json --no-lock` and treats a
  successful command as existence.
- `VerifyRepositoryIntegrity` runs `restic check --no-lock`, then
  `restic stats --quiet --json --mode raw-data --no-lock`.
- `ListSnapshots` runs `restic snapshots --json --quiet --no-lock`.
- `DeleteSnapshots` runs `restic forget --quiet --prune` and retries after
  `unlock --remove-all` if restic reports an unlock-related failure.
- `GetSnapshotSize` runs `stats` for one snapshot and returns raw byte size.
- Key methods wrap `restic key add/list/passwd/remove`.
- `EnsureNoExclusiveLock` removes stale locks, inspects remaining locks, and
  waits up to one hour for active exclusive locks to disappear.

## Output Parsing

Backup parsing expects newline-delimited JSON objects from `restic backup
--json`. Only records with `message_type == "summary"` become `SnapshotStats`.

Repository integrity parsing looks for the exact text `no errors were found` in
`restic check` output.

Stats parsing unmarshals `total_size` from `restic stats --json`. Sizes are
formatted as binary units by `formatBytes`.

Status parsing is defensive: it trims junk before the first `{` and after the
last `}`, then decodes JSON objects one by one.

## Concurrency And Mutation Rules

- Do not share one `ResticWrapper` shell session across goroutines.
- Use `ResticWrapper.Copy()` for concurrent command execution.
- `SetupOptions.Timeout` is mutable during sequential path backups:
  `updateElapsedTimeout` subtracts elapsed time after each path.
- `SetupOptions` embeds a mutex to guard timeout mutation.
- Backend env maps must be deep-copied when copying wrappers. There is a test for
  this behavior.

## Testing And Verification

The package tests require the `restic` binary to be installed because the tests
exercise the real CLI against temporary local repositories.

Useful commands:

```bash
go test ./...
make test
make fmt
make verify
```

`make test`, `make fmt`, and `make build` run inside the configured Docker build
image. Plain `go test ./...` is faster for local iteration when the host has the
right Go version and `restic` installed.

## Change Guidance For Agents

- Keep the package as a thin restic CLI wrapper. Do not reimplement restic
  behavior in Go.
- Prefer adding command-building behavior near the low-level command in
  `commands.go`, then expose it through the relevant workflow file.
- When adding backend behavior, update setup env construction, backend flag
  helpers, and tests together.
- When adding output fields, update the parser structs in `output.go` and the
  public stats structs in `types.go` only if callers need the data.
- Be careful with secrets: credentials should stay in backend env maps or temp
  files and should not be logged or written to world-readable files.
- Avoid changing `vendor/` unless dependency updates are part of the task.
- Before editing, check `git status --short`; this repository may have unrelated
  local changes.
