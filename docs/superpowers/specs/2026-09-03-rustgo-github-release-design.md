# Rustgo GitHub Multi-Platform Release Design

## Purpose

Rustgo V0.3 will use GitHub Actions to build and publish reproducible client and
server archives for Windows x86_64, Linux x86_64, and Linux ARM64. A pushed
release tag is the sole publication trigger. The workflow must fail closed: it
must not create or update a GitHub Release unless every required archive and its
checksum have been produced and validated.

The release structure must remain easy to extend with the planned
`rustgoc-gui` binary in V0.4 without publishing an empty GUI artifact in V0.3.

## Version and Trigger Contract

The workflow runs for tags matching `v*`. V0.3 is released by pushing the
`v0.3` tag.

The tag and Cargo workspace version must describe the same semantic version.
The short tag `vMAJOR.MINOR` is accepted only when the Cargo patch version is
zero, so `v0.3` matches Cargo version `0.3.0`. A full
`vMAJOR.MINOR.PATCH` tag matches the Cargo version exactly. The exact tag text,
including its leading `v`, is used in archive names.

The V0.3 change updates `[workspace.package].version` to `0.3.0`. A tag/version
mismatch is a hard failure before compilation or publication.

## Build Matrix

The release contains both existing executables for all three targets:

| Platform label | Rust target | Build environment |
| --- | --- | --- |
| `win-x86` | `x86_64-pc-windows-msvc` | GitHub Windows runner |
| `linux-x86` | `x86_64-unknown-linux-gnu` | GitHub Linux runner |
| `linux-arm64` | `aarch64-unknown-linux-gnu` | GitHub Linux runner using `cross` |

Each matrix job builds `rustgoc` and `rustgos` in release mode. Windows uses
the native MSVC toolchain. Linux x86_64 uses the native GNU target. Linux ARM64
uses `cross` so native dependencies such as bundled SQLite and the TLS/crypto
stack are compiled in a controlled target environment rather than relying on an
incomplete host linker setup.

Build jobs upload intermediate artifacts only for transfer inside the workflow.
A separate publication job downloads all outputs, validates the complete set,
generates the checksum manifest, and creates the GitHub Release.

## Archive Names and Contents

For tag `v0.3`, the required archives are:

- `rustgoc-win-x86-v0.3.zip`
- `rustgos-win-x86-v0.3.zip`
- `rustgoc-linux-x86-v0.3.zip`
- `rustgos-linux-x86-v0.3.zip`
- `rustgoc-linux-arm64-v0.3.zip`
- `rustgos-linux-arm64-v0.3.zip`

Every archive has a flat top-level layout. Client archives contain the target
executable and `client.toml`; server archives contain the target executable and
`server.toml`. The TOML files come from `examples/client.toml` and
`examples/server.toml` without injecting credentials or generated keys.

Windows client layout:

```text
rustgoc.exe
client.toml
```

Windows server layout:

```text
rustgos.exe
server.toml
```

All four Linux archives additionally contain a package-specific
`docker-compose.yaml`:

```text
rustgoc | rustgos
client.toml | server.toml
docker-compose.yaml
```

The executable keeps its conventional name inside the ZIP. Only the ZIP carries
the platform and version suffix, so existing commands and the default
`./client.toml` or `./server.toml` behavior remain unchanged.

## Docker Compose Contract

Compose runs the binary shipped in the same Linux archive. The release does not
build or publish a Rustgo container image. Each package-specific Compose file
mounts its executable and configuration into a minimal multi-architecture,
glibc-compatible, non-root runtime image and invokes the executable directly.
The selected image is pinned to an immutable digest during implementation; a
floating `latest` tag is forbidden.

The runtime image has no shell or package manager. The container runs as a
non-root user with a read-only root filesystem, drops Linux capabilities, sets
`no-new-privileges`, and mounts the executable, TOML configuration, and secrets
read-only. Linux host networking is used because Rustgo exposes and consumes
fixed relay, tunnel, observation, and peer-to-peer ports that cannot be fully
represented by a static Compose port list.

Each archive expects a sibling `secrets/` directory for user-provided
certificates and keys. The distributed TOML remains a documented example and
must be edited before startup. The service package also mounts a writable
`data/` directory for the optional V0.3 SQLite telemetry database; all other
container paths remain read-only. No secrets, keys, generated identities, or
production values are included in an archive.

The client Compose file starts `rustgoc -c /config/client.toml`. The server
Compose file starts `rustgos -c /config/server.toml`. Both use
`restart: unless-stopped` and expose configuration paths through explicit bind
mounts rather than copying mutable configuration into an image.

## Packaging and Publication

A repository script owns archive assembly so naming and content validation can
be exercised locally and identically in GitHub Actions. The script takes the
tag, platform label, executable paths, and staging directory as explicit input.
It rejects unknown platform labels, unexpected tag formats, missing or empty
executables, missing configuration examples, and unexpected archive members.

Archives are assembled in clean staging directories. Linux executable mode is
preserved as executable in the ZIP metadata. Archive member paths are relative,
use forward slashes, and cannot escape the archive root.

After all six archives exist, the publication job generates one `SHA256SUMS`
file containing exactly one entry per ZIP, sorted by archive name. It then
recomputes and verifies every entry before publication. The GitHub Release is
created only after validation succeeds and receives the six ZIP files plus
`SHA256SUMS` in one publication step.

GitHub workflow permissions are minimal: build jobs need read-only repository
contents, while only the final publication job receives `contents: write`.
Intermediate workflow artifacts are not presented as product releases.

## V0.4 GUI Extension Boundary

The packaging script and workflow represent binaries as data: binary name,
configuration file, supported platform, and optional Compose template. V0.3
registers `rustgoc` and `rustgos`. V0.4 can add `rustgoc-gui` to that list and
declare its supported targets without copying the release workflow or changing
the archive validation model.

V0.3 does not create a `rustgoc-gui` crate, build step, archive, placeholder, or
Release asset. GUI-specific runtime libraries and packaging rules remain a V0.4
decision.

## Failure Handling

Any of the following stops publication:

- tag and Cargo version mismatch;
- compilation failure for either binary on any target;
- missing, empty, or non-executable target binary;
- missing or malformed required configuration or Compose file;
- archive name or member-set mismatch;
- Linux archive without executable ZIP mode;
- incomplete six-archive matrix;
- checksum generation or verification failure;
- GitHub Release upload failure.

Because the publication job depends on every build job, a partial platform
success cannot create a release. A failed rerun may leave GitHub Actions
intermediate artifacts, but it must not mark an incomplete Release as current.

## Acceptance

This is a release-pipeline change, so final acceptance uses the repository's
full functional-test workflow rather than adding isolated unit tests during
implementation. Acceptance evidence must include:

1. The full Rustgo functional suite exits successfully.
2. Release builds of `rustgoc` and `rustgos` succeed for all three targets.
3. Exactly the six specified ZIP names and one `SHA256SUMS` are produced.
4. Every ZIP contains exactly its executable, matching TOML file, and, for
   Linux, `docker-compose.yaml`.
5. Every extracted executable returns successful help/version output and its
   real `check -c` path is exercised with test-owned credentials.
6. Both Linux Compose files pass `docker compose config` and resolve only the
   expected mounts, command, security settings, and pinned runtime image.
7. SHA-256 verification succeeds against all six final ZIP files.
8. A tag/version mismatch fails before a GitHub Release is created.
