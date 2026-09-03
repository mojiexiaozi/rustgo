# Rustgo GitHub Multi-Platform Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and atomically publish six V0.3 ZIP archives for `rustgoc` and `rustgos` on Windows x86_64, Linux x86_64, and Linux ARM64 from a Git tag.

**Architecture:** A standard-library Python release tool validates the tag, stages deterministic archive contents, generates package-specific Compose files from reviewed templates, and verifies the complete release set. GitHub Actions builds a three-target matrix, transfers only intermediate artifacts between jobs, and grants release-write permission solely to the final all-or-nothing publication job.

**Tech Stack:** Rust stable, Cargo, GitHub Actions, Python 3 standard library, `cross`, ZIP, Docker Compose, GitHub CLI.

**Spec:** `docs/superpowers/specs/2026-09-03-rustgo-github-release-design.md`

## Global Constraints

- The release trigger is a pushed `v*` Git tag; `v0.3` must match Cargo workspace version `0.3.0`.
- Required targets are `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, and `aarch64-unknown-linux-gnu`.
- Required product binaries are `rustgoc` and `rustgos`; V0.3 must not emit any `rustgoc-gui` artifact.
- Archive names use `rustgoc|rustgos` + `win-x86|linux-x86|linux-arm64` + exact tag, for example `rustgoc-win-x86-v0.3.zip`.
- Each archive contains one conventionally named executable and its matching example TOML; all four Linux archives also contain `docker-compose.yaml`.
- Linux Compose runs the bundled executable inside `gcr.io/distroless/cc-debian12@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f`, whose reviewed index contains both `linux/amd64` and `linux/arm64`.
- No credentials, generated keys, production configuration, floating container tags, or Rustgo container image may be published.
- `SHA256SUMS` contains exactly six sorted ZIP entries and is verified before release creation.
- Any missing build, archive mismatch, checksum failure, or tag/version mismatch prevents GitHub Release creation.
- Follow repository `AGENTS.md`: do not add unit tests; do not run tests while implementing; run the full functional acceptance only after all implementation tasks are complete.

---

## File Map

- Create `scripts/release.py`: the single cross-platform CLI for tag validation, ZIP assembly, complete-set validation, and checksum generation.
- Create `scripts/release_acceptance.py`: black-box functional acceptance for archive names, members, ZIP modes, checksums, tag rejection, and GUI extensibility boundary.
- Create `packaging/compose/rustgoc.yaml`: reviewed client Compose template with a pinned minimal runtime image and client command/mounts.
- Create `packaging/compose/rustgos.yaml`: reviewed server Compose template with a pinned minimal runtime image, server command/mounts, and writable telemetry data mount.
- Create `.github/workflows/release.yml`: tag-triggered three-platform build matrix plus fail-closed publication job.
- Modify `Cargo.toml`: change workspace package version from `0.1.0` to `0.3.0`.
- Modify `Cargo.lock`: accept Cargo's workspace package version updates.
- Modify `README.md`: document Release assets, archive layouts, Compose prerequisites, and tag procedure.
- Modify `docs/operations.md`: add operator-grade download, checksum, extraction, configuration, Compose, and release verification commands.

---

### Task 1: Version Contract and Cross-Platform Packaging Tool

**Files:**
- Create: `scripts/release.py`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`

**Interfaces:**
- Produces CLI `python scripts/release.py verify-version --tag v0.3 --manifest Cargo.toml`.
- Produces CLI `python scripts/release.py package --tag v0.3 --platform win-x86 --binary rustgoc --executable target/x86_64-pc-windows-msvc/release/rustgoc.exe --output-dir release-input/win-x86` (the workflow supplies the other registry combinations).
- Produces CLI `python scripts/release.py finalize --tag v0.3 --input-dir release-input --output-dir release-out`.
- `verify-version` exits nonzero unless the tag and `[workspace.package].version` match under the approved short-tag rule.
- `package` prints the absolute generated ZIP path as its only stdout line.
- `finalize` copies exactly six validated ZIPs, writes `SHA256SUMS`, verifies it, and rejects any extra ZIP.

- [ ] **Step 1: Update the Cargo workspace version**

Change the workspace package declaration to:

```toml
[workspace.package]
edition = "2024"
license = "MIT OR Apache-2.0"
version = "0.3.0"
```

Run `cargo check --workspace --locked` only in the final acceptance task. For now, run `cargo metadata --no-deps --format-version 1` only to refresh `Cargo.lock` if Cargo changes workspace package records; this is metadata generation, not acceptance testing.

- [ ] **Step 2: Implement strict tag parsing and Cargo version validation**

Use only Python's standard library. Define these stable interfaces:

```python
@dataclass(frozen=True)
class ReleaseVersion:
    tag: str
    cargo: str

def parse_tag(tag: str) -> tuple[int, int, int | None]: ...
def read_workspace_version(manifest: Path) -> tuple[int, int, int]: ...
def verify_version(tag: str, manifest: Path) -> ReleaseVersion: ...
```

Accept only `vN.N` and `vN.N.N`, with decimal nonnegative components and no
suffix. `vN.N` matches only `N.N.0`; full tags match all three components.
Use `tomllib` to read `Cargo.toml`. Error messages must name both conflicting
values without printing environment variables.

- [ ] **Step 3: Encode the V0.3 product and platform registry as data**

Define immutable registries rather than branching workflow logic:

```python
PRODUCTS = {
    "rustgoc": {"config": "examples/client.toml", "compose": "packaging/compose/rustgoc.yaml"},
    "rustgos": {"config": "examples/server.toml", "compose": "packaging/compose/rustgos.yaml"},
}
PLATFORMS = {
    "win-x86": {"windows": True, "compose": False},
    "linux-x86": {"windows": False, "compose": True},
    "linux-arm64": {"windows": False, "compose": True},
}
```

The future GUI extension is one new `PRODUCTS` entry; do not add it now.

- [ ] **Step 4: Implement safe, deterministic ZIP assembly**

Define:

```python
def archive_name(binary: str, platform: str, tag: str) -> str: ...
def package_release(root: Path, tag: str, platform: str, binary: str,
                    executable: Path, output_dir: Path) -> Path: ...
```

Require a regular, nonempty executable. Reject symlinks and paths outside the
explicit inputs. Write a flat archive with `ZIP_DEFLATED`, normalized member
timestamps `(1980, 1, 1, 0, 0, 0)`, and sorted members. Set Unix executable
mode `0o755` for Linux executable entries and `0o644` for configs/Compose;
Windows entries use regular-file mode. Read example configs and Compose
templates as bytes without variable substitution. Write to a temporary file in
`output_dir`, validate it, then replace the final ZIP atomically.

- [ ] **Step 5: Implement archive and complete-set validation**

Define:

```python
def expected_archives(tag: str) -> tuple[str, ...]: ...
def validate_archive(path: Path, binary: str, platform: str) -> None: ...
def finalize_release(tag: str, input_dir: Path, output_dir: Path) -> Path: ...
```

Expected Windows members are executable plus TOML. Expected Linux members are
executable, TOML, and `docker-compose.yaml`. Reject absolute paths, `..`, nested
members, duplicates, missing entries, extras, empty entries, and incorrect
Linux executable mode. `finalize_release` requires exactly the six names,
copies them to a clean staging directory, hashes bytes with SHA-256, writes
sorted GNU checksum lines consisting of 64 lowercase hexadecimal characters,
two spaces, and the ZIP filename; it rereads and verifies
all lines, then atomically promotes the seven-file output set.

- [ ] **Step 6: Add argparse commands and fail-closed process behavior**

Each subcommand must return exit code 0 only after its postconditions hold.
Errors go to stderr as one concise line; tracebacks are suppressed for expected
input failures. Resolve repository-relative config/template paths from the
script's repository root, not the caller's current directory.

- [ ] **Step 7: Review without executing tests**

Inspect the diff for secret material, unsafe archive paths, platform-name drift,
and accidental `rustgoc-gui` output. Run only `git diff --check`; defer script
execution and Cargo tests to Task 5.

- [ ] **Step 8: Commit the packaging boundary**

```text
git add Cargo.toml Cargo.lock scripts/release.py
git commit -m "build: add strict release packaging tool"
```

---

### Task 2: Minimal Compose Templates for Every Linux Archive

**Files:**
- Create: `packaging/compose/rustgoc.yaml`
- Create: `packaging/compose/rustgos.yaml`

**Interfaces:**
- Consumes package member names `rustgoc`, `rustgos`, `client.toml`, and `server.toml` from Task 1.
- Produces a client service named `rustgoc` and server service named `rustgos`.
- Both templates are copied byte-for-byte to the corresponding Linux ZIP as `docker-compose.yaml`.

- [ ] **Step 1: Resolve and record the immutable distroless manifest digest**

On a networked machine with Docker Buildx, run:

```text
docker buildx imagetools inspect gcr.io/distroless/cc-debian12:nonroot
```

Confirm the response still reports top-level digest
`sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f`
and contains both `linux/amd64` and `linux/arm64`. Both templates use
`gcr.io/distroless/cc-debian12@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f`.
Do not use a per-architecture child digest or a floating tag. If the tag has
moved, stop and review the new index rather than silently changing the pinned
runtime.

- [ ] **Step 2: Create the client Compose template**

Use this exact security and mount shape:

```yaml
services:
  rustgoc:
    image: gcr.io/distroless/cc-debian12@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
    network_mode: host
    restart: unless-stopped
    read_only: true
    user: "65532:65532"
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    working_dir: /work
    command: [/app/rustgoc, -c, /config/client.toml]
    volumes:
      - ./rustgoc:/app/rustgoc:ro
      - ./client.toml:/config/client.toml:ro
      - ./secrets:/run/secrets:ro
```

The operator edits `client.toml` so certificate/key paths resolve beneath
`/run/secrets`. Do not add privileged mode, device mounts, or published ports.

- [ ] **Step 3: Create the server Compose template**

Use the same security fields and host networking, with:

```yaml
    working_dir: /data
    command: [/app/rustgos, -c, /config/server.toml]
    volumes:
      - ./rustgos:/app/rustgos:ro
      - ./server.toml:/config/server.toml:ro
      - ./secrets:/run/secrets:ro
      - ./data:/data
```

The operator edits certificate/key paths to `/run/secrets/...` and may keep the
dashboard database at `/data/rustgo-metrics.db`. Do not grant extra capabilities.

- [ ] **Step 4: Review without running Compose**

Check that both files use the same immutable manifest digest, no shell command,
no credentials, no build context, no Rustgo image, and no mutable tag. Run only
`git diff --check`; defer `docker compose config` to Task 5.

- [ ] **Step 5: Commit the Compose templates**

```text
git add packaging/compose/rustgoc.yaml packaging/compose/rustgos.yaml
git commit -m "build: add minimal Linux Compose templates"
```

---

### Task 3: Fail-Closed GitHub Release Workflow

**Files:**
- Create: `.github/workflows/release.yml`

**Interfaces:**
- Consumes all three `scripts/release.py` commands from Task 1.
- Produces six intermediate ZIP artifacts from matrix builds.
- Produces one GitHub Release containing exactly those ZIPs and `SHA256SUMS`.

- [ ] **Step 1: Define tag trigger, concurrency, and default permissions**

Start with:

```yaml
name: Release
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
concurrency:
  group: release-${{ github.ref }}
  cancel-in-progress: false
```

Do not add `workflow_dispatch`; releases remain tag-authoritative.

- [ ] **Step 2: Add a version-gate job**

Checkout the tag, install Python 3, and run:

```text
python scripts/release.py verify-version --tag "${{ github.ref_name }}" --manifest Cargo.toml
```

Every build job must declare `needs: version` so mismatch fails before compile.

- [ ] **Step 3: Add the three-entry build matrix**

Use explicit entries with `runner`, `target`, `platform`, `build_command`, and
`exe_suffix` rather than computed shell conditionals:

```yaml
include:
  - runner: windows-latest
    target: x86_64-pc-windows-msvc
    platform: win-x86
    build_command: cargo build --locked --release --target x86_64-pc-windows-msvc -p rustgoc -p rustgos
    exe_suffix: .exe
  - runner: ubuntu-latest
    target: x86_64-unknown-linux-gnu
    platform: linux-x86
    build_command: cargo build --locked --release --target x86_64-unknown-linux-gnu -p rustgoc -p rustgos
    exe_suffix: ""
  - runner: ubuntu-latest
    target: aarch64-unknown-linux-gnu
    platform: linux-arm64
    build_command: cross build --locked --release --target aarch64-unknown-linux-gnu -p rustgoc -p rustgos
    exe_suffix: ""
```

Set `fail-fast: false` so all platform failures remain visible while publication
still requires the entire matrix.

- [ ] **Step 4: Pin third-party Actions and cross**

Use commit SHA pins for `actions/checkout`, `actions/setup-python`,
`actions/upload-artifact`, and `actions/download-artifact`; add a trailing
comment identifying the reviewed major release. Install an exact locked `cross`
version with `cargo install cross --version 0.2.5 --locked` only in the ARM64
entry. Do not use an unconstrained install.

- [ ] **Step 5: Build and package both binaries on every matrix entry**

Install stable Rust with the explicit target, execute the matrix build command,
then invoke `scripts/release.py package` twice with the target output paths.
Upload both ZIPs in one intermediate artifact named
`release-${{ matrix.platform }}`. Use
`if-no-files-found: error`, a bounded retention period, and no hidden files.

- [ ] **Step 6: Add the all-or-nothing publication job**

Declare `needs: build`, `runs-on: ubuntu-latest`, and job-local:

```yaml
permissions:
  contents: write
```

Download all intermediate artifacts into one input directory. Run `finalize`
into a separate output directory. Assert the directory contains seven regular
files, create a draft, download its assets into a clean audit directory, verify
the count and checksums, then publish it with:

```text
gh release create "${{ github.ref_name }}" release-out/* --verify-tag --generate-notes --title "Rustgo ${{ github.ref_name }}" --draft
mkdir release-audit
gh release download "${{ github.ref_name }}" --dir release-audit
test "$(find release-audit -maxdepth 1 -type f | wc -l)" -eq 7
(cd release-audit && sha256sum --check SHA256SUMS)
gh release edit "${{ github.ref_name }}" --draft=false
```

Set `GH_TOKEN: ${{ github.token }}` only on this step. A failed upload or audit
can leave a diagnostic draft but cannot create a partial public Release.

- [ ] **Step 7: Review without executing the workflow**

Confirm that only the publication job has `contents: write`, every action uses a
commit SHA, every build uses `--locked`, the version job precedes builds, and
publication needs the full matrix. Run only `git diff --check`; defer YAML and
packaging execution to Task 5.

- [ ] **Step 8: Commit the workflow**

```text
git add .github/workflows/release.yml
git commit -m "ci: publish multi-platform Rustgo releases"
```

---

### Task 4: Operator Documentation and Functional Acceptance Harness

**Files:**
- Create: `scripts/release_acceptance.py`
- Modify: `README.md`
- Modify: `docs/operations.md`

**Interfaces:**
- Consumes `scripts/release.py`, Compose templates, and locally supplied target binaries.
- Produces a black-box acceptance command that creates packages in a test-owned temporary directory and leaves the repository untouched.

- [ ] **Step 1: Implement the release functional acceptance harness**

The CLI accepts repeated explicit binary mappings so it can validate native and
cross-compiled outputs without guessing:

```text
python scripts/release_acceptance.py \
  --tag v0.3 \
  --win-x86-dir artifacts/win-x86 \
  --linux-x86-dir artifacts/linux-x86 \
  --linux-arm64-dir artifacts/linux-arm64
```

It creates one `tempfile.TemporaryDirectory`, invokes the real release CLI in
subprocesses, and asserts observable behavior only:

- `v0.3` accepts Cargo `0.3.0`, while `v0.3.1` and malformed tags fail;
- six exact archives and `SHA256SUMS` are produced;
- Windows ZIPs have two exact members and Linux ZIPs have three;
- Linux executables have ZIP mode `0o755`;
- configs equal the repository example bytes;
- Compose members equal the package-specific template bytes;
- every checksum matches recomputed bytes and sorted names;
- an extra ZIP, missing ZIP, empty executable, symlink executable, and unexpected
  product name each fail closed;
- the six published names contain no `rustgoc-gui` asset.

The harness must delete only its own temporary directory and return nonzero on
the first failed contract with a concise assertion message.

- [ ] **Step 2: Document user-facing downloads in README**

Add a `Releases` section listing the six V0.3 naming patterns, ZIP contents,
checksum command examples for PowerShell and Linux, and the rule that
`docker-compose.yaml` is present only in Linux packages. State that configs are
examples and require user-supplied certificates/keys.

- [ ] **Step 3: Document Compose deployment and maintainer release procedure**

In `docs/operations.md`, document:

- extraction and `chmod 755 rustgoc|rustgos`;
- creation of `secrets/` and, for server, `data/`;
- editing container paths in TOML to `/run/secrets/...` and database path to
  `/data/rustgo-metrics.db`;
- `docker compose config`, `docker compose up -d`, logs, stop, and upgrade;
- host-network implications and fixed firewall ports;
- maintainer sequence: set Cargo version, commit, run Task 5 acceptance, create
  annotated `v0.3`, push tag, verify all seven Release assets and checksums;
- failure rule: never manually upload a missing platform into a partial release;
  fix the workflow/source and rerun before publication.

- [ ] **Step 4: Review without running tests**

Cross-check commands against actual CLI names and Compose mounts. Run only
`git diff --check`; defer all harness execution to Task 5.

- [ ] **Step 5: Commit docs and acceptance harness**

```text
git add scripts/release_acceptance.py README.md docs/operations.md
git commit -m "docs: add release and Compose operations"
```

---

### Task 5: Final Full Functional Acceptance

**Files:**
- Verify only; modify earlier task files only when acceptance exposes a defect.

**Interfaces:**
- Consumes all deliverables from Tasks 1-4.
- Produces auditable local results plus the pushed GitHub Actions run after user-authorized publication.

- [ ] **Step 1: Run static repository gates**

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
git diff --check
```

Require exit code 0 for every command.

- [ ] **Step 2: Run the full Rust functional suite**

```text
cargo test --workspace
```

Require the complete command to exit 0; focused crate tests are insufficient.

- [ ] **Step 3: Run the platform release E2E on Windows**

```text
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/e2e.ps1
```

Require release build, real config checks, default/explicit startup, TCP, UDP,
and P2P gates to finish with exit code 0.

- [ ] **Step 4: Run Linux E2E and namespace gates in GitHub CI**

Push the implementation commits without creating the release tag. Require the
ordinary `CI` workflow to pass Linux `scripts/e2e.sh`, workspace tests, pidfd
integration, and two consecutive complex NAT namespace runs. This provides the
Linux-native functional evidence unavailable on the Windows checkout.

- [ ] **Step 5: Build all release targets without publishing**

Run or manually dispatch the same matrix commands in a non-release validation
context: native Windows, native Linux x86_64, and `cross` Linux ARM64. Preserve
the six produced binaries as inputs to `scripts/release_acceptance.py`.

- [ ] **Step 6: Run release archive acceptance**

Invoke `scripts/release_acceptance.py` with all three output directories. Require
all negative fail-closed checks and the complete positive six-archive path to
exit 0.

- [ ] **Step 7: Validate Compose semantically**

Extract one client and one server archive for each Linux architecture. Run:

```text
docker compose -f release-stage/linux-x86-rustgoc/docker-compose.yaml config --quiet
docker compose -f release-stage/linux-x86-rustgos/docker-compose.yaml config --quiet
```

Inspect resolved output and require the pinned image digest, host networking,
non-root user, read-only root, dropped capabilities, no-new-privileges, correct
binary/config/secrets mounts, and server-only writable data mount. On an ARM64
or emulated host, run the ARM64 image/binary `--help`; on x86_64 run both Linux
x86_64 binaries `--help` and real `check -c` with test-owned credentials.

- [ ] **Step 8: Review the final diff and commit acceptance fixes**

Inspect `git status`, `git diff`, and the commits since the design. Preserve
unrelated files. If acceptance required fixes, rerun every affected gate plus
the complete functional suite, then commit:

Stage only the release files shown by `git status`, inspect the staged diff,
then commit them with `git commit -m "fix: satisfy release acceptance gates"`.

- [ ] **Step 9: Stop before tag publication unless explicitly authorized**

Report exact local/CI results, the final commit, six archive names, and any
platform limitation. Do not create or push `v0.3`, create a GitHub Release, or
overwrite an existing tag without an explicit user instruction after acceptance.
