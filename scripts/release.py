#!/usr/bin/env python3
"""Build and validate Rustgo release archives without publishing them."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import stat
import sys
import tempfile
import tomllib
import zipfile
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
TAG_PATTERN = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?\Z")
PRODUCTS = {
    "rustgoc": {
        "config": "examples/client.toml",
        "compose": "packaging/compose/rustgoc.yaml",
    },
    "rustgos": {
        "config": "examples/server.toml",
        "compose": "packaging/compose/rustgos.yaml",
    },
}
PLATFORMS = {
    "win-x86": {"windows": True, "compose": False},
    "linux-x86": {"windows": False, "compose": True},
    "linux-arm64": {"windows": False, "compose": True},
}
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


class ReleaseError(ValueError):
    """An expected release-contract failure."""


@dataclass(frozen=True)
class ReleaseVersion:
    tag: str
    cargo: str


def parse_tag(tag: str) -> tuple[int, int, int | None]:
    match = TAG_PATTERN.fullmatch(tag)
    if match is None:
        raise ReleaseError(f"invalid release tag {tag!r}; expected vMAJOR.MINOR or vMAJOR.MINOR.PATCH")
    major, minor, patch = match.groups()
    return int(major), int(minor), None if patch is None else int(patch)


def read_workspace_version(manifest: Path) -> tuple[int, int, int]:
    try:
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        raw = data["workspace"]["package"]["version"]
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as error:
        raise ReleaseError(f"cannot read workspace package version from {manifest}: {error}") from error
    if not isinstance(raw, str) or re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", raw) is None:
        raise ReleaseError(f"workspace package version must be plain MAJOR.MINOR.PATCH, got {raw!r}")
    return tuple(int(part) for part in raw.split("."))  # type: ignore[return-value]


def verify_version(tag: str, manifest: Path) -> ReleaseVersion:
    tag_major, tag_minor, tag_patch = parse_tag(tag)
    cargo_version = read_workspace_version(manifest)
    expected = (tag_major, tag_minor, 0 if tag_patch is None else tag_patch)
    if expected != cargo_version:
        cargo_text = ".".join(str(part) for part in cargo_version)
        raise ReleaseError(f"release tag {tag!r} does not match Cargo workspace version {cargo_text!r}")
    if tag_patch is None and cargo_version[2] != 0:
        raise ReleaseError(f"short release tag {tag!r} requires a zero Cargo patch version")
    return ReleaseVersion(tag=tag, cargo=".".join(str(part) for part in cargo_version))


def archive_name(binary: str, platform: str, tag: str) -> str:
    _require_registry_key(PRODUCTS, binary, "binary")
    _require_registry_key(PLATFORMS, platform, "platform")
    parse_tag(tag)
    return f"{binary}-{platform}-{tag}.zip"


def expected_archives(tag: str) -> tuple[str, ...]:
    parse_tag(tag)
    return tuple(sorted(archive_name(binary, platform, tag) for binary in PRODUCTS for platform in PLATFORMS))


def _require_registry_key(registry: dict[str, dict[str, object]], key: str, label: str) -> None:
    if key not in registry:
        raise ReleaseError(f"unknown {label} {key!r}")


def _require_regular_file(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ReleaseError(f"{label} must be a regular file: {path}")
    if path.stat().st_size == 0:
        raise ReleaseError(f"{label} must not be empty: {path}")


def _zip_info(name: str, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | mode) << 16
    return info


def package_release(
    root: Path,
    tag: str,
    platform: str,
    binary: str,
    executable: Path,
    output_dir: Path,
) -> Path:
    _require_registry_key(PRODUCTS, binary, "binary")
    _require_registry_key(PLATFORMS, platform, "platform")
    parse_tag(tag)
    if executable.is_symlink():
        raise ReleaseError(f"executable must not be a symlink: {executable}")
    executable = executable.resolve(strict=True)
    _require_regular_file(executable, "executable")
    product = PRODUCTS[binary]
    platform_spec = PLATFORMS[platform]
    config = (root / str(product["config"])).resolve(strict=True)
    _require_regular_file(config, "configuration")
    members: list[tuple[str, Path, int]] = []
    executable_name = f"{binary}.exe" if bool(platform_spec["windows"]) else binary
    members.append((executable_name, executable, 0o755 if not bool(platform_spec["windows"]) else 0o644))
    members.append((config.name, config, 0o644))
    if bool(platform_spec["compose"]):
        compose = (root / str(product["compose"])).resolve(strict=True)
        _require_regular_file(compose, "Compose template")
        members.append(("docker-compose.yaml", compose, 0o644))

    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / archive_name(binary, platform, tag)
    handle, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=output_dir)
    os.close(handle)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary, "w") as archive:
            for member_name, source, mode in sorted(members):
                archive.writestr(_zip_info(member_name, mode), source.read_bytes())
        validate_archive(temporary, binary, platform)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination.resolve()


def validate_archive(path: Path, binary: str, platform: str) -> None:
    _require_registry_key(PRODUCTS, binary, "binary")
    _require_registry_key(PLATFORMS, platform, "platform")
    _require_regular_file(path, "archive")
    platform_spec = PLATFORMS[platform]
    executable_name = f"{binary}.exe" if bool(platform_spec["windows"]) else binary
    config_name = Path(str(PRODUCTS[binary]["config"])).name
    expected = {executable_name, config_name}
    if bool(platform_spec["compose"]):
        expected.add("docker-compose.yaml")
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise ReleaseError(f"archive contains duplicate members: {path}")
            if set(names) != expected:
                raise ReleaseError(f"archive members for {binary}/{platform} are {sorted(names)!r}, expected {sorted(expected)!r}")
            for info in infos:
                member = Path(info.filename)
                if member.is_absolute() or len(member.parts) != 1 or ".." in member.parts or info.is_dir():
                    raise ReleaseError(f"unsafe or nested archive member {info.filename!r}")
                if info.file_size == 0:
                    raise ReleaseError(f"archive member must not be empty: {info.filename}")
            if not bool(platform_spec["windows"]):
                executable_info = archive.getinfo(executable_name)
                mode = (executable_info.external_attr >> 16) & 0o777
                if mode != 0o755:
                    raise ReleaseError(f"Linux executable mode is {oct(mode)}, expected 0o755")
    except zipfile.BadZipFile as error:
        raise ReleaseError(f"invalid ZIP archive {path}: {error}") from error


def _find_input_archives(input_dir: Path) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for path in input_dir.rglob("*.zip"):
        _require_regular_file(path, "input archive")
        if path.name in found:
            raise ReleaseError(f"duplicate input archive name {path.name!r}")
        found[path.name] = path
    return found


def _validate_named_archive(path: Path, tag: str) -> None:
    match = re.fullmatch(r"(rustgoc|rustgos)-(win-x86|linux-x86|linux-arm64)-(.+)\.zip", path.name)
    if match is None or match.group(3) != tag:
        raise ReleaseError(f"unexpected archive name {path.name!r}")
    validate_archive(path, match.group(1), match.group(2))


def _write_and_verify_checksums(directory: Path, names: tuple[str, ...]) -> Path:
    checksum_path = directory / "SHA256SUMS"
    lines = []
    expected_hashes: dict[str, str] = {}
    for name in names:
        digest = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        expected_hashes[name] = digest
        lines.append(f"{digest}  {name}\n")
    checksum_path.write_text("".join(lines), encoding="ascii", newline="\n")
    parsed: dict[str, str] = {}
    for line in checksum_path.read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\]+\.zip)", line)
        if match is None or match.group(2) in parsed:
            raise ReleaseError("generated SHA256SUMS has an invalid or duplicate entry")
        parsed[match.group(2)] = match.group(1)
    if parsed != expected_hashes:
        raise ReleaseError("generated SHA256SUMS failed verification")
    return checksum_path


def finalize_release(tag: str, input_dir: Path, output_dir: Path) -> Path:
    parse_tag(tag)
    expected = expected_archives(tag)
    found = _find_input_archives(input_dir)
    if set(found) != set(expected):
        missing = sorted(set(expected) - set(found))
        extra = sorted(set(found) - set(expected))
        raise ReleaseError(f"release archive set mismatch; missing={missing!r} extra={extra!r}")
    if output_dir.exists():
        raise ReleaseError(f"release output directory already exists: {output_dir}")
    output_parent = output_dir.resolve().parent
    output_parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.", dir=output_parent))
    try:
        for name in expected:
            _validate_named_archive(found[name], tag)
            shutil.copyfile(found[name], staging / name)
        _write_and_verify_checksums(staging, expected)
        os.replace(staging, output_dir.resolve())
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return output_dir.resolve() / "SHA256SUMS"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    version = commands.add_parser("verify-version")
    version.add_argument("--tag", required=True)
    version.add_argument("--manifest", type=Path, required=True)
    package = commands.add_parser("package")
    package.add_argument("--tag", required=True)
    package.add_argument("--platform", choices=sorted(PLATFORMS), required=True)
    package.add_argument("--binary", choices=sorted(PRODUCTS), required=True)
    package.add_argument("--executable", type=Path, required=True)
    package.add_argument("--output-dir", type=Path, required=True)
    finalize = commands.add_parser("finalize")
    finalize.add_argument("--tag", required=True)
    finalize.add_argument("--input-dir", type=Path, required=True)
    finalize.add_argument("--output-dir", type=Path, required=True)
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    try:
        if arguments.command == "verify-version":
            verify_version(arguments.tag, arguments.manifest)
        elif arguments.command == "package":
            result = package_release(ROOT, arguments.tag, arguments.platform, arguments.binary, arguments.executable, arguments.output_dir)
            print(result)
        else:
            result = finalize_release(arguments.tag, arguments.input_dir, arguments.output_dir)
            print(result)
        return 0
    except (OSError, ReleaseError) as error:
        print(f"release error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
