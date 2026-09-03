#!/usr/bin/env python3
"""Black-box functional acceptance for Rustgo release packaging."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RELEASE = ROOT / "scripts" / "release.py"
PRODUCTS = {"rustgoc": "client.toml", "rustgos": "server.toml"}
PLATFORMS = {
    "win-x86": ("rustgoc.exe", "rustgos.exe"),
    "linux-x86": ("rustgoc", "rustgos"),
    "linux-arm64": ("rustgoc", "rustgos"),
}


def run(*arguments: str, success: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, str(RELEASE), *arguments],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if success and result.returncode != 0:
        raise AssertionError(f"release command failed: {result.stderr.strip()}")
    if not success and result.returncode == 0:
        raise AssertionError(f"release command unexpectedly succeeded: {' '.join(arguments)}")
    return result


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--win-x86-dir", type=Path, required=True)
    parser.add_argument("--linux-x86-dir", type=Path, required=True)
    parser.add_argument("--linux-arm64-dir", type=Path, required=True)
    return parser.parse_args()


def assert_version_contract(temporary: Path, tag: str) -> None:
    run("verify-version", "--tag", tag, "--manifest", "Cargo.toml")
    manifest = temporary / "Cargo.toml"
    manifest.write_text('[workspace.package]\nversion = "0.3.1"\n', encoding="utf-8")
    run("verify-version", "--tag", tag, "--manifest", str(manifest), success=False)
    run("verify-version", "--tag", "0.3", "--manifest", "Cargo.toml", success=False)


def package_all(tag: str, binary_dirs: dict[str, Path], output: Path) -> None:
    for platform, executable_names in PLATFORMS.items():
        for binary, executable_name in zip(PRODUCTS, executable_names, strict=True):
            run(
                "package",
                "--tag", tag,
                "--platform", platform,
                "--binary", binary,
                "--executable", str(binary_dirs[platform] / executable_name),
                "--output-dir", str(output / platform),
            )


def assert_archive(path: Path, binary: str, platform: str) -> None:
    config_name = PRODUCTS[binary]
    executable_name = f"{binary}.exe" if platform == "win-x86" else binary
    expected = {executable_name, config_name}
    if platform != "win-x86":
        expected.add("docker-compose.yaml")
    with zipfile.ZipFile(path) as archive:
        assert set(archive.namelist()) == expected, path.name
        assert archive.read(config_name) == (ROOT / "examples" / config_name).read_bytes()
        if platform != "win-x86":
            assert archive.read("docker-compose.yaml") == (ROOT / "packaging" / "compose" / f"{binary}.yaml").read_bytes()
            mode = (archive.getinfo(executable_name).external_attr >> 16) & 0o777
            assert mode == 0o755, f"{path.name} executable mode is {oct(mode)}"


def assert_complete_release(tag: str, input_dir: Path, final_dir: Path) -> None:
    run("finalize", "--tag", tag, "--input-dir", str(input_dir), "--output-dir", str(final_dir))
    expected_names = {f"{binary}-{platform}-{tag}.zip" for binary in PRODUCTS for platform in PLATFORMS}
    assert {path.name for path in final_dir.glob("*.zip")} == expected_names
    assert all("rustgoc-gui" not in name for name in expected_names)
    for name in expected_names:
        stem = name.removesuffix(f"-{tag}.zip")
        binary, platform = stem.split("-", 1)
        assert_archive(final_dir / name, binary, platform)
    checksum_lines = (final_dir / "SHA256SUMS").read_text(encoding="ascii").splitlines()
    assert [line.split("  ", 1)[1] for line in checksum_lines] == sorted(expected_names)
    for line in checksum_lines:
        digest, name = line.split("  ", 1)
        assert hashlib.sha256((final_dir / name).read_bytes()).hexdigest() == digest


def assert_negative_paths(tag: str, binary_dirs: dict[str, Path], input_dir: Path, temporary: Path) -> None:
    empty = temporary / "empty"
    empty.touch()
    run("package", "--tag", tag, "--platform", "linux-x86", "--binary", "rustgoc", "--executable", str(empty), "--output-dir", str(temporary / "empty-out"), success=False)
    run("package", "--tag", tag, "--platform", "linux-x86", "--binary", "rustgoc-gui", "--executable", str(binary_dirs["linux-x86"] / "rustgoc"), "--output-dir", str(temporary / "gui-out"), success=False)

    link = temporary / "linked-rustgoc"
    try:
        os.symlink(binary_dirs["linux-x86"] / "rustgoc", link)
    except OSError as error:
        if os.name != "nt":
            raise AssertionError(f"could not create symlink for negative acceptance: {error}") from error
    else:
        run("package", "--tag", tag, "--platform", "linux-x86", "--binary", "rustgoc", "--executable", str(link), "--output-dir", str(temporary / "link-out"), success=False)

    extra_input = temporary / "extra-input"
    shutil.copytree(input_dir, extra_input)
    (extra_input / "unexpected.zip").write_bytes(b"not a release archive")
    run("finalize", "--tag", tag, "--input-dir", str(extra_input), "--output-dir", str(temporary / "extra-final"), success=False)

    missing_input = temporary / "missing-input"
    shutil.copytree(input_dir, missing_input)
    next(missing_input.rglob("*.zip")).unlink()
    run("finalize", "--tag", tag, "--input-dir", str(missing_input), "--output-dir", str(temporary / "missing-final"), success=False)


def main() -> int:
    arguments = parse_arguments()
    binary_dirs = {
        "win-x86": arguments.win_x86_dir.resolve(strict=True),
        "linux-x86": arguments.linux_x86_dir.resolve(strict=True),
        "linux-arm64": arguments.linux_arm64_dir.resolve(strict=True),
    }
    with tempfile.TemporaryDirectory(prefix="rustgo-release-acceptance-") as temporary_name:
        temporary = Path(temporary_name)
        assert_version_contract(temporary, arguments.tag)
        release_input = temporary / "input"
        package_all(arguments.tag, binary_dirs, release_input)
        assert_complete_release(arguments.tag, release_input, temporary / "final")
        assert_negative_paths(arguments.tag, binary_dirs, release_input, temporary)
    print("release acceptance passed: 6 archives, checksums, contents, and fail-closed paths")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
