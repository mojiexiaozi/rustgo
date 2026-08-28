#!/usr/bin/env python3
"""Terminate one Linux process through a single identity-checked pidfd."""

from __future__ import annotations

import argparse
import errno
import math
import os
import select
import signal
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol, Union

SIGTERM_NUMBER = int(getattr(signal, "SIGTERM", 15))
SIGKILL_NUMBER = int(getattr(signal, "SIGKILL", 9))


class PidfdUnavailable(RuntimeError):
    """The host cannot provide the pidfd safety contract."""


class ProcIdentityUnavailable(RuntimeError):
    """The target's post-pidfd /proc identity could not be verified."""


class CleanupDisposition(Enum):
    ALREADY_EXITED = "already-exited"
    IDENTITY_MISMATCH = "identity-mismatch"
    TERMINATED = "terminated"
    KILLED = "killed"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"


@dataclass(frozen=True)
class CleanupResult:
    disposition: CleanupDisposition
    detail: str

    @property
    def ok(self) -> bool:
        return self.disposition in {
            CleanupDisposition.ALREADY_EXITED,
            CleanupDisposition.IDENTITY_MISMATCH,
            CleanupDisposition.TERMINATED,
            CleanupDisposition.KILLED,
        }


class PidfdOperations(Protocol):
    def ensure_supported(self) -> None: ...

    def open_pidfd(self, pid: int) -> int: ...

    def read_starttime(self, pid: int) -> int: ...

    def poll_exited(self, pidfd: int, timeout_seconds: float) -> bool: ...

    def send_signal(self, pidfd: int, sig: int) -> None: ...

    def close_pidfd(self, pidfd: int) -> None: ...


def parse_proc_stat_starttime(stat_line: Union[str, bytes], expected_pid: int) -> int:
    """Return field 22 from /proc/<pid>/stat without splitting comm."""

    if isinstance(stat_line, bytes):
        expected_prefix: Union[str, bytes] = f"{expected_pid} (".encode("ascii")
        delimiter: Union[str, bytes] = b") "
    else:
        expected_prefix = f"{expected_pid} ("
        delimiter = ") "
    if not stat_line.startswith(expected_prefix) or delimiter not in stat_line:
        raise ValueError("proc stat PID/comm prefix is malformed")
    fields = stat_line.rsplit(delimiter, 1)[1].split()
    if len(fields) < 20:
        raise ValueError("proc stat is missing starttime field 22")
    starttime = int(fields[19])
    if starttime < 0:
        raise ValueError("proc stat starttime must be nonnegative")
    return starttime


class RealPidfdOperations:
    def ensure_supported(self) -> None:
        if sys.platform != "linux":
            raise PidfdUnavailable("pidfd cleanup requires Linux")
        if sys.version_info < (3, 10):
            raise PidfdUnavailable("Python 3.10 or newer is required")
        if not callable(getattr(os, "pidfd_open", None)):
            raise PidfdUnavailable("Python does not provide os.pidfd_open")
        if not callable(getattr(signal, "pidfd_send_signal", None)):
            raise PidfdUnavailable("Python does not provide signal.pidfd_send_signal")
        if not callable(getattr(select, "poll", None)):
            raise PidfdUnavailable("Python does not provide select.poll")

    def open_pidfd(self, pid: int) -> int:
        return os.pidfd_open(pid, 0)

    def read_starttime(self, pid: int) -> int:
        try:
            stat_line = Path(f"/proc/{pid}/stat").read_bytes()
            return parse_proc_stat_starttime(stat_line, pid)
        except (OSError, ValueError) as error:
            raise ProcIdentityUnavailable(str(error)) from error

    def poll_exited(self, pidfd: int, timeout_seconds: float) -> bool:
        timeout_milliseconds = math.ceil(max(0.0, timeout_seconds) * 1000.0)
        poller = select.poll()
        poller.register(pidfd, select.POLLIN)
        events = poller.poll(timeout_milliseconds)
        for _descriptor, event_mask in events:
            invalid_mask = select.POLLERR | select.POLLNVAL
            if event_mask & invalid_mask:
                raise OSError(errno.EBADF, "pidfd poll reported an invalid descriptor")
            if event_mask & (select.POLLIN | select.POLLHUP):
                return True
        return False

    def send_signal(self, pidfd: int, sig: int) -> None:
        signal.pidfd_send_signal(pidfd, sig, None, 0)

    def close_pidfd(self, pidfd: int) -> None:
        os.close(pidfd)

    def preflight(self) -> None:
        self.ensure_supported()
        pidfd = self.open_pidfd(os.getpid())
        try:
            self.send_signal(pidfd, 0)
        finally:
            self.close_pidfd(pidfd)


def _failure(detail: str) -> CleanupResult:
    return CleanupResult(CleanupDisposition.FAILED, detail)


def supervise_process(
    pid: int,
    expected_starttime: int,
    term_grace_seconds: float,
    kill_grace_seconds: float,
    operations: PidfdOperations,
) -> CleanupResult:
    """Validate identity after pidfd_open, then signal and poll only that pidfd."""

    try:
        operations.ensure_supported()
    except PidfdUnavailable as error:
        return CleanupResult(CleanupDisposition.UNAVAILABLE, str(error))

    try:
        pidfd = operations.open_pidfd(pid)
    except ProcessLookupError:
        return CleanupResult(
            CleanupDisposition.ALREADY_EXITED,
            "managed process exited before pidfd_open",
        )
    except OSError as error:
        if error.errno in {errno.ENOSYS, errno.EINVAL}:
            return CleanupResult(
                CleanupDisposition.UNAVAILABLE,
                f"kernel pidfd_open support is unavailable: {error}",
            )
        return _failure(f"pidfd_open failed: {error}")

    try:
        try:
            observed_starttime = operations.read_starttime(pid)
        except ProcIdentityUnavailable as error:
            try:
                if operations.poll_exited(pidfd, 0.0):
                    return CleanupResult(
                        CleanupDisposition.ALREADY_EXITED,
                        "pidfd target exited before identity verification",
                    )
            except OSError as poll_error:
                return _failure(f"pidfd poll failed after unreadable identity: {poll_error}")
            return _failure(f"cannot verify pidfd target identity: {error}")

        if observed_starttime != expected_starttime:
            return CleanupResult(
                CleanupDisposition.IDENTITY_MISMATCH,
                "pidfd target starttime does not match the managed identity",
            )

        try:
            if operations.poll_exited(pidfd, 0.0):
                return CleanupResult(
                    CleanupDisposition.ALREADY_EXITED,
                    "managed pidfd target already exited",
                )
            operations.send_signal(pidfd, SIGTERM_NUMBER)
        except ProcessLookupError:
            return CleanupResult(
                CleanupDisposition.ALREADY_EXITED,
                "managed pidfd target exited before TERM",
            )
        except OSError as error:
            return _failure(f"pidfd TERM failed: {error}")

        try:
            if operations.poll_exited(pidfd, term_grace_seconds):
                return CleanupResult(
                    CleanupDisposition.TERMINATED,
                    "managed pidfd target exited after TERM",
                )
            operations.send_signal(pidfd, SIGKILL_NUMBER)
        except ProcessLookupError:
            return CleanupResult(
                CleanupDisposition.TERMINATED,
                "managed pidfd target exited before KILL",
            )
        except OSError as error:
            return _failure(f"pidfd escalation failed: {error}")

        try:
            if operations.poll_exited(pidfd, kill_grace_seconds):
                return CleanupResult(
                    CleanupDisposition.KILLED,
                    "managed pidfd target exited after KILL",
                )
        except OSError as error:
            return _failure(f"pidfd post-KILL poll failed: {error}")
        return _failure("managed pidfd target remained present after the KILL deadline")
    finally:
        try:
            operations.close_pidfd(pidfd)
        except OSError:
            # Helper exit closes any descriptor that an unusual close error left open.
            pass


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0.0:
        raise argparse.ArgumentTypeError("timeout must be greater than zero")
    return parsed


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("preflight")

    terminate = subparsers.add_parser("terminate")
    terminate.add_argument("--pid", type=int, required=True)
    terminate.add_argument("--expected-starttime", type=int, required=True)
    terminate.add_argument("--term-grace-seconds", type=_positive_float, required=True)
    terminate.add_argument("--kill-grace-seconds", type=_positive_float, required=True)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    arguments = parse_arguments(argv)
    operations = RealPidfdOperations()
    if arguments.command == "preflight":
        try:
            operations.preflight()
        except (PidfdUnavailable, OSError) as error:
            print(
                "pidfd preflight failed: Linux kernel pidfd support and "
                f"Python pidfd APIs are required: {error}",
                file=sys.stderr,
            )
            return 1
        return 0

    if arguments.pid <= 0 or arguments.expected_starttime < 0:
        print("pidfd cleanup requires a positive PID and nonnegative starttime", file=sys.stderr)
        return 2
    result = supervise_process(
        arguments.pid,
        arguments.expected_starttime,
        arguments.term_grace_seconds,
        arguments.kill_grace_seconds,
        operations,
    )
    if not result.ok:
        print(f"pidfd cleanup failed for managed PID {arguments.pid}: {result.detail}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
