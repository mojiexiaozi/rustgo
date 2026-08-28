#!/usr/bin/env python3
"""Executable tests for the Linux pidfd cleanup supervisor."""

from __future__ import annotations

import argparse
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pidfd_supervisor  # noqa: E402
from pidfd_supervisor import (  # noqa: E402
    CleanupDisposition,
    PidfdUnavailable,
    ProcIdentityUnavailable,
    RealPidfdOperations,
    SIGKILL_NUMBER,
    SIGTERM_NUMBER,
    parse_proc_stat_starttime,
    supervise_process,
)


class FakePidfdOperations:
    def __init__(
        self,
        *,
        observed_starttime: int = 987654,
        poll_results: tuple[bool, ...] = (),
        unavailable: bool = False,
        identity_unavailable: bool = False,
        open_error: BaseException | None = None,
    ) -> None:
        self.observed_starttime = observed_starttime
        self.poll_results = list(poll_results)
        self.unavailable = unavailable
        self.identity_unavailable = identity_unavailable
        self.open_error = open_error
        self.events: list[tuple[object, ...]] = []
        self.signals: list[int] = []

    def ensure_supported(self) -> None:
        self.events.append(("ensure_supported",))
        if self.unavailable:
            raise PidfdUnavailable("pidfd API unavailable in test")

    def open_pidfd(self, pid: int) -> int:
        self.events.append(("open_pidfd", pid))
        if self.open_error is not None:
            raise self.open_error
        return 91

    def read_starttime(self, pid: int) -> int:
        self.events.append(("read_starttime", pid))
        if self.identity_unavailable:
            raise ProcIdentityUnavailable("identity unavailable in test")
        return self.observed_starttime

    def poll_exited(self, pidfd: int, timeout_seconds: float) -> bool:
        self.events.append(("poll_exited", pidfd, timeout_seconds))
        if not self.poll_results:
            raise AssertionError("unexpected pidfd poll")
        return self.poll_results.pop(0)

    def send_signal(self, pidfd: int, sig: int) -> None:
        self.events.append(("send_signal", pidfd, sig))
        self.signals.append(sig)

    def close_pidfd(self, pidfd: int) -> None:
        self.events.append(("close_pidfd", pidfd))


class PidfdSupervisorStateMachineTests(unittest.TestCase):
    def test_preflight_rejects_python_older_than_documented_minimum(self) -> None:
        operations = RealPidfdOperations()

        with (
            patch.object(pidfd_supervisor.sys, "platform", "linux"),
            patch.object(pidfd_supervisor.sys, "version_info", (3, 9, 0)),
            self.assertRaisesRegex(PidfdUnavailable, "Python 3.10"),
        ):
            operations.ensure_supported()

    def test_proc_stat_parser_handles_spaces_and_right_parentheses(self) -> None:
        stat_line = (
            "4242 (worker ) with spaces) S "
            "1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 20"
        )

        self.assertEqual(parse_proc_stat_starttime(stat_line, 4242), 987654)

    def test_identity_mismatch_closes_pidfd_without_signalling(self) -> None:
        operations = FakePidfdOperations(observed_starttime=987655)

        result = supervise_process(4242, 987654, 2.0, 2.0, operations)

        self.assertTrue(result.ok, result.detail)
        self.assertEqual(result.disposition, CleanupDisposition.IDENTITY_MISMATCH)
        self.assertEqual(operations.signals, [])
        self.assertEqual(
            operations.events,
            [
                ("ensure_supported",),
                ("open_pidfd", 4242),
                ("read_starttime", 4242),
                ("close_pidfd", 91),
            ],
        )

    def test_matching_process_that_cooperates_receives_only_term(self) -> None:
        operations = FakePidfdOperations(poll_results=(False, True))

        result = supervise_process(4242, 987654, 2.0, 2.0, operations)

        self.assertTrue(result.ok, result.detail)
        self.assertEqual(result.disposition, CleanupDisposition.TERMINATED)
        self.assertEqual(operations.signals, [SIGTERM_NUMBER])
        self.assertEqual(operations.poll_results, [])

    def test_matching_process_that_ignores_term_is_killed_via_same_pidfd(self) -> None:
        operations = FakePidfdOperations(poll_results=(False, False, True))

        result = supervise_process(4242, 987654, 2.0, 2.0, operations)

        self.assertTrue(result.ok, result.detail)
        self.assertEqual(result.disposition, CleanupDisposition.KILLED)
        self.assertEqual(operations.signals, [SIGTERM_NUMBER, SIGKILL_NUMBER])
        signal_events = [event for event in operations.events if event[0] == "send_signal"]
        self.assertEqual(
            signal_events,
            [("send_signal", 91, SIGTERM_NUMBER), ("send_signal", 91, SIGKILL_NUMBER)],
        )

    def test_missing_pidfd_api_fails_without_opening_or_signalling(self) -> None:
        operations = FakePidfdOperations(unavailable=True)

        result = supervise_process(4242, 987654, 2.0, 2.0, operations)

        self.assertFalse(result.ok)
        self.assertEqual(result.disposition, CleanupDisposition.UNAVAILABLE)
        self.assertEqual(operations.signals, [])
        self.assertEqual(operations.events, [("ensure_supported",)])

    def test_unreadable_identity_fails_safe_without_signalling(self) -> None:
        operations = FakePidfdOperations(
            identity_unavailable=True,
            poll_results=(False,),
        )

        result = supervise_process(4242, 987654, 2.0, 2.0, operations)

        self.assertFalse(result.ok)
        self.assertEqual(result.disposition, CleanupDisposition.FAILED)
        self.assertEqual(operations.signals, [])

    def test_process_missing_before_pidfd_open_is_already_released(self) -> None:
        operations = FakePidfdOperations(open_error=ProcessLookupError())

        result = supervise_process(4242, 987654, 2.0, 2.0, operations)

        self.assertTrue(result.ok, result.detail)
        self.assertEqual(result.disposition, CleanupDisposition.ALREADY_EXITED)
        self.assertEqual(operations.signals, [])

    def test_process_still_present_after_kill_deadline_fails_boundedly(self) -> None:
        operations = FakePidfdOperations(poll_results=(False, False, False))

        result = supervise_process(4242, 987654, 0.01, 0.01, operations)

        self.assertFalse(result.ok)
        self.assertEqual(result.disposition, CleanupDisposition.FAILED)
        self.assertEqual(operations.signals, [SIGTERM_NUMBER, SIGKILL_NUMBER])


class LinuxPidfdIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if sys.platform != "linux":
            raise AssertionError("real pidfd integration tests require Linux")
        cls.operations = RealPidfdOperations()
        cls.operations.preflight()

    def spawn_child(self, signal_setup: str) -> subprocess.Popen[str]:
        code = (
            "import signal, sys\n"
            f"{signal_setup}\n"
            "print('ready', flush=True)\n"
            "while True:\n"
            "    signal.pause()\n"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertIsNotNone(process.stdout)
        self.assertEqual(process.stdout.readline().strip(), "ready")
        return process

    def finish_child(self, process: subprocess.Popen[str]) -> None:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)

    def test_real_pidfd_identity_mismatch_does_not_signal_child(self) -> None:
        process = self.spawn_child("signal.signal(signal.SIGTERM, signal.SIG_IGN)")
        try:
            starttime = self.operations.read_starttime(process.pid)

            result = supervise_process(
                process.pid,
                starttime + 1,
                0.5,
                0.5,
                self.operations,
            )

            self.assertTrue(result.ok, result.detail)
            self.assertEqual(result.disposition, CleanupDisposition.IDENTITY_MISMATCH)
            self.assertIsNone(process.poll())
        finally:
            self.finish_child(process)

    def test_real_pidfd_terminates_cooperative_child(self) -> None:
        process = self.spawn_child(
            "signal.signal(signal.SIGTERM, lambda _sig, _frame: sys.exit(0))"
        )
        try:
            starttime = self.operations.read_starttime(process.pid)

            result = supervise_process(
                process.pid,
                starttime,
                1.0,
                1.0,
                self.operations,
            )

            self.assertTrue(result.ok, result.detail)
            self.assertEqual(result.disposition, CleanupDisposition.TERMINATED)
            self.assertEqual(process.wait(timeout=5), 0)
        finally:
            self.finish_child(process)

    def test_real_pidfd_kills_child_that_ignores_term(self) -> None:
        process = self.spawn_child("signal.signal(signal.SIGTERM, signal.SIG_IGN)")
        try:
            starttime = self.operations.read_starttime(process.pid)

            result = supervise_process(
                process.pid,
                starttime,
                0.05,
                1.0,
                self.operations,
            )

            self.assertTrue(result.ok, result.detail)
            self.assertEqual(result.disposition, CleanupDisposition.KILLED)
            self.assertEqual(process.wait(timeout=5), -SIGKILL_NUMBER)
        finally:
            self.finish_child(process)


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--mock-only", action="store_true")
    mode.add_argument("--integration", action="store_true")
    args = parser.parse_args()

    loader = unittest.TestLoader()
    suites = [loader.loadTestsFromTestCase(PidfdSupervisorStateMachineTests)]
    if args.integration:
        suites.append(loader.loadTestsFromTestCase(LinuxPidfdIntegrationTests))
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(suites))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
