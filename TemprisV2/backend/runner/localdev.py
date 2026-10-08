# backend/runner/localdev.py
"""
LOCAL-ONLY execution backend for canary/verification runs on a developer
machine (e.g. Docker Desktop, where the host has no iptables binary).

The containment plan is IDENTICAL to production (runner.execution:
prepare_network / teardown_network / stop_container) — the only difference
is that the iptables commands are executed inside the Docker VM's host
network namespace through a privileged helper, because Docker Desktop keeps
DOCKER-USER in the VM. This module must NEVER run in production: on the VPS
the runner executes the plan natively via runner.execution.run_in_container.
"""
from __future__ import annotations

import shlex
import subprocess

from runner import execution

HELPER_IMAGE = "alpine:3.20"


def _iptables_via_vm(cmd: list[str]) -> None:
    """Run one `iptables ...` command inside the Docker VM host netns."""
    args = " ".join(shlex.quote(a) for a in cmd[1:])
    full = [
        "docker", "run", "--rm", "--network", "host", "--privileged",
        HELPER_IMAGE, "sh", "-c",
        f"apk add -q iptables >/dev/null 2>&1; iptables {args}",
    ]
    proc = subprocess.run(full, shell=False, capture_output=True, timeout=300)
    if proc.returncode != 0:
        raise RuntimeError(
            f"VM iptables failed ({proc.returncode}): "
            f"{proc.stderr.decode('utf-8', errors='replace').strip()}"
        )


def _split(cmds: list[list[str]]):
    native, via_vm = [], []
    for cmd in cmds:
        (via_vm if cmd[0] == "iptables" else native).append(cmd)
    return native, via_vm


def prepare(run: dict, pinned_ips: list[str]) -> None:
    native, via_vm = _split(execution.prepare_network(run, pinned_ips))
    for cmd in native:
        execution._run_checked(cmd)
    for cmd in via_vm:
        _iptables_via_vm(cmd)


def teardown(run: dict, pinned_ips: list[str]) -> None:
    # B2: teardown failures are LOUD here too — a silently skipped rule
    # deletion leaves ACCEPTs above DROP for the next run.
    native, via_vm = _split(execution.teardown_network(run, pinned_ips))
    failures: list[str] = []
    for cmd in via_vm:
        proc = subprocess.run(
            ["docker", "run", "--rm", "--network", "host", "--privileged",
             HELPER_IMAGE, "sh", "-c",
             "apk add -q iptables >/dev/null 2>&1; "
             + " ".join(shlex.quote(a) for a in cmd[1:])],
            shell=False, capture_output=True, timeout=300,
        )
        if proc.returncode != 0:
            failures.append(
                f"{' '.join(cmd)}: rc={proc.returncode} "
                f"{proc.stderr.decode('utf-8', errors='replace').strip()}"
            )
    for cmd in native:
        try:
            execution._run_checked(cmd, timeout=60)
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            failures.append(str(exc))
    if failures:
        raise execution.TeardownError("; ".join(failures))


def cut(run: dict) -> None:
    """The quarantine DROP via the VM helper (LOCAL ONLY): must succeed —
    a failed cut fails loud as containment-not-established."""
    for cmd in execution.cut_egress(run):
        proc = subprocess.run(
            ["docker", "run", "--rm", "--network", "host", "--privileged",
             HELPER_IMAGE, "sh", "-c",
             "apk add -q iptables >/dev/null 2>&1; "
             + " ".join(shlex.quote(a) for a in cmd[1:])],
            shell=False, capture_output=True, timeout=300,
        )
        if proc.returncode != 0:
            raise execution.TeardownError(
                f"quarantine drop could not be installed; containment not "
                f"established: {' '.join(cmd)} rc={proc.returncode} "
                f"{proc.stderr.decode('utf-8', errors='replace').strip()}"
            )


def execute(run: dict, check_alive=None) -> execution.ExecutionResult:
    """The local canary executor: signature-compatible with
    runner.execution.run_in_container for the claim loop."""
    pinned = run["policy_snapshot"]["pinned_ips"]
    return execution.run_in_container(
        run, check_alive,
        prepare=lambda: prepare(run, pinned),
        teardown=lambda: teardown(run, pinned),
        cut=lambda: cut(run),
    )
