"""Windows-safe import contract for local developer and demo verification."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest


LOCK_COMPETITOR = r"""
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from src.operations.runner import OperationsRunner

lock_dir = Path(sys.argv[1])
started = Path(sys.argv[2])
entered = Path(sys.argv[3])
release = Path(sys.argv[4])
hold = sys.argv[5] == "hold"
runner = OperationsRunner(storage=object(), config=SimpleNamespace(lock_dir=lock_dir))
started.write_text("started", encoding="utf-8")
with runner._task_lock("shared-key"):
    entered.write_text("entered", encoding="utf-8")
    while hold and not release.exists():
        time.sleep(0.02)
"""


def _wait_for(path: Path, process: subprocess.Popen[str], timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError(f"lock competitor exited early ({process.returncode}): {stdout}\n{stderr}")
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {path}")


def test_operations_runner_imports_without_posix_fcntl() -> None:
    from src.operations.runner import OperationsRunner

    assert OperationsRunner.__name__ == "OperationsRunner"


def test_operations_runner_releases_a_windows_local_lock(tmp_path: Path) -> None:
    from src.operations.runner import OperationsRunner

    runner = OperationsRunner(
        storage=object(),
        config=SimpleNamespace(lock_dir=tmp_path / "locks"),
    )

    with runner._task_lock("local-demo"):
        lock_path = tmp_path / "locks" / "local-demo.lock"
        assert lock_path.exists()
        if os.name == "nt":
            assert lock_path.stat().st_size >= 1


@pytest.mark.skipif(os.name != "nt", reason="exercises the Windows msvcrt cross-process fallback")
def test_windows_task_lock_releases_after_an_exception(tmp_path: Path) -> None:
    from src.operations.runner import OperationsRunner

    runner = OperationsRunner(
        storage=object(),
        config=SimpleNamespace(lock_dir=tmp_path / "locks"),
    )

    with pytest.raises(RuntimeError, match="task failed"):
        with runner._task_lock("exceptional-task"):
            raise RuntimeError("task failed")

    with runner._task_lock("exceptional-task"):
        assert True


@pytest.mark.skipif(os.name != "nt", reason="exercises the Windows msvcrt cross-process fallback")
def test_windows_task_lock_blocks_a_second_process_until_release(tmp_path: Path) -> None:
    lock_dir = tmp_path / "locks"
    first_started = tmp_path / "first-started"
    first_entered = tmp_path / "first-entered"
    second_started = tmp_path / "second-started"
    second_entered = tmp_path / "second-entered"
    release = tmp_path / "release"

    first = subprocess.Popen(
        [
            sys.executable,
            "-c",
            LOCK_COMPETITOR,
            str(lock_dir),
            str(first_started),
            str(first_entered),
            str(release),
            "hold",
        ],
        cwd=Path(__file__).parents[1],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    second: subprocess.Popen[str] | None = None
    try:
        _wait_for(first_entered, first)
        second = subprocess.Popen(
            [
                sys.executable,
                "-c",
                LOCK_COMPETITOR,
                str(lock_dir),
                str(second_started),
                str(second_entered),
                str(release),
                "enter",
            ],
            cwd=Path(__file__).parents[1],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _wait_for(second_started, second)

        time.sleep(0.2)
        assert not second_entered.exists()
        assert second.poll() is None

        release.write_text("release", encoding="utf-8")
        first.wait(timeout=5)
        second.wait(timeout=5)
        assert first.returncode == 0
        assert second.returncode == 0
        assert second_entered.exists()
    finally:
        release.touch(exist_ok=True)
        for process in (first, second):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
