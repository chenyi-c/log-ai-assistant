"""Windows-safe import contract for local developer and demo verification."""

from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path


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
        pass
