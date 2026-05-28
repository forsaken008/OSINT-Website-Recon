from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any, Callable, Optional

from loguru import logger

from ..config import Config
from ..models import ScanResult


ProgressCallback = Callable[[str, str, str], None]
# (module_name, level, message)  level = "info" | "warn" | "error" | "success"


class BaseModule(ABC):
    """Abstract base for every recon module.

    Subclasses implement `run()` which receives the in-progress ScanResult
    and mutates it in-place, returning it when done.
    """

    #: Short identifier used in CLI flags and JSON output keys
    name: str = "base"

    #: Human-readable label for progress display
    label: str = "Base Module"

    def __init__(
        self,
        config: Config,
        progress_cb: Optional[ProgressCallback] = None,
        cancel_event: Optional[asyncio.Event] = None,
    ) -> None:
        self.config = config
        self._progress_cb = progress_cb or _noop_progress
        self._cancel = cancel_event or asyncio.Event()

    # ── Public API ────────────────────────────────────────────────────────────

    @abstractmethod
    async def run(self, result: ScanResult) -> ScanResult:
        """Execute the module and populate the relevant field(s) of result."""

    def is_cancelled(self) -> bool:
        return self._cancel.is_set()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def info(self, msg: str) -> None:
        logger.info(f"[{self.name}] {msg}")
        self._progress_cb(self.name, "info", msg)

    def warn(self, msg: str) -> None:
        logger.warning(f"[{self.name}] {msg}")
        self._progress_cb(self.name, "warn", msg)

    def error(self, msg: str) -> None:
        logger.error(f"[{self.name}] {msg}")
        self._progress_cb(self.name, "error", msg)

    def success(self, msg: str) -> None:
        logger.success(f"[{self.name}] {msg}")
        self._progress_cb(self.name, "success", msg)

    async def _check_cancelled(self) -> bool:
        """Yield to the event loop and return True if cancelled."""
        await asyncio.sleep(0)
        return self.is_cancelled()


def _noop_progress(module: str, level: str, message: str) -> None:
    pass
