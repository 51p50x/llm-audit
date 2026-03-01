"""Probe registry for llm-audit — auto-discovers BaseProbe subclasses."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import TYPE_CHECKING

from llm_audit.probes.base import BaseProbe

if TYPE_CHECKING:
    pass


def _discover_probes() -> dict[str, type[BaseProbe]]:
    """Scan every module in this package and register concrete BaseProbe subclasses.

    Each probe must declare a non-empty ``probe_key`` class attribute.
    """
    registry: dict[str, type[BaseProbe]] = {}
    package_path = __path__
    for finder, module_name, _is_pkg in pkgutil.iter_modules(package_path):
        if module_name == "base":
            continue
        module = importlib.import_module(f"{__name__}.{module_name}")
        for _attr_name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BaseProbe)
                and obj is not BaseProbe
                and getattr(obj, "probe_key", None)
            ):
                registry[obj.probe_key] = obj
    return dict(sorted(registry.items()))


ALL_PROBES: dict[str, type[BaseProbe]] = _discover_probes()

__all__ = ["BaseProbe", "ALL_PROBES"]
