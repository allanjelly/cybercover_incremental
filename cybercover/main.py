"""Artemis web/API entrypoint with the cybercover_nuclei module registered.

Run instead of ``artemis.main:app``:  uvicorn cybercover.main:app --host 0.0.0.0 --port 5000

No Artemis file is modified; the patching below happens in-process at start-up and fails loudly
if Artemis internals change.
"""

import functools
from typing import Any, Callable

import artemis.api as artemis_api
from artemis.config import Config

from cybercover.modules.cybercover_nuclei_configuration import (
    CybercoverNucleiConfiguration,
)

MODULE_IDENTITY = "cybercover_nuclei"
# Modules that must run so that a NUCLEI_TARGET task reaches cybercover_nuclei.
MODULE_PREREQUISITES = {"port_scanner", "nuclei-router"}
# Would receive the same NUCLEI_TARGET tasks and run a full scan.
STANDARD_MODULE = "nuclei-module"


def register_configuration() -> None:
    registry = artemis_api.RUNTIME_CONFIGURATION_CLASSES
    assert isinstance(registry, dict), "Artemis changed RUNTIME_CONFIGURATION_CLASSES, review cybercover.main"
    registry[MODULE_IDENTITY] = CybercoverNucleiConfiguration


def disable_by_default() -> None:
    defaults = Config.Miscellaneous.MODULES_DISABLED_BY_DEFAULT
    if MODULE_IDENTITY not in defaults:
        defaults.append(MODULE_IDENTITY)


def wrap_create_tasks(original: Callable[..., Any]) -> Callable[..., Any]:
    """The module runs iff a cybercover_nuclei configuration is supplied: then its prerequisites
    are enabled too, so that enabled_modules=["cybercover_nuclei"] is enough. Without a
    configuration the module is always disabled, so ordinary scans never trigger it."""

    @functools.wraps(original)
    def create_tasks(*args: Any, **kwargs: Any) -> Any:
        disabled = list(kwargs.get("disabled_modules") or [])
        if MODULE_IDENTITY in (kwargs.get("module_runtime_configurations") or {}):
            disabled = [m for m in disabled if m != MODULE_IDENTITY and m not in MODULE_PREREQUISITES]
            if STANDARD_MODULE not in disabled:
                disabled.append(STANDARD_MODULE)
        elif MODULE_IDENTITY not in disabled:
            disabled.append(MODULE_IDENTITY)
        kwargs["disabled_modules"] = disabled
        return original(*args, **kwargs)

    return create_tasks


assert hasattr(artemis_api, "create_tasks"), "Artemis changed create_tasks, review cybercover.main"
register_configuration()
disable_by_default()
artemis_api.create_tasks = wrap_create_tasks(artemis_api.create_tasks)

from artemis.main import app  # noqa: E402  (must be imported after patching)

__all__ = ["app"]
