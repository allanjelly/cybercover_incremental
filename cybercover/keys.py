"""How Cybercover identifies a customer ("client") and an endpoint in its stored state."""

from typing import Any, Optional


def client_key(task: Any, fallback: Optional[str] = None) -> str:
    """The customer a task belongs to: the top-level target the scan was requested for.

    Artemis copies ``original_target`` into the persistent payload of every task derived from a
    target added through /api/add, so two customers sharing a host (e.g. shared hosting) keep
    separate state.
    """
    persistent = getattr(task, "payload_persistent", None)
    original = persistent.get("original_target") if isinstance(persistent, dict) else None
    if original:
        return str(original)
    if fallback is not None:
        return fallback
    from artemis.task_utils import get_target_host

    return get_target_host(task)
