"""Read-only access to results of Artemis' stock port_scanner (e.g. from the monthly full scan)."""

import datetime
import logging
from typing import Any, List, Optional, Tuple

from sqlalchemy import select  # type: ignore
from sqlalchemy.engine import Engine  # type: ignore

from cybercover.state import as_utc

log = logging.getLogger(__name__)

Endpoint = Tuple[int, str, bool]

STOCK_RECEIVER = "port_scanner"
COMPLETED_STATUSES = ("OK", "INTERESTING")
MAX_ROWS = 50


def endpoints_from_result(result: Any) -> Optional[List[Endpoint]]:
    """Convert a stock port_scanner result ``{ip: {port: {service, ssl, ...}}}`` into the endpoints
    it emitted as SERVICE tasks (the union of ports over all IPs of the host). None if malformed."""
    from artemis.binds import Service

    if not isinstance(result, dict):
        return None
    endpoints = set()
    for ports in result.values():
        if not isinstance(ports, dict):
            return None
        for port, details in ports.items():
            if not isinstance(details, dict) or not isinstance(details.get("service"), str):
                return None
            try:
                service = Service(details["service"].lower()).value
                endpoints.add((int(port), service, bool(details.get("ssl"))))
            except (ValueError, TypeError):
                return None
    return sorted(endpoints)


class StockPortResults:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def latest(
        self, client: str, host: str, newer_than: datetime.datetime
    ) -> Optional[Tuple[datetime.datetime, List[Endpoint]]]:
        """The newest completed stock port_scanner result for (client, host) created after
        ``newer_than``, as (scan time in UTC, endpoints), or None."""
        from artemis.db import TaskResult

        # task_result.created_at is a naive UTC timestamp.
        since = as_utc(newer_than).replace(tzinfo=None)
        statement = (
            select(TaskResult.created_at, TaskResult.task, TaskResult.result)
            .where(
                TaskResult.receiver == STOCK_RECEIVER,
                TaskResult.target_string == host,
                TaskResult.status.in_(COMPLETED_STATUSES),
                TaskResult.created_at > since,
            )
            .order_by(TaskResult.created_at.desc())
            .limit(MAX_ROWS)
        )
        with self._engine.connect() as connection:
            for created_at, task, result in connection.execute(statement):
                persistent = (task or {}).get("payload_persistent", {}) if isinstance(task, dict) else {}
                if (persistent.get("original_target") or host) != client:
                    continue
                endpoints = endpoints_from_result(result)
                if endpoints is None:
                    log.warning("Ignoring malformed stock port_scanner result for %s", host)
                    continue
                return as_utc(created_at), endpoints
        return None
