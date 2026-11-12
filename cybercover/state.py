"""Persistent Cybercover state in Artemis' PostgreSQL, outside Artemis' Alembic migrations."""

import datetime
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy import (  # type: ignore
    Boolean,
    Column,
    Date,
    DateTime,
    Integer,
    MetaData,
    String,
    create_engine,
)
from sqlalchemy.engine import Engine  # type: ignore
from sqlalchemy.orm import declarative_base, sessionmaker  # type: ignore

# Separate metadata, so Artemis' alembic migrations never see these tables.
Base = declarative_base(metadata=MetaData())

# (client, host, port): the customer (original target), the scanned host and its port.
EndpointKey = Tuple[str, str, int]


def as_utc(value: datetime.datetime) -> datetime.datetime:
    """Normalize a stored timestamp to an aware UTC datetime (naive values are UTC)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value.astimezone(datetime.timezone.utc)


class ScanState(Base):  # type: ignore
    """The incremental Nuclei state of one endpoint of one customer.

    ``snapshot_date`` is the UTC date of the main/.new-additions snapshot the last successful scan
    used. The next scan diffs against exactly that snapshot, so a scan running past midnight does
    not skip the additions published later that day.

    Version 2 of the table: version 1 (``cybercover_scan_state``) was keyed by host:port only, which
    mixed up customers sharing a host. It is left untouched; endpoints without a v2 row are treated
    as first scans (installed release list plus today's additions).
    """

    __tablename__ = "cybercover_scan_state_v2"

    client = Column(String, primary_key=True)
    host = Column(String, primary_key=True)
    port = Column(Integer, primary_key=True)
    templates_version = Column(String, nullable=False)
    snapshot_date = Column(Date, nullable=False)
    scanned_at = Column(DateTime(timezone=True), nullable=False)


class DiscoveryState(Base):  # type: ignore
    """The release and time for which ports of a (client, host) were last discovered."""

    __tablename__ = "cybercover_discovery_state"

    client = Column(String, primary_key=True)
    host = Column(String, primary_key=True)
    templates_version = Column(String, nullable=False)
    discovered_at = Column(DateTime(timezone=True), nullable=False)


class DiscoveredEndpoint(Base):  # type: ignore
    __tablename__ = "cybercover_endpoints"

    client = Column(String, primary_key=True)
    host = Column(String, primary_key=True)
    port = Column(Integer, primary_key=True)
    service = Column(String, nullable=False)
    ssl = Column(Boolean, nullable=False)


def _create_engine(conn_str: Optional[str], engine: Optional[Engine]) -> Engine:
    if engine is None:
        if conn_str is None:
            from artemis.config import Config

            conn_str = Config.Data.POSTGRES_CONN_STR
        engine = create_engine(conn_str)
    return engine


class DiscoveryStore:
    def __init__(self, conn_str: Optional[str] = None, engine: Optional[Engine] = None) -> None:
        self.engine = _create_engine(conn_str, engine)
        self._session = sessionmaker(bind=self.engine)
        Base.metadata.create_all(self.engine)

    def get_state(self, client: str, host: str) -> Optional[Tuple[str, datetime.datetime]]:
        """The (release, discovery time in UTC) of the stored endpoints, or None if unknown."""
        with self._session() as session:
            row = session.get(DiscoveryState, (client, host))
            return (row.templates_version, as_utc(row.discovered_at)) if row else None

    def get_version(self, client: str, host: str) -> Optional[str]:
        state = self.get_state(client, host)
        return state[0] if state else None

    def get_endpoints(self, client: str, host: str) -> List[Tuple[int, str, bool]]:
        with self._session() as session:
            rows = (
                session.query(DiscoveredEndpoint)
                .filter(DiscoveredEndpoint.client == client, DiscoveredEndpoint.host == host)
                .order_by(DiscoveredEndpoint.port)
                .all()
            )
            return [(row.port, row.service, row.ssl) for row in rows]

    def replace(
        self,
        client: str,
        host: str,
        version: str,
        endpoints: Iterable[Tuple[int, str, bool]],
        discovered_at: Optional[datetime.datetime] = None,
    ) -> None:
        """Replace the whole endpoint list of (client, host) with the result of a fresh discovery.

        ``discovered_at`` defaults to now; it is the time of the adopted scan when endpoints are
        taken over from a stock port_scanner result, so the age limit counts from that scan.
        """
        when = as_utc(discovered_at) if discovered_at else datetime.datetime.now(datetime.timezone.utc)
        with self._session() as session:
            session.query(DiscoveredEndpoint).filter(
                DiscoveredEndpoint.client == client, DiscoveredEndpoint.host == host
            ).delete()
            for port, service, ssl in set(endpoints):
                session.add(DiscoveredEndpoint(client=client, host=host, port=port, service=service, ssl=ssl))
            session.merge(DiscoveryState(client=client, host=host, templates_version=version, discovered_at=when))
            session.commit()


class ScanStateStore:
    def __init__(self, conn_str: Optional[str] = None, engine: Optional[Engine] = None) -> None:
        engine = _create_engine(conn_str, engine)
        self._session = sessionmaker(bind=engine)
        Base.metadata.create_all(engine)

    def get_states(self, keys: Iterable[EndpointKey]) -> Dict[EndpointKey, Tuple[str, datetime.date]]:
        """Map each known (client, host, port) to (release, snapshot date) of its last scan."""
        wanted = {(client, host, int(port)) for client, host, port in keys}
        if not wanted:
            return {}
        with self._session() as session:
            rows = session.query(ScanState).filter(ScanState.client.in_({key[0] for key in wanted})).all()
            return {
                (row.client, row.host, row.port): (row.templates_version, row.snapshot_date)
                for row in rows
                if (row.client, row.host, row.port) in wanted
            }

    def set_versions(self, keys: Iterable[EndpointKey], version: str, snapshot_date: datetime.date) -> None:
        now = datetime.datetime.now(datetime.timezone.utc)
        with self._session() as session:
            for client, host, port in {(c, h, int(p)) for c, h, p in keys}:
                session.merge(
                    ScanState(
                        client=client,
                        host=host,
                        port=port,
                        templates_version=version,
                        snapshot_date=snapshot_date,
                        scanned_at=now,
                    )
                )
            session.commit()
