"""Per-target scan state: the nuclei-templates version a target was last scanned with."""

import datetime
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy import Boolean, Column, DateTime, Integer, MetaData, String, create_engine  # type: ignore
from sqlalchemy.engine import Engine  # type: ignore
from sqlalchemy.orm import declarative_base, sessionmaker  # type: ignore

# Separate metadata, so Artemis' alembic migrations never see this table.
Base = declarative_base(metadata=MetaData())


class ScanState(Base):  # type: ignore
    __tablename__ = "cybercover_scan_state"

    target = Column(String, primary_key=True)
    templates_version = Column(String, nullable=False)
    scanned_at = Column(DateTime(timezone=True), nullable=False)


class DiscoveryState(Base):  # type: ignore
    """The release for which ports of a (client, host) were last discovered."""

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
        engine = _create_engine(conn_str, engine)
        self._session = sessionmaker(bind=engine)
        Base.metadata.create_all(engine)

    def get_version(self, client: str, host: str) -> Optional[str]:
        with self._session() as session:
            row = session.get(DiscoveryState, (client, host))
            return row.templates_version if row else None

    def get_endpoints(self, client: str, host: str) -> List[Tuple[int, str, bool]]:
        with self._session() as session:
            rows = (
                session.query(DiscoveredEndpoint)
                .filter(DiscoveredEndpoint.client == client, DiscoveredEndpoint.host == host)
                .order_by(DiscoveredEndpoint.port)
                .all()
            )
            return [(row.port, row.service, row.ssl) for row in rows]

    def replace(self, client: str, host: str, version: str, endpoints: Iterable[Tuple[int, str, bool]]) -> None:
        """Replace the whole endpoint list of (client, host) with the result of a fresh discovery."""
        with self._session() as session:
            session.query(DiscoveredEndpoint).filter(
                DiscoveredEndpoint.client == client, DiscoveredEndpoint.host == host
            ).delete()
            for port, service, ssl in set(endpoints):
                session.add(DiscoveredEndpoint(client=client, host=host, port=port, service=service, ssl=ssl))
            session.merge(
                DiscoveryState(
                    client=client,
                    host=host,
                    templates_version=version,
                    discovered_at=datetime.datetime.now(datetime.timezone.utc),
                )
            )
            session.commit()


class ScanStateStore:
    def __init__(self, conn_str: Optional[str] = None, engine: Optional[Engine] = None) -> None:
        engine = _create_engine(conn_str, engine)
        self._session = sessionmaker(bind=engine)
        Base.metadata.create_all(engine)

    def get_states(self, targets: Iterable[str]) -> Dict[str, Tuple[str, datetime.datetime]]:
        targets = list(set(targets))
        if not targets:
            return {}
        with self._session() as session:
            rows = session.query(ScanState).filter(ScanState.target.in_(targets)).all()
            return {row.target: (row.templates_version, row.scanned_at) for row in rows}

    def set_versions(self, targets: Iterable[str], version: str) -> None:
        now = datetime.datetime.now(datetime.timezone.utc)
        with self._session() as session:
            for target in set(targets):
                session.merge(ScanState(target=target, templates_version=version, scanned_at=now))
            session.commit()
