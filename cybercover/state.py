"""Per-target scan state: the nuclei-templates version a target was last scanned with."""

import datetime
from typing import Dict, Iterable, Optional, Tuple

from sqlalchemy import Column, DateTime, MetaData, String, create_engine  # type: ignore
from sqlalchemy.engine import Engine  # type: ignore
from sqlalchemy.orm import declarative_base, sessionmaker  # type: ignore

# Separate metadata, so Artemis' alembic migrations never see this table.
Base = declarative_base(metadata=MetaData())


class ScanState(Base):  # type: ignore
    __tablename__ = "cybercover_scan_state"

    target = Column(String, primary_key=True)
    templates_version = Column(String, nullable=False)
    scanned_at = Column(DateTime(timezone=True), nullable=False)


class ScanStateStore:
    def __init__(self, conn_str: Optional[str] = None, engine: Optional[Engine] = None) -> None:
        if engine is None:
            if conn_str is None:
                from artemis.config import Config

                conn_str = Config.Data.POSTGRES_CONN_STR
            engine = create_engine(conn_str)
        self._session = sessionmaker(bind=engine)
        Base.metadata.create_all(engine)

    def get_states(self, targets: Iterable[str]) -> Dict[str, Tuple[str, datetime.datetime]]:
        targets = list(set(targets))
        if not targets:
            return {}
        with self._session() as session:
            rows = session.query(ScanState).filter(ScanState.target.in_(targets)).all()
            return {row.target: (row.templates_version, row.scanned_at) for row in rows}

    def get_versions(self, targets: Iterable[str]) -> Dict[str, str]:
        return {target: version for target, (version, _) in self.get_states(targets).items()}

    def set_versions(self, targets: Iterable[str], version: str) -> None:
        now = datetime.datetime.now(datetime.timezone.utc)
        with self._session() as session:
            for target in set(targets):
                session.merge(ScanState(target=target, templates_version=version, scanned_at=now))
            session.commit()
