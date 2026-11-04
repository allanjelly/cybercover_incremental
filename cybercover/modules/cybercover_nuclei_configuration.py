import datetime
import enum
from typing import Any, Dict, Optional

from artemis.modules.runtime_configuration.nuclei_configuration import (
    NucleiConfiguration,
    SeverityThreshold,
)

MAX_DAYS_BACK = 30


class ChangeType(enum.Enum):
    ADDED = "added"
    ADDED_OR_MODIFIED = "added_or_modified"


def today_utc() -> datetime.date:
    return datetime.datetime.now(datetime.timezone.utc).date()


def parse_after(value: Any) -> datetime.date:
    """Parses ``YYYY-MM-DD`` (or an ISO 8601 datetime, converted to its UTC date)."""
    if isinstance(value, datetime.datetime):
        parsed = value
    elif isinstance(value, datetime.date):
        return value
    elif isinstance(value, str):
        try:
            parsed = datetime.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Invalid 'after' value: {value!r}") from exc
    else:
        raise ValueError(f"Invalid 'after' value: {value!r}")
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(datetime.timezone.utc)
    return parsed.date()


class CybercoverNucleiConfiguration(NucleiConfiguration):
    """
    Runtime configuration of the cybercover_nuclei module.

    Attributes:
        after: only templates added/modified on or after this UTC date are run.
        change_type: whether to consider only new templates or also modified ones.
        severity_threshold: inherited from NucleiConfiguration.
    """

    KEYS = {"after", "change_type", "severity_threshold"}

    def __init__(
        self,
        after: Optional[datetime.date] = None,
        change_type: ChangeType = ChangeType.ADDED_OR_MODIFIED,
        severity_threshold: SeverityThreshold = SeverityThreshold.HIGH_AND_ABOVE,
    ) -> None:
        super().__init__(severity_threshold=severity_threshold)
        self.after = after
        self.change_type = change_type

    def serialize(self) -> Dict[str, Any]:
        result = super().serialize()
        result["after"] = self.after.isoformat() if self.after else None
        result["change_type"] = self.change_type.value
        return result

    @classmethod
    def deserialize(cls, config_dict: Dict[str, Any]) -> "CybercoverNucleiConfiguration":
        unexpected = set(config_dict.keys()) - cls.KEYS
        if unexpected:
            raise KeyError(f"Unexpected keys in {config_dict}: {sorted(unexpected)}")

        after_raw = config_dict.get("after")
        return cls(
            after=parse_after(after_raw) if after_raw is not None else None,
            change_type=ChangeType(config_dict.get("change_type", ChangeType.ADDED_OR_MODIFIED.value)),
            severity_threshold=SeverityThreshold(
                config_dict.get("severity_threshold", SeverityThreshold.HIGH_AND_ABOVE.value)
            ),
        )

    def validate(self) -> bool:
        if not super().validate() or not isinstance(self.change_type, ChangeType) or self.after is None:
            return False
        today = today_utc()
        return today - datetime.timedelta(days=MAX_DAYS_BACK) <= self.after <= today
