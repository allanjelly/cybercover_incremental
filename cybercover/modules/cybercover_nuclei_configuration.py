import enum
import re
from typing import Any, Dict, Optional, Tuple

from artemis.modules.runtime_configuration.nuclei_configuration import (
    NucleiConfiguration,
    SeverityThreshold,
)

VERSION_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


class ChangeType(enum.Enum):
    ADDED = "added"
    ADDED_OR_MODIFIED = "added_or_modified"


def parse_version(value: Any) -> Tuple[int, int, int]:
    """Parses a nuclei-templates release tag such as ``v10.5.1``."""
    match = VERSION_RE.match(value) if isinstance(value, str) else None
    if not match:
        raise ValueError(f"Invalid templates version: {value!r} (expected e.g. 'v10.5.1')")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


class CybercoverNucleiConfiguration(NucleiConfiguration):
    """
    Runtime configuration of the cybercover_nuclei module.

    Attributes:
        after_version: nuclei-templates release (e.g. "v10.5.1") of the previous scan; only templates
            added/modified after it are run.
        change_type: whether to consider only new templates or also modified ones.
        severity_threshold: inherited from NucleiConfiguration.
    """

    KEYS = {"after_version", "change_type", "severity_threshold"}

    def __init__(
        self,
        after_version: Optional[str] = None,
        change_type: ChangeType = ChangeType.ADDED_OR_MODIFIED,
        severity_threshold: SeverityThreshold = SeverityThreshold.HIGH_AND_ABOVE,
    ) -> None:
        super().__init__(severity_threshold=severity_threshold)
        self.after_version = after_version
        self.change_type = change_type

    def serialize(self) -> Dict[str, Any]:
        result = super().serialize()
        result["after_version"] = self.after_version
        result["change_type"] = self.change_type.value
        return result

    @classmethod
    def deserialize(cls, config_dict: Dict[str, Any]) -> "CybercoverNucleiConfiguration":
        unexpected = set(config_dict.keys()) - cls.KEYS
        if unexpected:
            raise KeyError(f"Unexpected keys in {config_dict}: {sorted(unexpected)}")

        return cls(
            after_version=config_dict.get("after_version"),
            change_type=ChangeType(config_dict.get("change_type", ChangeType.ADDED_OR_MODIFIED.value)),
            severity_threshold=SeverityThreshold(
                config_dict.get("severity_threshold", SeverityThreshold.HIGH_AND_ABOVE.value)
            ),
        )

    def validate(self) -> bool:
        if not super().validate() or not isinstance(self.change_type, ChangeType) or self.after_version is None:
            return False
        try:
            parse_version(self.after_version)
        except ValueError:
            return False
        return True
