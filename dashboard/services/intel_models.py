from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class ProviderResult:
    """Normalized provider outcome independent of any vendor response schema."""

    provider: str
    status: str
    configured: bool
    data: dict[str, Any] = field(default_factory=dict)
    error_category: str | None = None
    message: str | None = None
    source: str = "live"

    @property
    def available(self) -> bool:
        return self.status == "ok"

    def normalized(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["available"] = self.available
        return payload

    def legacy(self) -> dict[str, Any]:
        """Preserve the established flattened provider response contract."""
        return {
            "provider": self.provider,
            "available": self.available,
            "configured": self.configured,
            **self.data,
            **({"message": self.message} if self.message else {}),
        }
