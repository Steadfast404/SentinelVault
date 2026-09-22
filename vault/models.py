from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from uuid import uuid4


@dataclass
class Credential:
    site: str
    username: str
    password: str
    notes: str = ""
    id: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = uuid4().hex
        if not self.updated_at:
            self.updated_at = datetime.now(timezone.utc).isoformat()

    def update(self, site: str, username: str, password: str, notes: str = "") -> None:
        self.site = site
        self.username = username
        self.password = password
        self.notes = notes
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> Credential:
        return cls(
            site=data.get("site", ""),
            username=data.get("username", ""),
            password=data.get("password", ""),
            notes=data.get("notes", ""),
            id=data.get("id", ""),
            updated_at=data.get("updated_at", ""),
        )
