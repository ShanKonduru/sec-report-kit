from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    source_type: str
    target: str
    severity: str
    vulnerability_id: str
    package: str
    installed_version: str
    fixed_version: str
    title: str
    primary_url: str
