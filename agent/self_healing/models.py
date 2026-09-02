"""Small, explicit contracts for bounded self-healing."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class FailureClassification:
    category: str
    risk: RiskLevel
    reason: str


@dataclass(frozen=True)
class Diagnosis:
    failure: str
    classification: FailureClassification
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class HealingPlan:
    risk: RiskLevel
    mutation_limit: int = 3
    requires_approval: bool = False
    requires_review: bool = False


@dataclass(frozen=True)
class HealingResult:
    incident_id: str
    risk: RiskLevel
    resolved: bool
    mutations: int
    verification_status: str
    rolled_back: bool = False
    reason: str = ""
