"""Risk gates for minimal, auditable healing plans."""
from __future__ import annotations

from .models import Diagnosis, HealingPlan, RiskLevel

MAX_MUTATIONS = 3


def plan_for(diagnosis: Diagnosis) -> HealingPlan:
    risk = diagnosis.classification.risk
    return HealingPlan(
        risk=risk,
        mutation_limit=MAX_MUTATIONS,
        requires_approval=risk is RiskLevel.MEDIUM,
        requires_review=risk in {RiskLevel.HIGH, RiskLevel.BLOCKED},
    )
