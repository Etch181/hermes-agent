"""Bounded, evidence-gated recovery for local agent workspaces."""
from .classifier import classify_failure
from .diagnosis import diagnose
from .models import Diagnosis, FailureClassification, HealingPlan, HealingResult, RiskLevel
from .integration import HermesFileMutation
from .orchestrator import SelfHealingOrchestrator
from .planner import MAX_MUTATIONS, plan_for
from .store import IncidentStore

__all__ = [
    "Diagnosis", "FailureClassification", "HermesFileMutation",
    "HealingPlan", "HealingResult", "IncidentStore", "MAX_MUTATIONS", "RiskLevel",
    "SelfHealingOrchestrator", "classify_failure", "diagnose", "plan_for",
]
