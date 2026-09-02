"""Fail-closed classification for automatic recovery attempts."""
from __future__ import annotations

from .models import FailureClassification, RiskLevel

_BLOCKED = ("secret", "token", "password", "private key", ".ssh", "credential")
_HIGH = ("migration", "database", "deploy", "production", "rm -rf", "network", "permission denied")
_MEDIUM = ("dependency", "install", "lockfile", "configuration", "config")


def classify_failure(failure: str) -> FailureClassification:
    text = (failure or "").lower()
    if any(marker in text for marker in _BLOCKED):
        return FailureClassification("sensitive", RiskLevel.BLOCKED, "failure references sensitive data")
    if any(marker in text for marker in _HIGH):
        return FailureClassification("system", RiskLevel.HIGH, "failure could require unsafe external mutation")
    if any(marker in text for marker in _MEDIUM):
        return FailureClassification("environment", RiskLevel.MEDIUM, "environment changes require approval")
    return FailureClassification("code", RiskLevel.LOW, "bounded local repair candidate")
