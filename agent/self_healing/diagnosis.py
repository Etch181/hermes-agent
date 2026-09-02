"""Diagnosis binds an observed failure to existing verification evidence."""
from __future__ import annotations

from typing import Any, Callable

from .classifier import classify_failure
from .models import Diagnosis


def diagnose(failure: str, *, verification_status: Callable[..., dict[str, Any]], session_id: str | None, workspace: str) -> Diagnosis:
    evidence = verification_status(session_id=session_id, cwd=workspace)
    return Diagnosis(failure=failure, classification=classify_failure(failure), evidence=evidence)
