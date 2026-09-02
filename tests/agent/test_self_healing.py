from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from agent.self_healing.integration import HermesFileMutation
from agent.self_healing.models import RiskLevel
from agent.self_healing.orchestrator import SelfHealingOrchestrator
from agent.self_healing.store import IncidentStore


class _Checkpoints:
    def __init__(self, available: bool = True) -> None:
        self.available, self.restored = available, []
    def ensure_checkpoint(self, workspace: str, reason: str) -> bool: return self.available
    def list_checkpoints(self, workspace: str): return [{"hash": "abc12345"}] if self.available else []
    def restore(self, workspace: str, checkpoint: str, safe: bool = False):
        self.restored.append((workspace, checkpoint, safe)); return {"success": True}


def _status(value: str, event_id: int | None = None):
    return {"status": value, "evidence": {"id": event_id} if event_id is not None else None}


def _orchestrator(tmp_path: Path, statuses, checkpoints=None, store=None, **hooks):
    calls = []
    def verify_status(**_):
        calls.append(1); return statuses[min(len(calls) - 1, len(statuses) - 1)]
    result = SelfHealingOrchestrator(
        store=store or IncidentStore(tmp_path / "incidents.db"), verification_status=verify_status,
        checkpoint_manager=checkpoints or _Checkpoints(), paused=lambda: False,
        _test_hooks=hooks,
    )
    result._mark_workspace_edited = lambda **_: {"marked": True}
    return result


def _mutation() -> HermesFileMutation:
    return HermesFileMutation("write_file", {"path": "repair.txt", "content": "fixed"})


def test_arbitrary_mutation_callback_is_rejected(tmp_path: Path):
    with pytest.raises(TypeError, match="HermesFileMutation"):
        _orchestrator(tmp_path, [_status("stale", 1)]).heal(workspace=tmp_path, failure="pytest failed", mutation=lambda: True)  # type: ignore[arg-type]


def test_checkpoint_is_mandatory_before_registered_mutation(tmp_path: Path):
    with patch.object(HermesFileMutation, "execute") as execute:
        result = _orchestrator(tmp_path, [_status("stale", 1)], _Checkpoints(False)).heal(workspace=tmp_path, failure="pytest failed", mutation=_mutation())
    assert result.reason == "checkpoint unavailable"
    execute.assert_not_called()


def test_resolution_requires_fresh_verification_then_review_before_learning(tmp_path: Path):
    seen = []
    hooks = {"verify": lambda **_: True, "review": lambda **_: seen.append("review") or True, "learning": lambda **_: seen.append("learning") or True}
    with patch.object(HermesFileMutation, "execute", return_value=True):
        result = _orchestrator(tmp_path, [_status("stale", 1), _status("passed", 2)], **hooks).heal(workspace=tmp_path, failure="pytest failed", mutation=_mutation())
    assert result.resolved is True
    assert seen == ["review", "learning"]


def test_review_failure_rolls_back_and_never_learns(tmp_path: Path):
    checkpoints, learned = _Checkpoints(), []
    with patch.object(HermesFileMutation, "execute", return_value=True):
        result = _orchestrator(tmp_path, [_status("stale", 1), _status("passed", 2)], checkpoints, verify=lambda **_: True, review=lambda **_: False, learning=lambda **_: learned.append(True)).heal(workspace=tmp_path, failure="pytest failed", mutation=_mutation())
    assert not result.resolved and result.rolled_back and learned == []
    assert checkpoints.restored == [(str(tmp_path.resolve()), "abc12345", True)]


def test_high_risk_never_mutates(tmp_path: Path):
    with patch.object(HermesFileMutation, "execute") as execute:
        result = _orchestrator(tmp_path, [_status("stale", 1)]).heal(workspace=tmp_path, failure="database migration failed", mutation=_mutation())
    assert result.risk is RiskLevel.HIGH and result.mutations == 0
    execute.assert_not_called()


def test_budget_is_persistent_and_redacts_durable_failure(tmp_path: Path):
    store, mutation = IncidentStore(tmp_path / "incidents.db"), _mutation()
    with patch.object(HermesFileMutation, "execute", return_value=False) as execute:
        for _ in range(4):
            _orchestrator(tmp_path, [_status("stale", 1)], store=store).heal(workspace=tmp_path, failure="pytest failed", mutation=mutation)
    incident = store.list(workspace=str(tmp_path.resolve()))[0]
    redacted_id = store.create_or_get(workspace=str(tmp_path.resolve()) + "/other", failure="pytest failed TOKEN=sk-secret", risk="low")
    assert incident["mutations"] == 3
    assert "sk-secret" not in store.get(redacted_id)["failure"]
    assert execute.call_count == 3
