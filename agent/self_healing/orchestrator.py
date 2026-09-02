"""Bounded self-healing coordinator using Hermes' established safety seams."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

from .diagnosis import diagnose
from .integration import HermesFileMutation, RealReviewGate, trigger_conservative_learning, workspace_is_safe
from .models import HealingResult, RiskLevel
from .planner import plan_for
from .store import IncidentStore

logger = logging.getLogger(__name__)


class SelfHealingOrchestrator:
    """Attempt only registered file-tool repairs with checkpointed rollback."""

    def __init__(
        self, *, store: IncidentStore | None = None,
        verification_status: Callable[..., dict[str, Any]] | None = None,
        checkpoint_manager: Any = None, paused: Callable[[], bool] | None = None,
        emit: Callable[[Any], None] | None = None, agent: Any | None = None,
        messages: list[dict[str, Any]] | None = None,
        _test_hooks: dict[str, Callable[..., Any]] | None = None,
    ) -> None:
        self.store = store or IncidentStore()
        if verification_status is None:
            from agent.verification_evidence import verification_status as _verification_status
            verification_status = _verification_status
        if paused is None:
            from agent.estop import is_engaged
            paused = is_engaged
        if emit is None:
            from agent.monitoring.emitter import emit as _emit
            emit = _emit
        if checkpoint_manager is None:
            from tools.checkpoint_manager import CheckpointManager
            checkpoint_manager = CheckpointManager(enabled=False)
        from agent.verification_evidence import mark_workspace_edited
        self.verification_status, self.checkpoints, self.paused, self.emit = verification_status, checkpoint_manager, paused, emit
        self.agent, self.messages = agent, list(messages or [])
        self._mark_workspace_edited = mark_workspace_edited
        self._test_hooks = _test_hooks or {}  # private seam, only test fixtures may replace it

    def heal(self, *, workspace: str | Path, failure: str, mutation: HermesFileMutation,
             approved: bool = False, session_id: str | None = None) -> HealingResult:
        if not isinstance(mutation, HermesFileMutation):
            raise TypeError("mutation must be a HermesFileMutation dispatched through model_tools")
        root = str(Path(workspace).resolve())
        diagnosis = diagnose(failure, verification_status=self.verification_status, session_id=session_id, workspace=root)
        plan = plan_for(diagnosis)
        # Pass classification category for stable signature (prevents budget reset via churn)
        incident_id = self.store.create_or_get(workspace=root, failure=failure, risk=plan.risk.value, 
                                                payload={"diagnosis": diagnosis.evidence}, classification=diagnosis.classification.category)
        existing = self.store.get(incident_id) or {}
        mutations = int(existing.get("mutations", 0))
        if existing.get("state") == "resolved":
            return self._result(incident_id, plan.risk, True, mutations, "passed", False, "already resolved")
        self._emit("detected", incident_id, plan.risk)
        if self.paused():
            return self._finish(incident_id, plan.risk, "paused", mutations, "paused by emergency stop")
        if plan.risk in {RiskLevel.HIGH, RiskLevel.BLOCKED}:
            return self._finish(incident_id, plan.risk, "review", mutations, "risk gate requires human review")
        if plan.requires_approval and not approved:
            return self._finish(incident_id, plan.risk, "awaiting_approval", mutations, "medium risk requires approval")
        if not workspace_is_safe(root):
            return self._finish(incident_id, plan.risk, "blocked", mutations, "file safety check denied workspace")
        checkpoint = self._checkpoint(root)
        if checkpoint is None:
            return self._finish(incident_id, plan.risk, "checkpoint_unavailable", mutations, "checkpoint unavailable")
        if not self.store.reserve_mutation(incident_id):
            return self._finish(incident_id, plan.risk, "budget_exhausted", mutations, "persistent mutation budget exhausted")
        mutations = self.store.mutation_count(incident_id)
        try:
            changed = mutation.execute(workspace=root, incident_id=incident_id, session_id=session_id)
        except Exception as exc:
            return self._rollback_finish(incident_id, plan.risk, root, checkpoint, mutations, "mutation failed", {"error": str(exc)})
        if not changed:
            return self._finish(incident_id, plan.risk, "no_change", mutations, "registered mutation made no change")
        try:
            marked = self._mark_workspace_edited(session_id=session_id, cwd=root)
        except Exception as exc:
            return self._rollback_finish(incident_id, plan.risk, root, checkpoint, mutations, "workspace edit was not recorded", {"error": str(exc)})
        if marked is None:
            return self._rollback_finish(incident_id, plan.risk, root, checkpoint, mutations, "workspace edit was not recorded")
        before_event_id = self._event_id(diagnosis.evidence)
        try:
            verification_ran = bool(self._run_verify(workspace=root, session_id=session_id))
            verification = self.verification_status(session_id=session_id, cwd=root)
        except Exception as exc:
            return self._rollback_finish(incident_id, plan.risk, root, checkpoint, mutations, "verification failed", {"error": str(exc)})
        status = str(verification.get("status", "unverified"))
        if not verification_ran or not self._is_fresh_pass(verification, before_event_id):
            return self._rollback_finish(incident_id, plan.risk, root, checkpoint, mutations, "fresh verification did not pass", {"verification_status": status})
        # Review is mandatory and runs after fresh evidence. A failed dispatch is
        # not best-effort: it blocks resolution and all durable learning.
        if not self._run_review(incident_id=incident_id, workspace=root, session_id=session_id):
            return self._rollback_finish(incident_id, plan.risk, root, checkpoint, mutations, "independent review failed")
        self.store.update(incident_id, state="resolved", mutations=mutations, payload={"verification_status": status, "review": "dispatched"})
        self._emit("resolved", incident_id, plan.risk)
        self._learn(incident_id=incident_id, workspace=root, session_id=session_id)
        return self._result(incident_id, plan.risk, True, mutations, status, False, "fresh verification and review passed")

    @staticmethod
    def _event_id(status: dict[str, Any] | None) -> int | None:
        evidence = (status or {}).get("evidence")
        event_id = evidence.get("id") if isinstance(evidence, dict) else None
        return event_id if isinstance(event_id, int) else None

    def _is_fresh_pass(self, status: dict[str, Any], before_event_id: int | None) -> bool:
        return status.get("status") == "passed" and (event_id := self._event_id(status)) is not None and event_id != before_event_id

    def _run_review(self, **kwargs: Any) -> bool:
        hook = self._test_hooks.get("review")
        if hook is not None:
            return bool(hook(**kwargs))
        return RealReviewGate(agent=self.agent, messages=self.messages).review(**kwargs)

    def _learn(self, **kwargs: Any) -> bool:
        hook = self._test_hooks.get("learning")
        if hook is not None:
            return bool(hook(**kwargs))
        return trigger_conservative_learning(agent=self.agent, messages=self.messages)

    def _run_verify(self, *, workspace: str, session_id: str | None = None) -> bool:
        hook = self._test_hooks.get("verify")
        if hook is not None:
            return bool(hook(workspace=workspace, session_id=session_id))
        from agent.verify import load_or_detect, run_verify
        from agent.verification_evidence import record_verify_run
        recipe, _ = load_or_detect(Path(workspace))
        if recipe is None:
            return False
        result = run_verify(Path(workspace), recipe)
        record_verify_run(root=Path(workspace), session_id=session_id, ok=result.ok, output=str(result.to_dict()))
        return bool(result.ok)

    def _checkpoint(self, workspace: str) -> str | None:
        try:
            if not self.checkpoints.ensure_checkpoint(workspace, "self-healing pre-mutation"):
                return None
            entries = self.checkpoints.list_checkpoints(workspace)
            value = entries[0].get("hash") if entries else None
            return value if isinstance(value, str) and value else None
        except Exception:
            logger.warning("self-healing checkpoint unavailable", exc_info=True)
            return None

    def _rollback_finish(self, incident_id: str, risk: RiskLevel, workspace: str, checkpoint: str, mutations: int, reason: str, payload: dict[str, Any] | None = None) -> HealingResult:
        rolled_back = self._rollback(workspace, checkpoint)
        state = "rolled_back" if rolled_back else "failed"
        self.store.update(incident_id, state=state, mutations=mutations, payload=payload)
        self._emit(state, incident_id, risk)
        return self._result(incident_id, risk, False, mutations, "failed", rolled_back, reason)

    def _rollback(self, workspace: str, checkpoint: str) -> bool:
        try:
            return bool(self.checkpoints.restore(workspace, checkpoint, safe=True).get("success"))
        except Exception:
            logger.warning("self-healing safe rollback failed", exc_info=True)
            return False

    def _finish(self, incident_id: str, risk: RiskLevel, state: str, mutations: int, reason: str) -> HealingResult:
        self.store.update(incident_id, state=state, mutations=mutations)
        self._emit(state, incident_id, risk)
        return self._result(incident_id, risk, False, mutations, state, False, reason)

    @staticmethod
    def _result(incident_id: str, risk: RiskLevel, resolved: bool, mutations: int, verification_status: str, rolled_back: bool, reason: str) -> HealingResult:
        return HealingResult(incident_id, risk, resolved, mutations, verification_status, rolled_back, reason)

    def _emit(self, state: str, incident_id: str, risk: RiskLevel) -> None:
        try:
            self.emit({"event": "self_healing", "state": state, "incident_id": incident_id, "risk": risk.value})
        except Exception:
            pass
