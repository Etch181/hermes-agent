"""Production-only bindings for self-healing safety, review, and learning.

The mutation path deliberately enters :func:`model_tools.handle_function_call`.
That is Hermes' authoritative tool-dispatch lifecycle: plugin middleware, ACP
edit approval, approval observability, and the registered file tool's path /
redaction / write-approval checks all run there.  This module does not offer a
callback escape hatch.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class HermesFileMutation:
    """A single pre-planned file-tool request executed through model_tools."""

    tool_name: str
    arguments: dict[str, Any]
    task_id: str = "self-healing"

    def __post_init__(self) -> None:
        if self.tool_name not in {"write_file", "patch"}:
            raise ValueError("self-healing only permits registered file mutations")
        if not isinstance(self.arguments, dict):
            raise TypeError("file mutation arguments must be a mapping")
        # Production self-healing MUST reject cross_profile=True
        # cross_profile is a caller-controlled escape hatch that bypasses profile isolation.
        if self.arguments.get("cross_profile"):
            raise ValueError("self-healing production mutation forbids cross_profile=True")

    def execute(self, *, workspace: str, incident_id: str, session_id: str | None = None) -> bool:
        """Dispatch via the same model-tool lifecycle as normal agent writes."""
        if not workspace_is_safe(workspace):
            return False
        args = dict(self.arguments)
        
        # Validate ALL target paths before ANY mutation using Hermes' authoritative patch parser
        if self.tool_name == "patch" and args.get("patch"):
            # Full authoritative validation via PatchParser - multi-target pre-validation
            from tools.patch_parser import parse_v4a_patch
            operations, error = parse_v4a_patch(args["patch"])
            if error:
                raise ValueError(f"Invalid V4A patch: {error}")
            # Canonicalize ALL target paths against workspace (TOCTOU/symlink protection)
            # This validates EVERY path in the patch without requiring file I/O
            for op in operations:
                _require_workspace_target(op.file_path, workspace)
                if op.new_path:  # MOVE operations have source and destination
                    _require_workspace_target(op.new_path, workspace)
        else:
            # write_file - validate the explicit path with canonicalization
            target = args.get("path")
            if isinstance(target, str) and target:
                _require_workspace_target(target, workspace)
        
        from model_tools import handle_function_call

        raw = handle_function_call(
            function_name=self.tool_name,
            function_args=args,
            task_id=f"{self.task_id}-{incident_id}",
            session_id=session_id,
        )
        try:
            result = json.loads(raw) if isinstance(raw, str) else raw
        except Exception:
            logger.warning("self-healing file mutation returned non-JSON result")
            return False
        return isinstance(result, dict) and not bool(result.get("error")) and bool(result.get("success", True))

    def _extract_v4a_targets(self, patch_content: str) -> list[str]:
        """Parse V4A patch and extract ALL target file paths for pre-validation."""
        from tools.patch_parser import parse_v4a_patch
        operations, error = parse_v4a_patch(patch_content)
        if error:
            raise ValueError(f"Invalid V4A patch: {error}")
        targets = []
        for op in operations:
            targets.append(op.file_path)
            if op.new_path:  # MOVE operations have source and destination
                targets.append(op.new_path)
        return targets


def _require_workspace_target(target: str, workspace: str) -> None:
    """Canonicalize and validate a target path against workspace root.
    
    Uses Hermes' authoritative path resolution to prevent TOCTOU and symlink bypasses.
    """
    root = Path(workspace).resolve()
    # Use Hermes' authoritative path resolution (mirrors file_tools._resolve_path_for_task)
    candidate = Path(target).expanduser()
    # Resolve against the workspace root for consistency (no relative path ambiguity)
    # This canonicalizes the path, resolving symlinks and ensuring it's within workspace
    resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("self-healing mutation target escapes workspace") from exc
    # Additional safety: verify against file_safety's denied/approval paths
    from agent.file_safety import is_write_denied, is_write_approval_required
    if is_write_denied(str(resolved)):
        raise ValueError(f"self-healing mutation target is write-denied: {resolved}")
    if is_write_approval_required(str(resolved)):
        raise ValueError(f"self-healing mutation target requires approval: {resolved}")


def workspace_is_safe(workspace: str) -> bool:
    """Use the existing file-tool checks before a self-healing mutation."""
    try:
        root = str(Path(workspace).resolve())
        from tools.file_tools import _check_cross_profile_path, _check_sensitive_path
        return not _check_sensitive_path(root) and not _check_cross_profile_path(root)
    except Exception:
        # Safety gate must fail closed when file tooling cannot be inspected.
        logger.warning("self-healing file safety gate unavailable", exc_info=True)
        return False


class RealReviewGate:
    """Wait for Hermes' independent reviewer completion after fresh verification.
    
    Does NOT return success on mere dispatch. Must wait for authoritative review
    completion and acceptance. If Hermes has no safe synchronous completion API,
    FAIL CLOSED.
    """

    def __init__(self, *, agent: Any | None = None, messages: list[dict[str, Any]] | None = None) -> None:
        self.agent = agent
        self.messages = list(messages or [])

    def review(self, *, incident_id: str, workspace: str, session_id: str | None) -> bool:
        if self.agent is None:
            return False
        snapshot = self.messages or [
            {"role": "user", "content": f"Review verified self-healing repair {incident_id} in {workspace}."}
        ]
        try:
            from agent.review_engine import start_review, wait_review
            # Dispatch the review
            result = start_review(self.agent, snapshot, "Verify the repair is safe and complete before it is resolved.")
            if not isinstance(result, dict) or result.get("status") != "dispatched":
                logger.warning("self-healing review dispatch failed: %s", result)
                return False
            # WAIT for authoritative completion - FAIL CLOSED if no wait API
            review_id = result.get("delegation_id")
            if review_id is None:
                logger.error("self-healing review: no delegation_id returned, cannot wait for completion")
                return False
            wait_result = wait_review(self.agent, review_id)
            if not isinstance(wait_result, dict):
                logger.warning("self-healing review wait returned unexpected type: %s", type(wait_result))
                return False
            # Only "accepted" (or equivalent success) allows resolution/learning
            status = wait_result.get("status")
            if status == "accepted":
                return True
            logger.info("self-healing review completed with status: %s", status)
            return False
        except ImportError:
            logger.error("self-healing review: no authoritative wait_review API available - FAIL CLOSED")
            return False
        except Exception:
            logger.warning("self-healing review wait failed", exc_info=True)
            return False


def trigger_conservative_learning(*, agent: Any | None, messages: list[dict[str, Any]] | None) -> bool:
    """Use the existing background-review memory/skill lifecycle, never write directly."""
    if agent is None or not callable(getattr(agent, "_spawn_background_review", None)):
        return False
    try:
        agent._spawn_background_review(
            list(messages or []), review_memory=True, review_skills=True,
            focus="Persist only reusable, conservative lessons from this verified and reviewed self-healing repair.",
        )
        return True
    except Exception:
        logger.warning("self-healing durable learning dispatch failed", exc_info=True)
        return False
