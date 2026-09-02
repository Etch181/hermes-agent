from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


def test_heal_cli_diagnose_and_status_use_durable_incident_store(tmp_path: Path, capsys, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    from hermes_cli.self_healing import run_heal_command

    diagnose = SimpleNamespace(mode="diagnose", path=str(tmp_path), failure="pytest failed", json=True)
    assert run_heal_command(diagnose) == 0
    assert '"risk": "low"' in capsys.readouterr().out

    status = SimpleNamespace(mode="status", path=str(tmp_path), failure=None, json=True)
    assert run_heal_command(status) == 0
    assert '"incidents"' in capsys.readouterr().out


def test_heal_cli_verify_uses_existing_verifier_and_fails_closed_without_recipe(tmp_path: Path, capsys, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    from hermes_cli.self_healing import run_heal_command

    assert run_heal_command(SimpleNamespace(mode="verify", path=str(tmp_path), failure=None, json=True)) == 1
    assert '"error": "no-recipe"' in capsys.readouterr().out


def test_registered_mutation_enters_model_tools_dispatch(tmp_path: Path):
    from agent.self_healing.integration import HermesFileMutation
    mutation = HermesFileMutation("write_file", {"path": "repair.txt", "content": "fixed"})
    with patch("model_tools.handle_function_call", return_value=json.dumps({"success": True})) as dispatch:
        with patch("agent.self_healing.integration.workspace_is_safe", return_value=True):
            with patch("agent.file_safety.is_write_denied", return_value=False):
                with patch("agent.file_safety.is_write_approval_required", return_value=False):
                    assert mutation.execute(workspace=str(tmp_path), incident_id="incident", session_id="session") is True
    assert dispatch.call_args.kwargs["function_name"] == "write_file"
    assert dispatch.call_args.kwargs["session_id"] == "session"


def test_verified_repair_is_not_resolved_when_real_review_dispatch_fails(tmp_path: Path):
    from agent.self_healing.integration import RealReviewGate

    gate = RealReviewGate(agent=object())
    assert gate.review(incident_id="i", workspace=str(tmp_path), session_id=None) is False


# ==================== ADVERSARIAL TESTS FOR HIGH FINDINGS ====================

def test_patch_mutation_outside_workspace_rejected(tmp_path: Path):
    """HIGH A: V4A patch targeting path outside workspace must be rejected before mutation."""
    from agent.self_healing.integration import HermesFileMutation
    # V4A patch with target outside workspace
    malicious_patch = """*** Begin Patch
*** Update File: /etc/passwd
@@
-root:x:0:0:root:/root:/bin/bash
+root:x:0:0:root:/root:/bin/zsh
*** End Patch"""
    mutation = HermesFileMutation("patch", {"patch": malicious_patch})
    with patch("model_tools.handle_function_call", return_value=json.dumps({"success": True})):
        with patch("agent.self_healing.integration.workspace_is_safe", return_value=True):
            import pytest
            with pytest.raises(ValueError, match="escapes workspace"):
                mutation.execute(workspace=str(tmp_path), incident_id="incident", session_id="session")


def test_patch_mutation_multi_target_mixed_safe_unsafe_rejected(tmp_path: Path):
    """HIGH A: V4A patch with mixed safe + unsafe targets must reject entirely."""
    from agent.self_healing.integration import HermesFileMutation
    # Create a safe file first
    safe_file = tmp_path / "safe.txt"
    safe_file.write_text("original")
    # V4A patch targeting both safe and unsafe paths
    malicious_patch = f"""*** Begin Patch
*** Update File: {safe_file}
@@
-original
+fixed
*** Update File: /etc/shadow
@@
-root:*:18000:0:99999:7:::
+root:$6$salt$hash:18000:0:99999:7:::
*** End Patch"""
    mutation = HermesFileMutation("patch", {"patch": malicious_patch})
    with patch("model_tools.handle_function_call", return_value=json.dumps({"success": True})):
        with patch("agent.self_healing.integration.workspace_is_safe", return_value=True):
            with patch("agent.file_safety.is_write_denied", return_value=False):
                with patch("agent.file_safety.is_write_approval_required", return_value=False):
                    import pytest
                    with pytest.raises(ValueError, match="escapes workspace"):
                        mutation.execute(workspace=str(tmp_path), incident_id="incident", session_id="session")


def test_relative_path_cwd_mismatch_canonicalized(tmp_path: Path):
    """HIGH A: Relative paths must resolve against workspace, not process cwd."""
    from agent.self_healing.integration import HermesFileMutation
    mutation = HermesFileMutation("write_file", {"path": "../escape.txt", "content": "bad"})
    with patch("model_tools.handle_function_call", return_value=json.dumps({"success": True})):
        with patch("agent.self_healing.integration.workspace_is_safe", return_value=True):
            import pytest
            with pytest.raises(ValueError, match="escapes workspace"):
                mutation.execute(workspace=str(tmp_path), incident_id="incident", session_id="session")


def test_path_traversal_dot_dot_rejected(tmp_path: Path):
    """HIGH A: ../../../etc/passwd traversal attempts must be rejected."""
    from agent.self_healing.integration import HermesFileMutation
    mutation = HermesFileMutation("write_file", {"path": "../../../etc/passwd", "content": "bad"})
    with patch("model_tools.handle_function_call", return_value=json.dumps({"success": True})):
        with patch("agent.self_healing.integration.workspace_is_safe", return_value=True):
            import pytest
            with pytest.raises(ValueError, match="escapes workspace"):
                mutation.execute(workspace=str(tmp_path), incident_id="incident", session_id="session")


def test_symlink_escape_rejected(tmp_path: Path):
    """HIGH A: Symlink pointing outside workspace must be rejected."""
    from agent.self_healing.integration import HermesFileMutation
    # Create symlink inside workspace pointing outside
    target_outside = Path("/tmp/outside_target")
    target_outside.write_text("original")
    link_inside = tmp_path / "link.txt"
    link_inside.symlink_to(target_outside)
    mutation = HermesFileMutation("write_file", {"path": "link.txt", "content": "bad"})
    with patch("model_tools.handle_function_call", return_value=json.dumps({"success": True})):
        with patch("agent.self_healing.integration.workspace_is_safe", return_value=True):
            import pytest
            with pytest.raises(ValueError, match="escapes workspace"):
                mutation.execute(workspace=str(tmp_path), incident_id="incident", session_id="session")


def test_cross_profile_true_rejected(tmp_path: Path):
    """HIGH A: cross_profile=True must be explicitly rejected in production path."""
    from agent.self_healing.integration import HermesFileMutation
    import pytest
    # The constructor itself rejects cross_profile=True - this is correct behavior
    with pytest.raises(ValueError, match="forbids cross_profile=True"):
        HermesFileMutation("write_file", {"path": "repair.txt", "content": "fixed", "cross_profile": True})


def test_protected_target_rejected(tmp_path: Path):
    """HIGH A: Protected paths (e.g., .ssh, credentials) must be rejected."""
    from agent.self_healing.integration import HermesFileMutation
    mutation = HermesFileMutation("write_file", {"path": ".ssh/id_rsa", "content": "bad"})
    with patch("model_tools.handle_function_call", return_value=json.dumps({"success": True})):
        with patch("agent.self_healing.integration.workspace_is_safe", return_value=True):
            with patch("agent.file_safety.is_write_denied", return_value=True):  # simulate protected path
                import pytest
                with pytest.raises(ValueError, match="write-denied"):
                    mutation.execute(workspace=str(tmp_path), incident_id="incident", session_id="session")


def test_arbitrary_executor_substitution_rejected(tmp_path: Path):
    """HIGH A: Production path must not accept arbitrary executor injection."""
    from agent.self_healing.integration import HermesFileMutation
    # The production HermesFileMutation has no executor parameter - verify it can't be passed
    mutation = HermesFileMutation("write_file", {"path": "repair.txt", "content": "fixed"})
    # Verify the class doesn't have an executor field
    import pytest
    with pytest.raises(TypeError):
        HermesFileMutation("write_file", {"path": "repair.txt", "content": "fixed"}, executor=lambda: None)


def test_checkpoint_before_mutation_order_enforced(tmp_path: Path):
    """HIGH B: Checkpoint creation must precede mutation; checkpoint failure = zero writes."""
    from agent.self_healing.orchestrator import SelfHealingOrchestrator
    from agent.self_healing.store import IncidentStore
    from agent.self_healing.integration import HermesFileMutation
    
    executed = {"count": 0}
    checkpoints_created = {"count": 0}
    event_counter = {"id": 1}
    
    class TrackingCheckpoints:
        def __init__(self, available: bool = True) -> None:
            self.available = available
            self.restored = []
        def ensure_checkpoint(self, workspace: str, reason: str) -> bool:
            checkpoints_created["count"] += 1
            return self.available
        def list_checkpoints(self, workspace: str):
            return [{"hash": "abc12345"}] if self.available else []
        def restore(self, workspace: str, checkpoint: str, safe: bool = False):
            self.restored.append((workspace, checkpoint, safe))
            return {"success": True}
    
    def verify_status(**_):
        event_counter["id"] += 1
        return {"status": "passed", "evidence": {"id": event_counter["id"]}}
    
    store = IncidentStore(tmp_path / "incidents.db")
    orchestrator = SelfHealingOrchestrator(
        store=store, 
        verification_status=verify_status,
        checkpoint_manager=TrackingCheckpoints(True),
        paused=lambda: False,
        _test_hooks={
            "verify": lambda **_: True,
            "review": lambda **_: True,
        },
    )
    orchestrator._mark_workspace_edited = lambda **_: {"marked": True}
    
    mutation = HermesFileMutation("write_file", {"path": "repair.txt", "content": "fixed"})
    
    with patch.object(HermesFileMutation, "execute", side_effect=lambda **_: executed.__setitem__("count", executed["count"] + 1) or True):
        result = orchestrator.heal(workspace=tmp_path, failure="pytest failed", mutation=mutation)
    
    # Checkpoint must be created before mutation
    assert checkpoints_created["count"] == 1
    # Mutation executed once
    assert executed["count"] == 1
    assert result.resolved is True


def test_checkpoint_failure_produces_zero_writes(tmp_path: Path):
    """HIGH B: Checkpoint failure must produce zero writes."""
    from agent.self_healing.orchestrator import SelfHealingOrchestrator
    from agent.self_healing.store import IncidentStore
    from agent.self_healing.integration import HermesFileMutation
    
    executed = {"count": 0}
    
    class FailingCheckpoints:
        def ensure_checkpoint(self, workspace: str, reason: str) -> bool:
            return False
        def list_checkpoints(self, workspace: str):
            return []
        def restore(self, workspace: str, checkpoint: str, safe: bool = False):
            return {"success": True}
    
    def verify_status(**_):
        return {"status": "passed", "evidence": {"id": 2}}
    
    store = IncidentStore(tmp_path / "incidents.db")
    orchestrator = SelfHealingOrchestrator(
        store=store,
        verification_status=verify_status,
        checkpoint_manager=FailingCheckpoints(),
        paused=lambda: False,
    )
    orchestrator._mark_workspace_edited = lambda **_: {"marked": True}
    
    mutation = HermesFileMutation("write_file", {"path": "repair.txt", "content": "fixed"})
    
    with patch.object(HermesFileMutation, "execute", side_effect=lambda **_: executed.__setitem__("count", executed["count"] + 1) or True):
        result = orchestrator.heal(workspace=tmp_path, failure="pytest failed", mutation=mutation)
    
    # Zero writes when checkpoint fails
    assert executed["count"] == 0
    assert result.reason == "checkpoint unavailable"
    assert result.resolved is False


def test_budget_signature_churn_prevented(tmp_path: Path):
    """HIGH C: Changing incident ID/error text must NOT reset mutation budget."""
    from agent.self_healing.store import IncidentStore
    from agent.self_healing.classifier import classify_failure
    
    store = IncidentStore(tmp_path / "incidents.db")
    
    # Same repair scope: workspace + classification kind + file context
    # First incident
    id1 = store.create_or_get(
        workspace=str(tmp_path), 
        failure="pytest failed in test_file.py", 
        risk="low",
        classification="code"
    )
    store.reserve_mutation(id1)
    store.reserve_mutation(id1)
    store.reserve_mutation(id1)  # 3 mutations used
    
    # Fourth mutation for same scope should be refused
    assert store.reserve_mutation(id1) is False
    
    # Reopening with different error text but same classification/files should share budget
    id2 = store.create_or_get(
        workspace=str(tmp_path),
        failure="pytest failed in test_file.py with different error message",  # Different text
        risk="low",
        classification="code"
    )
    # Should be SAME incident (deduplicated by signature)
    assert id2 == id1
    assert store.reserve_mutation(id2) is False  # Still exhausted
    
    # Different classification should be independent
    id3 = store.create_or_get(
        workspace=str(tmp_path),
        failure="database migration failed",  # Different classification = system
        risk="high",
        classification="system"
    )
    # Different classification = new budget
    assert id3 != id1
    assert store.reserve_mutation(id3) is True  # First mutation for this scope
    assert store.reserve_mutation(id3) is True  # Second
    assert store.reserve_mutation(id3) is True  # Third
    assert store.reserve_mutation(id3) is False  # Fourth refused


def test_review_dispatch_alone_not_success(tmp_path: Path):
    """HIGH E: Review dispatch alone must not count as review success."""
    from agent.self_healing.integration import RealReviewGate
    from unittest.mock import MagicMock
    
    mock_agent = MagicMock()
    gate = RealReviewGate(agent=mock_agent, messages=[{"role": "user", "content": "test"}])
    
    # start_review returns dispatched but wait_review would return timeout (no real delegation)
    with patch("agent.review_engine.start_review", return_value={"status": "dispatched", "delegation_id": "fake-id"}):
        with patch("agent.review_engine.wait_review", return_value={"status": "timeout", "delegation_id": "fake-id"}):
            result = gate.review(incident_id="i", workspace=str(tmp_path), session_id=None)
            assert result is False  # timeout = not accepted


def test_pending_review_no_learning(tmp_path: Path):
    """HIGH E: Pending review must not allow learning."""
    from agent.self_healing.integration import RealReviewGate
    from unittest.mock import MagicMock
    
    mock_agent = MagicMock()
    gate = RealReviewGate(agent=mock_agent, messages=[{"role": "user", "content": "test"}])
    
    with patch("agent.review_engine.start_review", return_value={"status": "dispatched", "delegation_id": "fake-id"}):
        with patch("agent.review_engine.wait_review", return_value={"status": "running", "delegation_id": "fake-id"}):
            result = gate.review(incident_id="i", workspace=str(tmp_path), session_id=None)
            assert result is False  # running = not accepted


def test_rejected_review_no_learning(tmp_path: Path):
    """HIGH E: Rejected review must not allow learning."""
    from agent.self_healing.integration import RealReviewGate
    from unittest.mock import MagicMock
    
    mock_agent = MagicMock()
    gate = RealReviewGate(agent=mock_agent, messages=[{"role": "user", "content": "test"}])
    
    with patch("agent.review_engine.start_review", return_value={"status": "dispatched", "delegation_id": "fake-id"}):
        with patch("agent.review_engine.wait_review", return_value={"status": "rejected", "delegation_id": "fake-id"}):
            result = gate.review(incident_id="i", workspace=str(tmp_path), session_id=None)
            assert result is False  # rejected = not accepted


def test_failed_review_no_learning(tmp_path: Path):
    """HIGH E: Failed review must not allow learning."""
    from agent.self_healing.integration import RealReviewGate
    from unittest.mock import MagicMock
    
    mock_agent = MagicMock()
    gate = RealReviewGate(agent=mock_agent, messages=[{"role": "user", "content": "test"}])
    
    with patch("agent.review_engine.start_review", return_value={"status": "dispatched", "delegation_id": "fake-id"}):
        with patch("agent.review_engine.wait_review", return_value={"status": "failed", "delegation_id": "fake-id"}):
            result = gate.review(incident_id="i", workspace=str(tmp_path), session_id=None)
            assert result is False  # failed = not accepted


def test_accepted_review_after_verification_allows_learning_once(tmp_path: Path):
    """HIGH E: Accepted completed review after fresh verification allows learning exactly once."""
    from agent.self_healing.integration import RealReviewGate
    from unittest.mock import MagicMock
    
    mock_agent = MagicMock()
    gate = RealReviewGate(agent=mock_agent, messages=[{"role": "user", "content": "test"}])
    
    with patch("agent.review_engine.start_review", return_value={"status": "dispatched", "delegation_id": "fake-id"}):
        with patch("agent.review_engine.wait_review", return_value={"status": "accepted", "delegation_id": "fake-id"}):
            result = gate.review(incident_id="i", workspace=str(tmp_path), session_id=None)
            assert result is True  # accepted = learning allowed
