"""``hermes heal`` diagnostic surfaces; no mutation mode is intentionally exposed."""
from __future__ import annotations

import json
import os
from pathlib import Path


def run_heal_command(args) -> int:
    from agent.self_healing import IncidentStore, classify_failure, diagnose
    from agent.verification_evidence import verification_status

    root = Path(getattr(args, "path", None) or ".").resolve()
    if not root.is_dir():
        print(json.dumps({"ok": False, "error": "not-directory", "root": str(root)}))
        return 2
    mode = getattr(args, "mode", "")
    store = IncidentStore()
    if mode == "status":
        payload = {"ok": True, "workspace": str(root), "incidents": store.list(workspace=str(root))}
    elif mode == "diagnose":
        failure = str(getattr(args, "failure", None) or "").strip()
        if not failure:
            print(json.dumps({"ok": False, "error": "--failure is required for diagnose"}))
            return 2
        finding = diagnose(failure, verification_status=verification_status, session_id=os.environ.get("HERMES_SESSION_ID"), workspace=str(root))
        incident_id = store.create_or_get(workspace=str(root), failure=failure, risk=finding.classification.risk.value, payload={"diagnosis": finding.evidence})
        payload = {"ok": True, "incident_id": incident_id, "risk": finding.classification.risk.value, "reason": finding.classification.reason, "evidence": finding.evidence}
    elif mode == "verify":
        from agent.verify import load_or_detect, run_verify
        from agent.verification_evidence import record_verify_run
        recipe, source = load_or_detect(root)
        if recipe is None:
            payload = {"ok": False, "error": "no-recipe", "root": str(root)}
        else:
            result = run_verify(root, recipe)
            record_verify_run(root=root, session_id=os.environ.get("HERMES_SESSION_ID"), ok=result.ok, command="hermes heal verify", output=str(result.to_dict()))
            payload = {"ok": bool(result.ok), "source": source, "result": result.to_dict()}
    else:
        print(json.dumps({"ok": False, "error": f"unknown heal mode: {mode}"}))
        return 2
    print(json.dumps(payload, ensure_ascii=False) if getattr(args, "json", False) else json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload.get("ok") else 1
