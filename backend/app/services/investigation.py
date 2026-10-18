"""
Service layer for Contextual investigations.

Single shared investigation execution pipeline used by both REST API
(/api/investigate) and MCP tools (investigate_finding).
Guarantees 100% behavioral, cryptographic, and temporal consistency.
"""
import collections
import hashlib
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from app.assembly.policy import Verdict, assemble_verdict, format_verdict_result
from app.graph.layer3_envelope import get_query_engine
from app.graph.memory import GraphMemoryRecord, get_graph_memory_manager
from app.security.rfc8785_canonicalizer import create_signed_receipt
from app.storage.durable_store import get_durable_store

_RATE_LIMIT_WINDOW = 60          # seconds
_RATE_LIMIT_MAX_REQUESTS = 60    # requests per window
_rate_buckets: Dict[str, collections.deque] = {}


def check_rate_limit(client_key: str) -> Optional[int]:
    """
    Check if a client has exceeded the sliding-window rate limit.
    Returns retry_after in seconds if exceeded, or None if allowed.
    """
    now = time.monotonic()
    window = _rate_buckets.setdefault(client_key, collections.deque())

    while window and window[0] < now - _RATE_LIMIT_WINDOW:
        window.popleft()

    if len(window) >= _RATE_LIMIT_MAX_REQUESTS:
        oldest = window[0]
        retry_after = int(_RATE_LIMIT_WINDOW - (now - oldest)) + 1
        return retry_after

    window.append(now)
    return None


class FindingNotFoundError(Exception):
    """Raised when a finding does not exist for the authenticated tenant."""
    pass


def perform_investigation(
    finding_id: str,
    tenant_id: str,
    world_time: str,
    knowledge_time: str,
    current_user: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Executes the full Q1-Q7 FalkorDB investigation, evaluates truth table verdict,
    persists the authoritative receipt into SQLite, and records graph memory into FalkorDB.
    """
    engine = get_query_engine()
    graph_result = engine.execute_full_investigation(
        finding_id=finding_id,
        tenant_id=tenant_id,
        world_time=world_time,
        knowledge_time=knowledge_time,
    )

    finding_meta = graph_result["queries"].get("Q3_finding")
    if not finding_meta:
        raise FindingNotFoundError(f"Finding '{finding_id}' not found for tenant '{tenant_id}'.")

    p1_path: bool = graph_result["queries"]["Q1_topology"]["path_exists"]
    rules = graph_result["queries"]["Q2_rules"]
    p3_rule: bool = rules["rules_exist"]

    user_roles = current_user.get("roles", [])
    p2_role: bool = any(
        r in user_roles
        for r in ("security:analyst", "security:reviewer", "security:lead", "security:admin")
    )

    severity = (finding_meta.get("severity") or "").upper()
    p4_cves = 1 if severity in ("CRITICAL", "HIGH", "MEDIUM") else 0

    blast_radius = engine.evaluate_blast_radius(
        tenant_id=tenant_id,
        p1_path=p1_path,
        graph_queries=graph_result["queries"],
    )

    verdict, reason = assemble_verdict(p1_path, p2_role, p3_rule, p4_cves)
    verdict_dict = format_verdict_result(
        verdict,
        reason,
        p1_path,
        p2_role,
        p3_rule,
        p4_cves,
        blast_radius=blast_radius,
    )

    receipt_id = "rcpt-" + hashlib.sha256(
        (finding_id + tenant_id + world_time + knowledge_time).encode()
    ).hexdigest()[:16]

    store = get_durable_store()
    existing_receipt = store.get_receipt(receipt_id, tenant_id=tenant_id)

    if existing_receipt:
        evidence_digest = existing_receipt["canonical_sha256"]
        hmac_sig = existing_receipt["hmac_signature"]
        created_at_val = existing_receipt["created_at"]
    else:
        evidence_payload = {
            "finding_id": finding_id,
            "tenant_id": tenant_id,
            "world_time": world_time,
            "knowledge_time": knowledge_time,
            "verdict": verdict.value,
            "reason": reason.value,
            "signals": verdict_dict["signals"],
            "investigator": current_user.get("sub"),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        signed = create_signed_receipt(evidence_payload)
        evidence_digest = signed["canonical_sha256"]
        hmac_sig = signed["hmac"]
        created_at_val = evidence_payload["created_at"]

        store.write_receipt(
            receipt_id=receipt_id,
            tenant_id=tenant_id,
            finding_id=finding_id,
            verdict=verdict.value,
            world_time=world_time,
            knowledge_time=knowledge_time,
            signals=verdict_dict["signals"],
            canonical_sha256=evidence_digest,
            hmac_signature=hmac_sig,
        )

    # Additive persistent graph memory write to FalkorDB
    memory_manager = get_graph_memory_manager()
    memory_record = GraphMemoryRecord(
        receipt_id=receipt_id,
        tenant_id=tenant_id,
        finding_id=finding_id,
        verdict=verdict.value,
        reason=reason.value,
        investigator=current_user.get("sub"),
        world_time=world_time,
        knowledge_time=knowledge_time,
        digest=evidence_digest,
        created_at=created_at_val,
    )
    memory_manager.record_decision(memory_record)

    gate_a = store.get_review_disposition(receipt_id, tenant_id=tenant_id)
    gate_b = store.get_remediation_proposal(receipt_id, tenant_id=tenant_id)

    lifecycle_state = "INDETERMINATE" if verdict == Verdict.INDETERMINATE else "RECEIPT_CREATED"
    if gate_b:
        lifecycle_state = "GATE_B_APPROVED"
    elif gate_a:
        lifecycle_state = "GATE_A_APPROVED" if gate_a.get("disposition") == "APPROVED" else "GATE_A_REJECTED"

    return {
        "receipt_id": receipt_id,
        "finding_id": finding_id,
        "tenant_id": tenant_id,
        "verdict": verdict.value,
        "reason": reason.value,
        "signals": verdict_dict["signals"],
        "evidence_digest": evidence_digest,
        "hmac_signature": hmac_sig,
        "lifecycle_state": lifecycle_state,
        "review_disposition": gate_a,
        "remediation_proposal": gate_b,
        "graph_evidence": graph_result["queries"],
        "created_at": created_at_val,
    }
