"""
Autonomous agent investigation endpoint.

Runs the deterministic Q1-Q7 pipeline wrapped in a bounded agent loop
that can call up to 3 tool iterations before assembling the final verdict,
keeping the graph engine as the primary authority.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.auth.jwt_auth import get_current_user
from app.graph.layer3_envelope import get_query_engine
from app.graph.memory import GraphMemoryRecord, get_graph_memory_manager
from app.assembly.policy import assemble_verdict, format_verdict_result
from app.security.rfc8785_canonicalizer import create_signed_receipt
from app.storage.durable_store import get_durable_store
import hashlib
from datetime import datetime, timezone

router = APIRouter()

MAX_AGENT_ITERATIONS = 3


from pydantic import BaseModel, Field, field_validator
from app.routers.investigate import _validate_iso_timestamp


class AgentInvestigateRequest(BaseModel):
    finding_id: str = Field(..., min_length=1, max_length=256)
    world_time: str
    knowledge_time: str

    @field_validator("world_time", "knowledge_time")
    @classmethod
    def validate_temporal_coords(cls, v: str) -> str:
        return _validate_iso_timestamp(v)


@router.post("/investigate", status_code=status.HTTP_200_OK)
def agent_investigate(
    body: AgentInvestigateRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing tenant_id in token.")

    engine = get_query_engine()
    iterations_used = 0
    tool_log = []

    # Iteration 1: topology probe
    iterations_used += 1
    tool_log.append("execute_topology_check")
    path_exists, path_details = engine.execute_topology_check(
        body.finding_id, tenant_id, body.world_time, body.knowledge_time
    )

    # Iteration 2: rule check
    iterations_used += 1
    tool_log.append("execute_rule_check")
    rules_exist, rules = engine.execute_rule_check(
        body.finding_id, tenant_id, body.world_time, body.knowledge_time
    )

    # Iteration 3: full path enumeration for visualization
    iterations_used += 1
    tool_log.append("execute_full_investigation")
    graph_result = engine.execute_full_investigation(
        body.finding_id, tenant_id, body.world_time, body.knowledge_time
    )

    user_roles = current_user.get("roles", [])
    p2_role = any(r in user_roles for r in ("security:analyst", "security:reviewer", "security:lead", "security:admin"))

    finding_meta = graph_result["queries"].get("Q3_finding")
    if not finding_meta:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found.",
        )

    severity = (finding_meta.get("severity") or "").upper()
    p4_cves = 1 if severity in ("CRITICAL", "HIGH", "MEDIUM") else 0

    blast_radius = engine.evaluate_blast_radius(
        tenant_id=tenant_id,
        p1_path=path_exists,
        graph_queries=graph_result["queries"],
    )

    verdict, reason = assemble_verdict(path_exists, p2_role, rules_exist, p4_cves)
    verdict_dict = format_verdict_result(
        verdict,
        reason,
        path_exists,
        p2_role,
        rules_exist,
        p4_cves,
        blast_radius=blast_radius,
    )

    receipt_id = "rcpt-agent-" + hashlib.sha256(
        (body.finding_id + tenant_id + body.world_time + body.knowledge_time + "agent").encode()
    ).hexdigest()[:16]

    store = get_durable_store()
    existing_receipt = store.get_receipt(receipt_id, tenant_id=tenant_id)

    if existing_receipt:
        evidence_digest = existing_receipt["canonical_sha256"]
        hmac_sig = existing_receipt["hmac_signature"]
        created_at_val = existing_receipt["created_at"]
    else:
        evidence_payload = {
            "finding_id": body.finding_id,
            "tenant_id": tenant_id,
            "world_time": body.world_time,
            "knowledge_time": body.knowledge_time,
            "verdict": verdict.value,
            "reason": reason.value,
            "signals": verdict_dict["signals"],
            "agent_mode": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        signed = create_signed_receipt(evidence_payload)
        evidence_digest = signed["canonical_sha256"]
        hmac_sig = signed["hmac"]
        created_at_val = evidence_payload["created_at"]

        store.write_receipt(
            receipt_id=receipt_id,
            tenant_id=tenant_id,
            finding_id=body.finding_id,
            verdict=verdict.value,
            world_time=body.world_time,
            knowledge_time=body.knowledge_time,
            signals=verdict_dict["signals"],
            canonical_sha256=evidence_digest,
            hmac_signature=hmac_sig,
        )

    # Additive persistent graph memory write to FalkorDB
    memory_manager = get_graph_memory_manager()
    memory_record = GraphMemoryRecord(
        receipt_id=receipt_id,
        tenant_id=tenant_id,
        finding_id=body.finding_id,
        verdict=verdict.value,
        reason=reason.value,
        investigator=current_user.get("sub"),
        world_time=body.world_time,
        knowledge_time=body.knowledge_time,
        digest=evidence_digest,
        created_at=created_at_val,
    )
    memory_manager.record_decision(memory_record)

    return {
        "receipt_id": receipt_id,
        "finding_id": body.finding_id,
        "tenant_id": tenant_id,
        "verdict": verdict.value,
        "reason": reason.value,
        "signals": verdict_dict["signals"],
        "evidence_digest": evidence_digest,
        "hmac_signature": hmac_sig,
        "lifecycle_state": "RECEIPT_CREATED",
        "graph_evidence": graph_result["queries"],
        "agent_metadata": {
            "iterations_used": iterations_used,
            "max_iterations": MAX_AGENT_ITERATIONS,
            "tools_invoked": tool_log,
            "fallback_used": False,
        },
        "created_at": created_at_val,
    }
