"""
POST /api/investigate: core investigation endpoint.

Runs the full Q1-Q7 query suite against FalkorDB, assembles the 16-row
policy verdict, signs an RFC 8785 canonical receipt, and persists it to the
SQLite WAL store. Rate limiting is enforced by the middleware in main.py.
"""
import hashlib
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.assembly.policy import assemble_verdict, format_verdict_result
from app.auth.jwt_auth import get_current_user
from app.graph.layer3_envelope import get_query_engine
from app.graph.memory import GraphMemoryRecord, get_graph_memory_manager
from app.security.rfc8785_canonicalizer import create_signed_receipt
from app.storage.durable_store import get_durable_store
from app.services.investigation import perform_investigation, FindingNotFoundError

router = APIRouter()


from datetime import datetime
from pydantic import BaseModel, Field, field_validator


def _validate_iso_timestamp(v: str) -> str:
    if not isinstance(v, str) or not v.strip():
        raise ValueError("Timestamp must be a non-empty ISO-8601 string.")
    cleaned = v.strip()
    iso_val = cleaned.replace("Z", "+00:00") if cleaned.endswith("Z") else cleaned
    try:
        dt = datetime.fromisoformat(iso_val)
        if dt.tzinfo is None:
            raise ValueError("Timestamp must include a timezone offset or 'Z'.")
    except Exception as exc:
        raise ValueError(f"Invalid ISO-8601 timestamp '{v}': {exc}") from exc
    return cleaned


class InvestigateRequest(BaseModel):
    finding_id: str = Field(..., min_length=1, max_length=256)
    world_time: str = Field(..., description="ISO-8601 world time (vt)")
    knowledge_time: str = Field(..., description="ISO-8601 knowledge time (kt)")

    @field_validator("world_time", "knowledge_time")
    @classmethod
    def validate_temporal_coords(cls, v: str) -> str:
        return _validate_iso_timestamp(v)


class InvestigateResponse(BaseModel):
    receipt_id: str
    finding_id: str
    tenant_id: str
    verdict: str
    reason: str
    signals: dict
    evidence_digest: str
    hmac_signature: str
    lifecycle_state: str
    graph_evidence: dict
    created_at: str
    review_disposition: Optional[dict] = None
    remediation_proposal: Optional[dict] = None


@router.post(
    "/investigate",
    response_model=InvestigateResponse,
    status_code=status.HTTP_200_OK,
)
def run_investigation(
    body: InvestigateRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing tenant_id in token.")

    try:
        result = perform_investigation(
            finding_id=body.finding_id,
            tenant_id=tenant_id,
            world_time=body.world_time,
            knowledge_time=body.knowledge_time,
            current_user=current_user,
        )
    except FindingNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found.",
        )

    return InvestigateResponse(**result)



class DecisionHistoryItem(BaseModel):
    receipt_id: str
    finding_id: str
    tenant_id: str
    verdict: str
    reason: Optional[str] = None
    investigator: Optional[str] = None
    world_time: str
    knowledge_time: str
    evidence_digest: str
    created_at: str


class DecisionHistoryResponse(BaseModel):
    finding_id: str
    tenant_id: str
    history: list[DecisionHistoryItem]
    count: int


@router.get(
    "/investigate/{finding_id}/history",
    response_model=DecisionHistoryResponse,
    status_code=status.HTTP_200_OK,
)
def get_finding_decision_history(
    finding_id: str,
    request: Request,
    limit: int = 100,
    current_user: dict = Depends(get_current_user),
):
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing tenant_id in token.")

    memory_manager = get_graph_memory_manager()

    # Anti-enumeration IDOR defense: Verify finding exists and belongs to authenticated tenant
    if not memory_manager.finding_exists(finding_id, tenant_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found.",
        )

    try:
        history_records = memory_manager.get_finding_history(finding_id, tenant_id, limit=limit)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query decision history: {exc}",
        )

    return DecisionHistoryResponse(
        finding_id=finding_id,
        tenant_id=tenant_id,
        history=history_records,
        count=len(history_records),
    )



@router.get("/fixtures", status_code=status.HTTP_200_OK)
def list_fixtures():
    """
    Returns the well-known finding IDs loaded by the seeder.
    Lets the frontend pre-populate the investigation form without hardcoded values.
    """
    return {
        "findings": [
            {
                "id": "finding-priv-esc-01",
                "tenant_id": "tenant-corp-alpha",
                "description": "Privilege escalation via over-permissioned IAM role on customer-api",
                "severity": "CRITICAL",
            },
            {
                "id": "finding-stale-key-02",
                "tenant_id": "tenant-corp-alpha",
                "description": "Stale access key on payment-vault service account",
                "severity": "HIGH",
            },
            {
                "id": "finding-beta-01",
                "tenant_id": "tenant-corp-beta",
                "description": "Cross-tenant isolation test finding on beta portal",
                "severity": "MEDIUM",
            },
        ]
    }
