"""
Gate A and Gate B review routers.

Gate A: POST /api/reviews/gate-a/disposition
  An analyst or reviewer submits their human review of a decision receipt.
  Requires role: security:analyst or security:reviewer.

Gate B: POST /api/reviews/gate-b/authorize
  A security lead authorizes a remediation proposal derived from Gate A.
  Requires role: security:lead or security:admin.
  Enforces separation of duties: the Gate B authorizer cannot be the same
  person who submitted the Gate A disposition.
"""
import uuid
from typing import Optional
from urllib.parse import urlparse
import re

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from app.auth.jwt_auth import get_current_user, require_role
from app.config import get_settings
from app.storage.durable_store import get_durable_store

router = APIRouter()


class GateARequest(BaseModel):
    receipt_id: str
    disposition: str  # APPROVED | REJECTED
    analyst_notes: Optional[str] = None


class GateBRequest(BaseModel):
    model_config = {"extra": "allow"}
    receipt_id: str
    proposal_action: Optional[str] = None
    remediation_target: Optional[str] = None
    rollback_safe: Optional[bool] = None


@router.post("/gate-a/disposition", status_code=status.HTTP_201_CREATED)
def submit_gate_a(
    body: GateARequest,
    request: Request,
    current_user: dict = Depends(require_role("security:analyst", "security:reviewer")),
):
    if body.disposition not in ("APPROVED", "REJECTED"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="disposition must be APPROVED or REJECTED.",
        )

    tenant_id = current_user["tenant_id"]
    reviewer_id = current_user["sub"]  # server-derived, never from request body
    store = get_durable_store()

    # Verify the receipt exists and belongs to this tenant (IDOR-safe)
    receipt = store.get_receipt(body.receipt_id, tenant_id)
    if not receipt:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Receipt not found.")

    disposition_id = str(uuid.uuid4())
    store.write_review_disposition(
        disposition_id=disposition_id,
        receipt_id=body.receipt_id,
        tenant_id=tenant_id,
        reviewer_id=reviewer_id,
        disposition=body.disposition,
        analyst_notes=body.analyst_notes,
    )

    return {
        "disposition_id": disposition_id,
        "receipt_id": body.receipt_id,
        "disposition": body.disposition,
        "reviewer_id": reviewer_id,
        "lifecycle_state": "GATE_A_APPROVED" if body.disposition == "APPROVED" else "GATE_A_REJECTED",
    }


@router.post("/gate-b/authorize", status_code=status.HTTP_201_CREATED)
def authorize_gate_b(
    body: GateBRequest,
    request: Request,
    current_user: dict = Depends(require_role("security:lead", "security:admin")),
):
    tenant_id = current_user["tenant_id"]
    authorizer_id = current_user["sub"]  # server-derived identity

    store = get_durable_store()
    settings = get_settings()

    receipt = store.get_receipt(body.receipt_id, tenant_id)
    if not receipt:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Receipt not found.")

    gate_a = store.get_review_disposition(body.receipt_id, tenant_id)
    if not gate_a or gate_a["disposition"] != "APPROVED":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Gate A must be APPROVED before Gate B can proceed.",
        )

    # Separation of duties: authorizer cannot be the same as the Gate A reviewer
    if gate_a["reviewer_id"] == authorizer_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Separation of Duties violation: the Gate B authorizer cannot be the Gate A reviewer.",
            headers={"X-Error-Code": "SEPARATION_OF_DUTIES"},
        )

    proposal_id = str(uuid.uuid4())
    pr_url = None
    pr_status = "PENDING"
    note = "Remediation proposal registered."

    if settings.github_token and settings.github_repo:
        try:
            import httpx
            gh_headers = {
                "Authorization": f"Bearer {settings.github_token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "Contextual-Decision-Defense-Engine",
            }
            gh_resp = httpx.post(
                f"https://api.github.com/repos/{settings.github_repo}/pulls",
                headers=gh_headers,
                json={
                    "title": f"security(remediation): Revoke IAM Role Assignment [{body.receipt_id}]",
                    "head": f"remediation/{proposal_id[:8]}",
                    "base": "main",
                    "body": f"Automated Remediation Authorization from Contextual Decision Defense Engine.\nReceipt ID: {body.receipt_id}\nAuthorizer: {authorizer_id}\nTarget Action: {body.proposal_action or 'REVOKE_IAM_ROLE_ASSIGNMENT'}",
                },
                timeout=5.0,
            )
            if gh_resp.status_code in (200, 201):
                try:
                    gh_data = gh_resp.json()
                except Exception:
                    gh_data = None

                if isinstance(gh_data, dict):
                    raw_url = gh_data.get("html_url")
                    expected_repo = (settings.github_repo or "").strip().strip("/")
                    valid_repo_name = bool(re.fullmatch(r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$", expected_repo))
                    try:
                        parsed_url = urlparse(raw_url) if isinstance(raw_url, str) and raw_url.strip() else None
                        parsed_port = parsed_url.port if parsed_url is not None else None
                    except (ValueError, Exception):
                        parsed_url = None
                        parsed_port = None

                    pr_pattern = rf"^/{re.escape(expected_repo)}/pull/([1-9]\d*)/?$" if valid_repo_name else None

                    is_valid_pr_url = (
                        isinstance(raw_url, str)
                        and bool(raw_url.strip())
                        and parsed_url is not None
                        and parsed_url.scheme.lower() == "https"
                        and parsed_url.netloc.lower() in ("github.com", "github.com:443")
                        and parsed_url.username is None
                        and parsed_url.password is None
                        and (parsed_port is None or parsed_port == 443)
                        and valid_repo_name
                        and pr_pattern is not None
                        and bool(re.fullmatch(pr_pattern, parsed_url.path, re.IGNORECASE))
                    )

                    if is_valid_pr_url:
                        pr_url = raw_url
                        pr_status = "OPEN"
                        note = "Remediation proposal authorized and pull request created on GitHub."
                    else:
                        pr_status = "PENDING"
                        pr_url = None
                        note = f"Remediation proposal authorized. GitHub response lacked a valid HTTPS PR URL for repository '{expected_repo}'; proposal persisted as PENDING."
                else:
                    pr_status = "PENDING"
                    pr_url = None
                    note = "Remediation proposal authorized. GitHub response body was not a valid JSON object; proposal persisted as PENDING."
            else:
                pr_status = "PENDING"
                pr_url = None
                note = f"Remediation proposal authorized. GitHub PR creation returned HTTP {gh_resp.status_code}; proposal persisted as PENDING for review."
        except Exception as exc:
            pr_status = "PENDING"
            pr_url = None
            note = f"Remediation proposal authorized. GitHub integration request failed ({type(exc).__name__}); proposal persisted as PENDING."
    else:
        pr_status = "PENDING"
        pr_url = None
        note = "Remediation proposal authorized. GitHub integration not configured; proposal recorded as PENDING without external pull request."

    store.write_remediation_proposal(
        proposal_id=proposal_id,
        receipt_id=body.receipt_id,
        tenant_id=tenant_id,
        authorizer_id=authorizer_id,
        pr_status=pr_status,
        pr_url=pr_url,
    )

    return {
        "proposal_id": proposal_id,
        "receipt_id": body.receipt_id,
        "authorizer_id": authorizer_id,
        "pr_status": pr_status,
        "pr_url": pr_url,
        "lifecycle_state": "GATE_B_APPROVED",
        "note": note,
    }


@router.get("/{receipt_id}/state", status_code=status.HTTP_200_OK)
def get_review_state(
    receipt_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    IDOR-safe retrieval of the governance review state for a receipt.
    Returns Gate A disposition and Gate B proposal if present.
    """
    tenant_id = current_user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing tenant_id in token.")

    store = get_durable_store()
    receipt = store.get_receipt(receipt_id, tenant_id)
    if not receipt:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Receipt not found.")

    gate_a = store.get_review_disposition(receipt_id, tenant_id)
    gate_b = store.get_remediation_proposal(receipt_id, tenant_id)

    lifecycle_state = "RECEIPT_CREATED"
    if gate_b:
        lifecycle_state = "GATE_B_APPROVED"
    elif gate_a:
        lifecycle_state = "GATE_A_APPROVED" if gate_a["disposition"] == "APPROVED" else "GATE_A_REJECTED"

    return {
        "receipt_id": receipt_id,
        "tenant_id": tenant_id,
        "lifecycle_state": lifecycle_state,
        "gate_a": gate_a,
        "gate_b": gate_b,
    }
