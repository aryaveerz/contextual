import React, { useState, useEffect } from "react";
import { CheckCircle2 } from "lucide-react";
import { submitGateADisposition, authorizeGateBRemediation } from "../services/api";

export default function AuthorizationGate({ receipt, tenantId, onStateChange }) {
  const [gateANotes, setGateANotes] = useState("Human review of bitemporal graph evidence complete.");
  const [gateAStatus, setGateAStatus] = useState(() => {
    if (receipt?.lifecycle_state === "GATE_B_APPROVED" || receipt?.lifecycle_state === "GATE_A_APPROVED") return "APPROVED";
    if (receipt?.lifecycle_state === "GATE_A_REJECTED") return "REJECTED";
    return "PENDING";
  });
  const [gateAResult, setGateAResult] = useState(null);
  const [gateBStatus, setGateBStatus] = useState(() => {
    if (receipt?.lifecycle_state === "GATE_B_APPROVED") return "AUTHORIZED";
    if (receipt?.lifecycle_state === "GATE_A_APPROVED") return "READY_FOR_AUTHORIZATION";
    return "LOCKED";
  });
  const [gateBResult, setGateBResult] = useState(null);
  const [actionError, setActionError] = useState(null);
  const [loadingAction, setLoadingAction] = useState(false);

  const receiptId = receipt?.receipt_id;
  const lifecycleState = receipt?.lifecycle_state;

  useEffect(() => {
    // Reset action-specific mutation results when receipt changes
    setGateAResult(null);
    setGateBResult(null);
    setActionError(null);

    if (lifecycleState === "GATE_B_APPROVED") {
      setGateAStatus("APPROVED");
      setGateBStatus("AUTHORIZED");
    } else if (lifecycleState === "GATE_A_APPROVED") {
      setGateAStatus("APPROVED");
      setGateBStatus("READY_FOR_AUTHORIZATION");
    } else if (lifecycleState === "GATE_A_REJECTED") {
      setGateAStatus("REJECTED");
      setGateBStatus("LOCKED");
    } else {
      setGateAStatus("PENDING");
      setGateBStatus("LOCKED");
    }
  }, [receiptId, lifecycleState]);

  const confirmedReviewer =
    gateAResult?.reviewer_id ||
    receipt?.review_disposition?.reviewer_id ||
    null;

  const confirmedAuthorizer =
    gateBResult?.authorizer_id ||
    receipt?.remediation_proposal?.authorizer_id ||
    null;

  const demoReviewer = tenantId && tenantId.includes("beta") ? "lead-dave-beta" : "analyst-alice-01";
  const demoAuthorizer = tenantId && tenantId.includes("beta") ? "lead-dave-beta" : "lead-carol-01";

  const prStatus =
    gateBResult?.pr_status ||
    receipt?.remediation_proposal?.pr_status ||
    "PENDING";

  const prUrl =
    gateBResult?.pr_url ||
    receipt?.remediation_proposal?.pr_url ||
    null;

  const proposalId =
    gateBResult?.proposal_id ||
    receipt?.remediation_proposal?.proposal_id;

  const handleGateA = async (disposition) => {
    if (!receiptId) {
      setActionError("Cannot submit Gate A disposition without an active decision receipt.");
      return;
    }
    setActionError(null);
    setLoadingAction(true);
    try {
      const res = await submitGateADisposition({ receipt_id: receiptId, disposition, analyst_notes: gateANotes }, tenantId);
      setGateAResult(res);
      setGateAStatus(disposition);
      if (disposition === "APPROVED") {
        setGateBStatus("READY_FOR_AUTHORIZATION");
      } else {
        setGateBStatus("LOCKED");
      }
      if (onStateChange && res.lifecycle_state) {
        onStateChange(res.lifecycle_state);
      }
    } catch (err) {
      setActionError(err.message || "Gate A submission failed.");
    } finally {
      setLoadingAction(false);
    }
  };

  const handleGateB = async () => {
    if (!receiptId) {
      setActionError("Cannot authorize Gate B remediation without an active decision receipt.");
      return;
    }
    setActionError(null);
    setLoadingAction(true);
    try {
      const res = await authorizeGateBRemediation({ receipt_id: receiptId, proposal_action: "REVOKE_IAM_ROLE_ASSIGNMENT" }, tenantId);
      setGateBStatus("AUTHORIZED");
      setGateBResult(res);
      if (onStateChange && res.lifecycle_state) {
        onStateChange(res.lifecycle_state);
      }
    } catch (err) {
      setActionError(err.message || "Gate B authorization failed.");
    } finally {
      setLoadingAction(false);
    }
  };

  return (
    <div className="card-section" style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <div className="card-title">
        <span>Two-Man Governance Cockpit</span>
        <span className="badge badge-cyan">Separation of Duties</span>
      </div>

      {actionError && (
        <div className="error-banner">
          {actionError}
        </div>
      )}

      {/* Gate A Panel */}
      <div className="card-inner-panel">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", color: "var(--accent-world)" }}>
            Gate A: Analyst Review
          </span>
          <span className={`badge ${gateAStatus === "APPROVED" ? "badge-exonerated" : gateAStatus === "REJECTED" ? "badge-culpable" : "badge-degraded"}`} style={{ fontSize: 9 }}>
            {gateAStatus}
          </span>
        </div>

        <div style={{ fontSize: 10, color: "var(--text-muted)" }}>
          {gateAStatus === "APPROVED" ? (
            <>Signed by: <code style={{ color: "var(--text-bright)" }}>{confirmedReviewer || "Reviewer identity unavailable"}</code></>
          ) : (
            <>Acting as: <code style={{ color: "var(--text-bright)" }}>{demoReviewer}</code> (demo session)</>
          )}
        </div>

        <textarea
          value={gateANotes}
          onChange={(e) => setGateANotes(e.target.value)}
          disabled={!receiptId || gateAStatus === "APPROVED" || gateAStatus === "REJECTED"}
          className="input-field"
          style={{ width: "100%", height: 50, resize: "none", fontSize: 11 }}
        />

        <div style={{ display: "flex", gap: 8 }}>
          <button
            type="button"
            onClick={() => handleGateA("APPROVED")}
            disabled={!receiptId || loadingAction || gateAStatus === "APPROVED"}
            className="btn-primary"
            style={{ fontSize: 11, padding: "5px 12px", flex: 1, justifyContent: "center" }}
          >
            Accept Evidence
          </button>
          <button
            type="button"
            onClick={() => handleGateA("REJECTED")}
            disabled={!receiptId || loadingAction || gateAStatus === "REJECTED"}
            className="btn-secondary"
            style={{ fontSize: 11, padding: "5px 12px", flex: 1, justifyContent: "center", color: "var(--verdict-culpable)" }}
          >
            Reject
          </button>
        </div>

        {gateAStatus === "APPROVED" && (
          <div style={{ padding: "6px 8px", background: "var(--verdict-exonerated-bg)", borderRadius: 4, fontSize: 10, color: "var(--verdict-exonerated)", border: "1px solid rgba(16, 185, 129, 0.3)", display: "flex", alignItems: "center", gap: 6, marginTop: 4 }}>
            <CheckCircle2 size={12} color="var(--verdict-exonerated)" />
            <span>
              Evidence Accepted: Signed by {confirmedReviewer || "Reviewer identity unavailable"}{gateAResult?.disposition_id ? ` (${gateAResult.disposition_id.substring(0, 8)})` : ""}. Gate B unlocked.
            </span>
          </div>
        )}

        {gateAStatus === "REJECTED" && (
          <div style={{ padding: "6px 8px", background: "var(--verdict-culpable-bg)", borderRadius: 4, fontSize: 10, color: "var(--verdict-culpable)", border: "1px solid rgba(239, 68, 68, 0.3)", display: "flex", alignItems: "center", gap: 6, marginTop: 4 }}>
            <span>Evidence Rejected: Finding disposition rejected by analyst. Gate B remains locked.</span>
          </div>
        )}
      </div>

      {/* Gate B Panel */}
      <div className="card-inner-panel">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", color: "var(--accent-violet)" }}>
            Gate B: Lead Authorization
          </span>
          <span className={`badge ${gateBStatus === "AUTHORIZED" ? "badge-exonerated" : "badge-degraded"}`} style={{ fontSize: 9 }}>
            {gateBStatus}
          </span>
        </div>

        <div style={{ fontSize: 10, color: "var(--text-muted)" }}>
          {gateBStatus === "AUTHORIZED" ? (
            <>Authorized by: <code style={{ color: "var(--text-bright)" }}>{confirmedAuthorizer || "Authorizer identity unavailable"}</code></>
          ) : (
            <>Required role: <code style={{ color: "var(--text-bright)" }}>lead / admin</code> (Acting as: <code>{demoAuthorizer}</code> (demo session))</>
          )}
        </div>

        <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
          Target Action: <code style={{ color: "var(--text-bright)" }}>REVOKE_IAM_ROLE_ASSIGNMENT</code>
        </div>

        <button
          type="button"
          onClick={handleGateB}
          disabled={!receiptId || gateAStatus !== "APPROVED" || gateBStatus === "AUTHORIZED" || loadingAction}
          className="btn-secondary"
          style={{
            fontSize: 11,
            padding: "6px 12px",
            justifyContent: "center",
            background: gateAStatus === "APPROVED" && gateBStatus !== "AUTHORIZED" ? "var(--accent-violet)" : undefined,
            color: gateAStatus === "APPROVED" && gateBStatus !== "AUTHORIZED" ? "#fff" : undefined,
          }}
        >
          Authorize Remediation Proposal
        </button>

        {gateBStatus === "AUTHORIZED" && (
          <div style={{ padding: "8px 10px", background: "var(--verdict-exonerated-bg)", borderRadius: 4, fontSize: 10, color: "var(--verdict-exonerated)", border: "1px solid rgba(16, 185, 129, 0.3)", display: "flex", flexDirection: "column", gap: 5 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <CheckCircle2 size={12} color="var(--verdict-exonerated)" />
              <span style={{ fontWeight: 600 }}>Remediation Proposal Authorized</span>
            </div>
            {proposalId && (
              <div style={{ color: "var(--text-muted)", fontSize: 10 }}>
                Proposal ID: <code>{proposalId.substring(0, 8)}</code>
              </div>
            )}
            <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 10 }}>
              <span style={{ color: "var(--text-muted)" }}>Execution Status:</span>
              <span className={`badge ${prStatus === "OPEN" ? "badge-exonerated" : "badge-degraded"}`} style={{ fontSize: 9 }}>
                {prStatus}
              </span>
            </div>
            {prUrl ? (
              <div style={{ fontSize: 10 }}>
                PR Tracking: <a href={prUrl} target="_blank" rel="noopener noreferrer" style={{ color: "var(--accent-cyan)", textDecoration: "underline" }}>{prUrl}</a>
              </div>
            ) : (
              <div style={{ fontSize: 10, color: "var(--text-dim)" }}>
                PR Tracking: None (Status: {prStatus}, external PR not created)
              </div>
            )}
            {gateBResult?.note && (
              <div style={{ fontSize: 9, color: "var(--text-dim)", fontStyle: "italic", marginTop: 2 }}>
                {gateBResult.note}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
