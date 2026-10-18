import React from "react";
import { Activity } from "lucide-react";

export default function SignalInspector({ receipt }) {
  if (!receipt) {
    return (
      <div className="card-section" style={{ textAlign: "center", padding: "32px 16px", color: "var(--text-muted)" }}>
        <div style={{ display: "flex", justifyContent: "center", marginBottom: 8 }}>
          <Activity size={24} color="var(--text-dim)" style={{ opacity: 0.5 }} />
        </div>
        <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-main)" }}>No Telemetry Available</div>
        <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 4 }}>
          Run an investigation to evaluate the 16-row policy truth table.
        </div>
      </div>
    );
  }

  const signals = receipt.signals || {};
  const p1Path = signals.p1_path;
  const p2Role = signals.p2_role;
  const p3Rule = signals.p3_rule;
  const p4Cves = signals.p4_cves ?? 0;
  const verdict = receipt.verdict || "UNKNOWN";
  const reason = receipt.reason || "N/A";

  const verdictBadgeClass =
    verdict === "EXONERATED"
      ? "badge-exonerated"
      : verdict === "CULPABLE"
      ? "badge-culpable"
      : "badge-degraded";

  return (
    <div className="card-section" style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <div className="card-title">
        <span>4-Signal Policy Matrix</span>
        <span className={`badge ${verdictBadgeClass}`}>{verdict}</span>
      </div>

      {/* 4 Signals Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
        {/* P1: Path */}
        <div style={{ padding: "8px 10px", background: "var(--bg-deep)", borderRadius: 5, border: "1px solid var(--border-hairline)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 3 }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: "var(--accent-world)" }}>P1: Attack Path</span>
            <span className={`badge ${p1Path === true ? "badge-culpable" : "badge-exonerated"}`} style={{ fontSize: 9 }}>
              {p1Path === true ? "TRUE" : "FALSE"}
            </span>
          </div>
          <div style={{ fontSize: 10, color: "var(--text-muted)" }}>
            {p1Path === true ? "Active path to DB" : "No reachability path"}
          </div>
        </div>

        {/* P2: Role */}
        <div style={{ padding: "8px 10px", background: "var(--bg-deep)", borderRadius: 5, border: "1px solid var(--border-hairline)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 3 }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: "var(--accent-violet)" }}>P2: Role Match</span>
            <span className={`badge ${p2Role ? "badge-exonerated" : "badge-culpable"}`} style={{ fontSize: 9 }}>
              {p2Role ? "TRUE" : "FALSE"}
            </span>
          </div>
          <div style={{ fontSize: 10, color: "var(--text-muted)" }}>
            {p2Role ? "Role mapped in IAM" : "Shadow role / unmapped"}
          </div>
        </div>

        {/* P3: Rule */}
        <div style={{ padding: "8px 10px", background: "var(--bg-deep)", borderRadius: 5, border: "1px solid var(--border-hairline)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 3 }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: "var(--accent-knowledge)" }}>P3: Policy Rule</span>
            <span className={`badge ${p3Rule ? "badge-exonerated" : "badge-degraded"}`} style={{ fontSize: 9 }}>
              {p3Rule ? "ACTIVE" : "EXPIRED"}
            </span>
          </div>
          <div style={{ fontSize: 10, color: "var(--text-muted)" }}>
            {p3Rule ? "Policy active at decision" : "Rule expired or gap"}
          </div>
        </div>

        {/* P4: CVEs */}
        <div style={{ padding: "8px 10px", background: "var(--bg-deep)", borderRadius: 5, border: "1px solid var(--border-hairline)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 3 }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: "var(--verdict-degraded)" }}>P4: CVE Count</span>
            <span className={`badge ${p4Cves > 0 ? "badge-culpable" : "badge-exonerated"}`} style={{ fontSize: 9 }}>
              {p4Cves} {p4Cves > 0 ? "CVEs" : "CLEAN"}
            </span>
          </div>
          <div style={{ fontSize: 10, color: "var(--text-muted)" }}>
            {p4Cves > 0 ? "Active vulnerability" : "0 active CVEs"}
          </div>
        </div>
      </div>

      {/* Rationale Banner */}
      <div style={{ padding: "10px", background: "var(--bg-deep)", borderRadius: 5, border: "1px solid var(--border-hairline)" }}>
        <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", marginBottom: 3 }}>
          Verified Policy Assembly
        </div>
        <div style={{ fontSize: 11, color: "var(--text-main)", lineHeight: 1.5 }}>
          {reason}
        </div>
      </div>
    </div>
  );
}
