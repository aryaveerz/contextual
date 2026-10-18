import React from "react";
import { History } from "lucide-react";

export default function DecisionHistory({ history, loading, error, findingId }) {
  if (loading && history.length === 0) {
    return (
      <div className="card-section" style={{ textAlign: "center", padding: "24px 16px", color: "var(--text-muted)" }}>
        <div style={{ fontSize: 11 }}>Querying FalkorDB decision memory...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card-section" style={{ padding: "12px", color: "var(--verdict-culpable)", fontSize: 11 }}>
        {error}
      </div>
    );
  }

  if (history.length === 0) {
    return (
      <div className="card-section" style={{ textAlign: "center", padding: "24px 16px", color: "var(--text-muted)" }}>
        <div style={{ display: "flex", justifyContent: "center", marginBottom: 8 }}>
          <History size={20} color="var(--text-dim)" style={{ opacity: 0.6 }} />
        </div>
        <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-main)" }}>No Prior Institutional Decisions</div>
        <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 4 }}>
          No prior graph decision nodes linked to finding {findingId}.
        </div>
      </div>
    );
  }

  return (
    <div className="card-section" style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <div className="card-title">
        <span>Graph Decision Memory</span>
        <span className="font-mono" style={{ fontSize: 10, color: "var(--text-dim)" }}>
          {history.length} Prior Run{history.length !== 1 ? "s" : ""}
        </span>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 360, overflowY: "auto" }}>
        {history.map((entry) => {
          const badgeClass =
            entry.verdict === "EXONERATED"
              ? "badge-exonerated"
              : entry.verdict === "CULPABLE"
              ? "badge-culpable"
              : "badge-degraded";

          return (
            <div
              key={entry.receipt_id}
              style={{
                background: "var(--bg-deep)",
                border: "1px solid var(--border-hairline)",
                borderRadius: 5,
                padding: "8px 10px",
                display: "flex",
                flexDirection: "column",
                gap: 4,
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span className="font-mono" style={{ fontSize: 10, color: "var(--accent-world)" }}>
                  {entry.receipt_id}
                </span>
                <span className={`badge ${badgeClass}`} style={{ fontSize: 9 }}>
                  {entry.verdict}
                </span>
              </div>
              {entry.reason && (
                <div style={{ fontSize: 10, color: "var(--text-muted)" }}>{entry.reason}</div>
              )}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 9, color: "var(--text-dim)", marginTop: 2 }}>
                <span>World: {entry.world_time ? entry.world_time.split("T")[0] : "N/A"}</span>
                <span>Knowledge: {entry.knowledge_time ? entry.knowledge_time.split("T")[0] : "N/A"}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
