import React from "react";
import { Search } from "lucide-react";

const ENTITY_COLORS = {
  Finding: "var(--e-finding)",
  NetworkEndpoint: "var(--e-endpoint)",
  Endpoint: "var(--e-endpoint)",
  ServiceInstance: "var(--e-service)",
  Service: "var(--e-service)",
  IAMRole: "var(--e-role)",
  Role: "var(--e-role)",
  SensitiveAsset: "var(--e-asset)",
  Asset: "var(--e-asset)",
  PolicyRule: "var(--e-policy)",
  Rule: "var(--e-policy)",
  DecisionNode: "var(--e-decision)",
  Decision: "var(--e-decision)",
};

export default function EntityInspector({ selectedNode, selectedEdge, receipt }) {
  if (selectedEdge) {
    return (
      <div className="card-section" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <div className="card-title">
          <span>Relationship Inspector</span>
          <span className="badge badge-cyan">{selectedEdge.label || "EDGE"}</span>
        </div>

        <div style={{ padding: "8px 10px", background: "var(--bg-deep)", borderRadius: 5, border: "1px solid var(--border-hairline)" }}>
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>Traversed Topology Hop:</div>
          <div className="font-mono" style={{ fontSize: 12, color: "var(--text-bright)" }}>
            <span style={{ color: "var(--accent-world)" }}>{selectedEdge.source}</span>
            <span style={{ color: "var(--text-dim)", margin: "0 6px" }}>[{selectedEdge.label}] -&gt;</span>
            <span style={{ color: "var(--accent-world)" }}>{selectedEdge.target}</span>
          </div>
        </div>

        <div style={{ fontSize: 11, color: "var(--text-muted)", lineHeight: 1.5 }}>
          This edge was discovered during FalkorDB openCypher bitemporal traversal under active temporal boundaries.
        </div>
      </div>
    );
  }

  if (!selectedNode) {
    return (
      <div className="card-section" style={{ textAlign: "center", padding: "32px 16px", color: "var(--text-muted)" }}>
        <div style={{ display: "flex", justifyContent: "center", marginBottom: 10 }}>
          <Search size={24} color="var(--text-dim)" style={{ opacity: 0.6 }} />
        </div>
        <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-main)", marginBottom: 4 }}>
          No Entity Selected
        </div>
        <div style={{ fontSize: 11, color: "var(--text-dim)", maxWidth: 240, margin: "0 auto", lineHeight: 1.5 }}>
          Click any node or relationship in the FalkorDB canvas to inspect point-in-time properties.
        </div>
      </div>
    );
  }

  const entityType = selectedNode.type || selectedNode.labels?.[0] || "Entity";
  const color = ENTITY_COLORS[entityType] || "var(--text-muted)";
  const validFrom = selectedNode.valid_from || selectedNode.properties?.valid_from;
  const validTo = selectedNode.valid_to || selectedNode.properties?.valid_to || "Open-ended (Present)";
  const discoveredAt = selectedNode.discovered_at || selectedNode.properties?.discovered_at;

  return (
    <div className="card-section" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
          <span style={{ width: 8, height: 8, borderRadius: 2, background: color }} />
          <span style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.5px", color: "var(--text-bright)" }}>
            {entityType}
          </span>
        </div>
        <span className="font-mono" style={{ fontSize: 11, color: "var(--text-dim)" }}>
          {selectedNode.id}
        </span>
      </div>

      {/* Label / Name */}
      <div style={{ padding: "8px 10px", background: "var(--bg-deep)", borderRadius: 5, border: "1px solid var(--border-hairline)" }}>
        <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", marginBottom: 2 }}>
          Node Name / Resource
        </div>
        <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-bright)", wordBreak: "break-all" }}>
          {selectedNode.name || selectedNode.id}
        </div>
      </div>

      {/* Bitemporal Telemetry Box */}
      <div style={{ padding: "10px", background: "var(--bg-deep)", borderRadius: 5, border: "1px solid var(--border-hairline)", display: "flex", flexDirection: "column", gap: 6 }}>
        <div style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.5px", color: "var(--accent-world)" }}>
          Bitemporal Properties
        </div>

        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11 }}>
          <span style={{ color: "var(--text-muted)" }}>valid_from:</span>
          <span className="font-mono" style={{ color: "var(--text-bright)" }}>{validFrom || "N/A"}</span>
        </div>

        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11 }}>
          <span style={{ color: "var(--text-muted)" }}>valid_to:</span>
          <span className="font-mono" style={{ color: "var(--text-bright)" }}>{validTo}</span>
        </div>

        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11 }}>
          <span style={{ color: "var(--text-muted)" }}>discovered_at:</span>
          <span className="font-mono" style={{ color: "var(--accent-knowledge)" }}>{discoveredAt || "N/A"}</span>
        </div>
      </div>

      {/* Tenant Context */}
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, padding: "4px 2px" }}>
        <span style={{ color: "var(--text-muted)" }}>Tenant Boundary:</span>
        <span className="font-mono" style={{ color: "var(--text-dim)" }}>{receipt?.tenant_id || "tenant-corp-alpha"}</span>
      </div>
    </div>
  );
}
