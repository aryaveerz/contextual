import React from "react";

export default function Header({ tenantId, setTenantId, digest, mode }) {
  return (
    <header className="glass-panel" style={{ borderRadius: 0, borderTop: "none", borderLeft: "none", borderRight: "none", display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 24px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
        <div style={{ width: "10px", height: "10px", borderRadius: "50%", background: "#0ea5e9", boxShadow: "0 0 10px #0ea5e9" }} />
        <h1 style={{ fontSize: "18px", fontWeight: "700", letterSpacing: "1px", textTransform: "uppercase" }}>
          Contextual <span style={{ color: "#94a3b8", fontWeight: 400 }}>Bitemporal Audit Defense Console</span>
        </h1>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{ fontSize: "12px", color: "#94a3b8" }}>Tenant:</span>
          <select value={tenantId} onChange={(e) => setTenantId(e.target.value)} style={{ background: "#1a1e28", color: "#f1f5f9", border: "1px solid #232836", borderRadius: "4px", padding: "4px 8px", fontSize: "12px" }}>
            <option value="tenant-corp-alpha">tenant-corp-alpha (Active)</option>
            <option value="tenant-corp-beta">tenant-corp-beta (Cross-Tenant HMAC)</option>
          </select>
        </div>
        {digest && <span className="badge badge-emerald" title={`RFC 8785 SHA-256: ${digest}`}>RFC 8785 Digest: {digest.substring(0, 8)}...</span>}
        <span className="badge badge-cyan">Dual-Clock: FalkorDB 0.4.0</span>
      </div>
    </header>
  );
}
