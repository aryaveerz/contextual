import React, { useState, useEffect } from "react";
import Header from "./components/Header";
import DualClockSlider from "./components/DualClockSlider";
import GraphCanvas from "./components/GraphCanvas";
import EntityInspector from "./components/EntityInspector";
import SignalInspector from "./components/SignalInspector";
import AuthorizationGate from "./components/AuthorizationGate";
import ReceiptViewer from "./components/ReceiptViewer";
import DecisionHistory from "./components/DecisionHistory";
import { runInvestigation, fetchDecisionHistory } from "./services/api";

const QUICK_EXAMPLES = [
  { label: "Privilege Escalation", findingId: "finding-priv-esc-01", tenantId: "tenant-corp-alpha" },
  { label: "Stale Access Key", findingId: "finding-stale-key-02", tenantId: "tenant-corp-alpha" },
  { label: "Beta Tenant Boundary", findingId: "finding-beta-01", tenantId: "tenant-corp-beta" },
];

// Tenant-to-default-finding mapping
const TENANT_DEFAULT_FINDINGS = {
  "tenant-corp-alpha": "finding-priv-esc-01",
  "tenant-corp-beta": "finding-beta-01",
};

export default function App() {
  const [tenantId, setTenantId] = useState("tenant-corp-alpha");
  const [findingId, setFindingId] = useState("finding-priv-esc-01");
  const [findingInput, setFindingInput] = useState("finding-priv-esc-01");
  const [hasInvestigated, setHasInvestigated] = useState(false);

  const [worldTime, setWorldTime] = useState("Day 5");
  const [knowledgeTime, setKnowledgeTime] = useState("Day 5");

  const [receipt, setReceipt] = useState(null);
  const [loading, setLoading] = useState(false);
  const [findingError, setFindingError] = useState(null);

  // Active right sidebar tab: 'inspector' | 'telemetry' | 'governance' | 'memory'
  const [activeTab, setActiveTab] = useState("telemetry");
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedEdge, setSelectedEdge] = useState(null);

  const [history, setHistory] = useState([]);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [historyError, setHistoryError] = useState(null);

  const loadHistory = async (fid, tid) => {
    if (!fid || !fid.trim()) return;
    setLoadingHistory(true);
    setHistoryError(null);
    try {
      const res = await fetchDecisionHistory(fid.trim(), tid);
      setHistory(res.history || []);
    } catch (err) {
      setHistory([]);
      setHistoryError(err.message || "Failed to load decision history.");
    } finally {
      setLoadingHistory(false);
    }
  };

  const loadInvestigation = async (overrideFindingId) => {
    const fid = overrideFindingId ?? findingId;
    if (!fid.trim()) return;

    setLoading(true);
    setFindingError(null);

    const worldTimeIso = worldTime.includes("Day 5") ? "2026-01-05T00:00:00Z" : "2026-01-02T00:00:00Z";
    const knowledgeTimeIso = knowledgeTime.includes("Day 5") ? "2026-01-05T00:00:00Z" : "2026-01-02T00:00:00Z";

    try {
      const params = {
        finding_id: fid.trim(),
        world_time: worldTimeIso,
        knowledge_time: knowledgeTimeIso,
      };

      const res = await runInvestigation(params, tenantId);
      setReceipt(res);
      setHasInvestigated(true);

      // Automatically select first node if none selected
      if (!selectedNode && res?.graph_evidence?.Q7_full_path?.[0]?.path_nodes?.[0]) {
        setSelectedNode(res.graph_evidence.Q7_full_path[0].path_nodes[0]);
      }

      loadHistory(fid.trim(), tenantId);
    } catch (err) {
      console.error("Investigation error:", err);
      setReceipt(null);
      setHasInvestigated(true); // We tried: show error state not "waiting" state
      setFindingError(err.message || "Investigation failed. Check finding ID and tenant authorization.");
      loadHistory(fid.trim(), tenantId);
    } finally {
      setLoading(false);
    }
  };

  // 300ms debounce on slider / finding / tenant changes
  useEffect(() => {
    const t = setTimeout(() => loadInvestigation(), 300);
    return () => clearTimeout(t);
  }, [tenantId, findingId, worldTime, knowledgeTime]);

  const handlePresetSelect = (preset) => {
    if (preset === "SCENARIO_A") {
      setWorldTime("Day 5");
      setKnowledgeTime("Day 5");
    } else if (preset === "ORIGINAL_DECISION") {
      setWorldTime("Day 2 (T1)");
      setKnowledgeTime("Day 2 (T1)");
    }
  };

  // When tenant changes, auto-switch finding to the tenant's default
  const handleTenantChange = (newTenantId) => {
    const defaultFinding = TENANT_DEFAULT_FINDINGS[newTenantId] || "finding-priv-esc-01";
    setTenantId(newTenantId);
    setFindingId(defaultFinding);
    setFindingInput(defaultFinding);
    setSelectedNode(null);
    setSelectedEdge(null);
    setReceipt(null);
    setHasInvestigated(false);
  };

  const handleFindingSubmit = (e) => {
    e.preventDefault();
    const trimmed = findingInput.trim();
    if (trimmed) {
      setFindingId(trimmed);
      setSelectedNode(null);
      setSelectedEdge(null);
    }
  };

  const applyExample = (ex) => {
    setFindingInput(ex.findingId);
    setFindingId(ex.findingId);
    setTenantId(ex.tenantId);
    setSelectedNode(null);
    setSelectedEdge(null);
    setReceipt(null);
    setHasInvestigated(false);
  };

  const handleNodeClick = (node) => {
    setSelectedNode(node);
    setSelectedEdge(null);
    setActiveTab("inspector");
  };

  const handleEdgeClick = (edge) => {
    setSelectedEdge(edge);
    setSelectedNode(null);
    setActiveTab("inspector");
  };

  return (
    <div className="studio-root">
      {/* 1. Top Header */}
      <Header
        tenantId={tenantId}
        setTenantId={handleTenantChange}
        digest={receipt?.evidence_digest}
      />

      {/* 2. Target Finding Bar */}
      <div
        style={{
          background: "var(--bg-panel)",
          borderBottom: "1px solid var(--border-hairline)",
          padding: "8px 20px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 16,
          flexShrink: 0,
        }}
      >
        <form onSubmit={handleFindingSubmit} style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.5px", color: "var(--text-muted)" }}>
            Investigation Finding:
          </span>
          <input
            id="finding-id-input"
            type="text"
            value={findingInput}
            onChange={(e) => setFindingInput(e.target.value)}
            placeholder="e.g. finding-01"
            className="input-field"
            style={{ width: 180 }}
          />
          <button type="submit" className="btn-primary" style={{ padding: "5px 12px", fontSize: 11 }}>
            {loading ? "Traversing..." : "Investigate"}
          </button>
        </form>

        {/* Quick Example Presets */}
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase" }}>Quick Targets:</span>
          {QUICK_EXAMPLES.map((ex) => (
            <button
              key={ex.findingId}
              type="button"
              className="btn-secondary"
              onClick={() => applyExample(ex)}
              style={{
                fontSize: 10,
                padding: "3px 8px",
                borderColor: findingId === ex.findingId ? "var(--accent-world)" : undefined,
                color: findingId === ex.findingId ? "var(--text-bright)" : undefined,
              }}
            >
              {ex.label}
            </button>
          ))}
        </div>
      </div>

      {/* 3. Dual-Tape Temporal Scrubber */}
      <DualClockSlider
        worldTime={worldTime}
        setWorldTime={setWorldTime}
        knowledgeTime={knowledgeTime}
        setKnowledgeTime={setKnowledgeTime}
        onPresetSelect={handlePresetSelect}
      />

      {/* 4. Split Workstation Body */}
      <div className="studio-body">
        {/* Left: React Flow Graph Canvas */}
        <GraphCanvas
          receipt={receipt}
          worldTime={worldTime}
          knowledgeTime={knowledgeTime}
          selectedNodeId={selectedNode?.id}
          onSelectNode={handleNodeClick}
          onSelectEdge={handleEdgeClick}
          loading={loading}
          hasInvestigated={hasInvestigated}
        />

        {/* Right: Tabbed Cockpit Sidebar */}
        <div className="cockpit-sidebar">
          {/* Tab Navigation Strip */}
          <div className="tab-nav">
            <button
              type="button"
              className={`tab-btn ${activeTab === "inspector" ? "active" : ""}`}
              onClick={() => setActiveTab("inspector")}
            >
              Inspector {selectedNode && <span style={{ display: "inline-block", width: 6, height: 6, borderRadius: "50%", background: "var(--accent-world)", marginLeft: 4 }} />}
            </button>
            <button
              type="button"
              className={`tab-btn ${activeTab === "telemetry" ? "active" : ""}`}
              onClick={() => setActiveTab("telemetry")}
            >
              Policy Matrix
            </button>
            <button
              type="button"
              className={`tab-btn ${activeTab === "governance" ? "active" : ""}`}
              onClick={() => setActiveTab("governance")}
            >
              Governance
            </button>
            <button
              type="button"
              className={`tab-btn ${activeTab === "memory" ? "active" : ""}`}
              onClick={() => setActiveTab("memory")}
            >
              Memory ({history.length})
            </button>
          </div>

          {/* Tab Content Body */}
          <div className="tab-content">
            {findingError && (
              <div className="error-banner">
                {findingError}
              </div>
            )}

            <div style={{ display: activeTab === "inspector" ? "block" : "none" }}>
              <EntityInspector
                selectedNode={selectedNode}
                selectedEdge={selectedEdge}
                receipt={receipt}
              />
            </div>

            <div style={{ display: activeTab === "telemetry" ? "block" : "none" }}>
              <SignalInspector receipt={receipt} />
            </div>

            <div style={{ display: activeTab === "governance" ? "block" : "none" }}>
              <AuthorizationGate
                receipt={receipt}
                tenantId={tenantId}
                onStateChange={(st) => {
                  if (receipt) setReceipt({ ...receipt, lifecycle_state: st });
                }}
              />
            </div>

            <div style={{ display: activeTab === "memory" ? "block" : "none" }}>
              <DecisionHistory
                history={history}
                loading={loadingHistory}
                error={historyError}
                findingId={findingId}
              />
            </div>
          </div>
        </div>
      </div>

      {/* 5. Bottom Dock: Cryptographic Audit Receipt */}
      <ReceiptViewer receipt={receipt} />
    </div>
  );
}