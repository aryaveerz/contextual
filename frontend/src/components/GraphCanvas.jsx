import React, { useState, useMemo } from "react";
import "@xyflow/react/dist/style.css";
import {
  ReactFlow,
  Background,
  Controls,
  MarkerType,
  Handle,
  Position,
} from "@xyflow/react";
import {
  Search,
  Network,
  Table,
  ShieldCheck,
  AlertCircle,
  Activity,
  Layers,
} from "lucide-react";

// Entity type visual configuration - maps each node category to its color and border tokens.
const ENTITY_CONFIG = {
  Finding: {
    label: "Finding",
    color: "#ef4444",
    bg: "rgba(239, 68, 68, 0.1)",
    border: "rgba(239, 68, 68, 0.4)",
  },
  Endpoint: {
    label: "Endpoint",
    color: "#f97316",
    bg: "rgba(249, 115, 22, 0.1)",
    border: "rgba(249, 115, 22, 0.4)",
  },
  Service: {
    label: "Service",
    color: "#3b82f6",
    bg: "rgba(59, 130, 246, 0.1)",
    border: "rgba(59, 130, 246, 0.4)",
  },
  Asset: {
    label: "Asset",
    color: "#06b6d4",
    bg: "rgba(6, 182, 212, 0.1)",
    border: "rgba(6, 182, 212, 0.4)",
  },
  IAMRole: {
    label: "Role",
    color: "#fbbf24",
    bg: "rgba(251, 191, 36, 0.1)",
    border: "rgba(251, 191, 36, 0.4)",
  },
  Rule: {
    label: "Rule",
    color: "#10b981",
    bg: "rgba(16, 185, 129, 0.1)",
    border: "rgba(16, 185, 129, 0.4)",
  },
  Decision: {
    label: "Decision",
    color: "#8b5cf6",
    bg: "rgba(139, 92, 246, 0.1)",
    border: "rgba(139, 92, 246, 0.4)",
  },
};

function resolveEntityType(node) {
  const id = (node?.id || "").toLowerCase();
  const rawType = node?.type || node?.label || node?.labels?.[0] || "";

  if (rawType && ENTITY_CONFIG[rawType]) return rawType;
  if (id.includes("finding") || id.includes("cve")) return "Finding";
  if (id.includes("endpoint") || id.includes("api") || id.includes("ep-")) return "Endpoint";
  if (id.includes("service") || id.includes("svc") || id.includes("gateway")) return "Service";
  if (id.includes("role") || id.includes("iam")) return "IAMRole";
  if (id.includes("asset") || id.includes("db") || id.includes("rds") || id.includes("as-")) return "Asset";
  if (id.includes("rule") || id.includes("policy") || id.includes("r-")) return "Rule";
  if (id.includes("decision") || id.includes("rcpt") || id.includes("d-")) return "Decision";
  if (id.includes("report") || id.includes("rp-")) return "Report";
  if (id.includes("event") || id.includes("ev-")) return "Event";
  return "Endpoint";
}

function getRelColor(relType) {
  const type = (relType || "").toUpperCase();
  if (type.includes("DEPEND") || type.includes("ROUTE")) return "#3b82f6";
  if (type.includes("REACH") || type.includes("AFFECT")) return "#f97316";
  if (type.includes("ASSUME") || type.includes("BASED")) return "#8b5cf6";
  if (type.includes("ACCESS")) return "#ef4444";
  if (type.includes("GOVERN")) return "#10b981";
  if (type.includes("SUPERSEDE")) return "#64748b";
  return "#94a3b8";
}

// Clean horizontal DAG node card matching the design specification
function EntityCardNode({ data }) {
  const { node, entityType, nodeLabel, selected, isDimmed } = data;
  const cfg = ENTITY_CONFIG[entityType] || ENTITY_CONFIG.Endpoint;
  const shortId = node.id?.split("-").slice(-2).join("-") || node.id || "ID";

  return (
    <div
      style={{
        width: 210,
        padding: "8px 12px",
        borderRadius: 6,
        background: "var(--bg-panel)",
        border: `1.5px solid ${selected ? "var(--accent-world)" : cfg.border}`,
        boxShadow: selected
          ? `0 0 16px ${cfg.color}40, 0 4px 12px rgba(0,0,0,0.5)`
          : "0 2px 8px rgba(0,0,0,0.4)",
        cursor: "pointer",
        position: "relative",
        opacity: isDimmed ? 0.25 : 1,
        transition: "all 0.15s ease",
      }}
    >
      <Handle
        type="target"
        position={Position.Left}
        style={{
          width: 7,
          height: 7,
          background: cfg.color,
          border: "2px solid var(--bg-deep)",
          left: -4,
        }}
      />

      {/* Card Header: Solid square + Entity Type + Node ID */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 5 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span
            style={{
              width: 8,
              height: 8,
              borderRadius: 2,
              background: cfg.color,
              display: "inline-block",
            }}
          />
          <span
            style={{
              fontSize: 10,
              fontWeight: 700,
              textTransform: "uppercase",
              letterSpacing: "0.5px",
              color: cfg.color,
              fontFamily: "var(--font-mono)",
            }}
          >
            {cfg.label}
          </span>
        </div>
        <span
          className="font-mono"
          style={{
            fontSize: 10,
            color: "var(--text-dim)",
          }}
        >
          {shortId}
        </span>
      </div>

      {/* Node Resource Identifier */}
      <div
        style={{
          fontSize: 12,
          fontWeight: 600,
          color: "var(--text-bright)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          lineHeight: 1.3,
        }}
        title={nodeLabel}
      >
        {nodeLabel}
      </div>

      <Handle
        type="source"
        position={Position.Right}
        style={{
          width: 7,
          height: 7,
          background: cfg.color,
          border: "2px solid var(--bg-deep)",
          right: -4,
        }}
      />
    </div>
  );
}

const nodeTypes = { entity: EntityCardNode };

export default function GraphCanvas({
  receipt,
  worldTime,
  knowledgeTime,
  selectedNodeId,
  onSelectNode,
  onSelectEdge,
  loading = false,
  hasInvestigated = false,
}) {
  const [searchQuery, setSearchQuery] = useState("");
  const [viewMode, setViewMode] = useState("graph"); // "graph" | "table"
  const [neighborhoodScope, setNeighborhoodScope] = useState("entire"); // "entire" | "target" | "critical"
  const [depth, setDepth] = useState(5);
  const [enabledEntityTypes, setEnabledEntityTypes] = useState({
    Finding: true,
    Endpoint: true,
    Service: true,
    Asset: true,
    IAMRole: true,
    Rule: true,
    Decision: true,
  });
  const [enabledRelTypes, setEnabledRelTypes] = useState({});

  const p1Path = receipt?.signals?.p1_path;
  const isIndeterminate = receipt?.lifecycle_state === "INDETERMINATE" || receipt?.verdict === "INDETERMINATE";
  const isVerifiedNegative = receipt && p1Path === false;
  const verdict = receipt?.verdict || "UNKNOWN";
  const findingId = receipt?.finding_id || "F-1042";

  // 1. Extract raw graph nodes and relationships from receipt evidence
  const rawGraph = useMemo(() => {
    const nodesMap = new Map();
    const edgesList = [];

    // Extract path nodes from Q7_full_path
    const q7Paths = receipt?.graph_evidence?.Q7_full_path || [];
    q7Paths.forEach((pathObj, pIdx) => {
      const pNodes = pathObj.path_nodes || [];
      const pRels = pathObj.relationship_types || [];

      pNodes.forEach((node, nIdx) => {
        if (!nodesMap.has(node.id)) {
          nodesMap.set(node.id, {
            ...node,
            entityType: resolveEntityType(node),
            discovered_at: node.discovered_at,
          });
        }

        if (nIdx < pRels.length) {
          const targetNode = pNodes[nIdx + 1];
          if (targetNode) {
            edgesList.push({
              id: `edge-q7-${pIdx}-${node.id}-${targetNode.id}`,
              source: node.id,
              target: targetNode.id,
              type: pRels[nIdx] || "REACHES",
            });
          }
        }
      });
    });

    // Extract rules from Q2_rules if available
    const rules = receipt?.graph_evidence?.Q2_rules?.rules || [];
    rules.forEach((rule, rIdx) => {
      const ruleId = rule.rule_id || rule.id || `rule-${rIdx}`;
      if (!nodesMap.has(ruleId)) {
        nodesMap.set(ruleId, {
          id: ruleId,
          name: rule.rule_name || rule.name || "Governing Security Policy",
          entityType: "Rule",
          discovered_at: rule.discovered_at,
        });
      }

      // Link rule to role or target asset
      const roleNode = Array.from(nodesMap.values()).find((n) => n.entityType === "IAMRole");
      if (roleNode) {
        edgesList.push({
          id: `edge-rule-${ruleId}-${roleNode.id}`,
          source: ruleId,
          target: roleNode.id,
          type: "GOVERNS",
        });
      }
    });

    // If receipt exists, include the institutional decision node
    if (receipt?.receipt_id) {
      const decId = receipt.receipt_id;
      if (!nodesMap.has(decId)) {
        nodesMap.set(decId, {
          id: decId,
          name: `Decision: ${receipt.verdict || "RECORD"}`,
          entityType: "Decision",
          discovered_at: receipt.created_at,
        });
      }

      const findingNode = Array.from(nodesMap.values()).find((n) => n.entityType === "Finding");
      if (findingNode) {
        edgesList.push({
          id: `edge-dec-${decId}-${findingNode.id}`,
          source: decId,
          target: findingNode.id,
          type: "BASED_ON",
        });
      }
    }

    // Deduplicate edges
    const dedupEdges = [];
    const edgeKeys = new Set();
    edgesList.forEach((e) => {
      const key = `${e.source}->${e.type}->${e.target}`;
      if (!edgeKeys.has(key)) {
        edgeKeys.add(key);
        dedupEdges.push(e);
      }
    });

    return {
      nodes: Array.from(nodesMap.values()),
      edges: dedupEdges,
    };
  }, [receipt]);

  // Compute available entity and relationship counts
  const entityCounts = useMemo(() => {
    const counts = {};
    rawGraph.nodes.forEach((n) => {
      counts[n.entityType] = (counts[n.entityType] || 0) + 1;
    });
    return counts;
  }, [rawGraph.nodes]);

  const relCounts = useMemo(() => {
    const counts = {};
    rawGraph.edges.forEach((e) => {
      counts[e.type] = (counts[e.type] || 0) + 1;
    });
    return counts;
  }, [rawGraph.edges]);

  // Initialize enabled relationship types on load
  React.useEffect(() => {
    const initialRels = {};
    Object.keys(relCounts).forEach((r) => {
      initialRels[r] = true;
    });
    setEnabledRelTypes(initialRels);
  }, [relCounts]);

  // Filtered nodes based on entity types, search query, and neighborhood topological scope
  const filteredNodes = useMemo(() => {
    let allowedNodeIds = null;

    const startId =
      (neighborhoodScope === "target" && selectedNodeId) ||
      rawGraph.nodes.find((n) => n.entityType === "Finding")?.id ||
      rawGraph.nodes[0]?.id;

    if (neighborhoodScope === "critical") {
      const q7Paths = receipt?.graph_evidence?.Q7_full_path || [];
      const critNodeList = [];
      q7Paths.forEach((pathObj) => {
        (pathObj.path_nodes || []).forEach((n) => {
          if (!critNodeList.some((existing) => existing.id === n.id)) {
            critNodeList.push(n);
          }
        });
      });
      if (critNodeList.length === 0) {
        const findingNode = rawGraph.nodes.find((n) => n.entityType === "Finding");
        if (findingNode) critNodeList.push(findingNode);
      }
      const maxChainNodes = Math.min(critNodeList.length, depth + 1);
      allowedNodeIds = new Set(critNodeList.slice(0, maxChainNodes).map((n) => n.id));
    } else {
      if (startId && (depth < 5 || neighborhoodScope === "target")) {
        const adj = new Map();
        rawGraph.edges.forEach((e) => {
          if (!adj.has(e.source)) adj.set(e.source, []);
          if (!adj.has(e.target)) adj.set(e.target, []);
          adj.get(e.source).push(e.target);
          adj.get(e.target).push(e.source);
        });

        const visited = new Map();
        visited.set(startId, 0);
        const queue = [startId];

        while (queue.length > 0) {
          const curr = queue.shift();
          const currDist = visited.get(curr);
          if (currDist < depth) {
            const nbrs = adj.get(curr) || [];
            nbrs.forEach((nbr) => {
              if (!visited.has(nbr)) {
                visited.set(nbr, currDist + 1);
                queue.push(nbr);
              }
            });
          }
        }
        allowedNodeIds = new Set(visited.keys());
      }
    }

    return rawGraph.nodes.filter((node) => {
      if (allowedNodeIds && !allowedNodeIds.has(node.id)) {
        return false;
      }
      const typeEnabled = enabledEntityTypes[node.entityType] !== false;
      const matchesSearch =
        !searchQuery.trim() ||
        (node.id || "").toLowerCase().includes(searchQuery.toLowerCase()) ||
        (node.name || "").toLowerCase().includes(searchQuery.toLowerCase());
      return typeEnabled && matchesSearch;
    });
  }, [rawGraph.nodes, rawGraph.edges, neighborhoodScope, depth, selectedNodeId, receipt, enabledEntityTypes, searchQuery]);

  // Filtered edges
  const filteredEdges = useMemo(() => {
    const visibleNodeIds = new Set(filteredNodes.map((n) => n.id));
    return rawGraph.edges.filter((edge) => {
      const relEnabled = enabledRelTypes[edge.type] !== false;
      const nodesVisible = visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target);
      return relEnabled && nodesVisible;
    });
  }, [rawGraph.edges, filteredNodes, enabledRelTypes]);

  // Build React Flow nodes with horizontal DAG layout
  const rfNodes = useMemo(() => {
    // Categorize nodes into sequential DAG columns
    const columns = {
      Finding: 0,
      Endpoint: 1,
      Service: 2,
      IAMRole: 3,
      Asset: 4,
      Rule: 3,
      Decision: 1,
    };

    const colYOffsets = [0, 0, 0, 0, 0];

    return filteredNodes.map((node, idx) => {
      const colIdx = columns[node.entityType] ?? (idx % 4);
      const x = 40 + colIdx * 280;
      const y = 80 + colYOffsets[colIdx] * 110;
      colYOffsets[colIdx] += 1;

      const isDiscovered = node.discovered_at ? node.discovered_at <= knowledgeTime : true;

      return {
        id: node.id,
        type: "entity",
        position: { x, y },
        data: {
          node,
          entityType: node.entityType,
          nodeLabel: node.name || node.id,
          selected: selectedNodeId === node.id,
          isDimmed: !isDiscovered,
        },
      };
    });
  }, [filteredNodes, selectedNodeId, knowledgeTime]);

  // Build React Flow edges with colored labels
  const rfEdges = useMemo(() => {
    return filteredEdges.map((edge) => {
      const isCulpable = verdict === "CULPABLE";
      const edgeColor = getRelColor(edge.type);

      return {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        label: edge.type,
        animated: isCulpable,
        labelStyle: {
          fill: isCulpable ? "#f43f5e" : "#cbd5e1",
          fontSize: 9,
          fontWeight: 700,
          fontFamily: "var(--font-mono)",
        },
        labelBgStyle: {
          fill: "#12151c",
          stroke: isCulpable ? "rgba(244, 63, 94, 0.5)" : "#232836",
          strokeWidth: 1,
          rx: 4,
          ry: 4,
        },
        labelBgPadding: [6, 3],
        style: {
          stroke: isCulpable ? "#f43f5e" : edgeColor,
          strokeWidth: isCulpable ? 2 : 1.5,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: isCulpable ? "#f43f5e" : edgeColor,
          width: 14,
          height: 14,
        },
      };
    });
  }, [filteredEdges, verdict]);

  const toggleEntityType = (type) => {
    setEnabledEntityTypes((prev) => ({
      ...prev,
      [type]: !prev[type],
    }));
  };

  const toggleRelType = (type) => {
    setEnabledRelTypes((prev) => ({
      ...prev,
      [type]: !prev[type],
    }));
  };

  // Loading state: investigation in flight
  if (loading) {
    return (
      <div className="canvas-area" style={{ alignItems: "center", justifyContent: "center", padding: 32 }}>
        <div style={{ textAlign: "center", maxWidth: 460 }}>
          <div style={{ display: "flex", justifyContent: "center", marginBottom: 16 }}>
            <div style={{
              width: 48, height: 48, borderRadius: "50%",
              border: "3px solid var(--border-hairline)",
              borderTopColor: "var(--accent-world)",
              animation: "spin 0.8s linear infinite",
            }} />
          </div>
          <div style={{ fontSize: 14, fontWeight: 700, color: "var(--text-bright)", marginBottom: 6 }}>
            Running FalkorDB Traversal...
          </div>
          <div style={{ fontSize: 11, color: "var(--text-dim)", lineHeight: 1.6 }}>
            Executing Q1-Q7 openCypher queries against bitemporal graph envelope<br />
            <span style={{ color: "var(--accent-world)" }}>vt: {worldTime}</span> / <span style={{ color: "var(--accent-knowledge)" }}>kt: {knowledgeTime}</span>
          </div>
        </div>
        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      </div>
    );
  }

  // If inconclusive fail-closed error with zero nodes
  if (isIndeterminate && rfNodes.length === 0) {
    return (
      <div className="canvas-area" style={{ alignItems: "center", justifyContent: "center", padding: 32 }}>
        <div style={{ textAlign: "center", maxWidth: 460 }}>
          <div style={{ display: "flex", justifyContent: "center", marginBottom: 12 }}>
            <AlertCircle size={40} color="var(--verdict-degraded)" />
          </div>
          <div style={{ fontSize: 15, fontWeight: 700, color: "var(--verdict-degraded)", marginBottom: 6 }}>
            Query Inconclusive (Fail-Closed)
          </div>
          <div style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: 1.6 }}>
            Graph traversal could not establish certainty with active filters. Per safety invariants, inconclusive evidence fails closed and is never treated as compliant.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="canvas-area">
      {/* 1. Top Graph Toolbar */}
      <div className="canvas-toolbar">
        <div className="top-search-bar">
          <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
            <Search size={13} color="var(--text-dim)" style={{ position: "absolute", left: 8 }} />
            <input
              type="text"
              placeholder="Search ID or name..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="top-search-input"
            />
          </div>

          <span
            className="font-mono"
            style={{
              fontSize: 10,
              padding: "4px 8px",
              borderRadius: 4,
              background: "var(--bg-deep)",
              border: "1px solid var(--border-hairline)",
              color: "var(--text-dim)",
            }}
          >
            Scope: {neighborhoodScope === "entire" ? `subgraph (depth ${depth})` : neighborhoodScope === "target" ? `target neighborhood (depth ${depth})` : `critical vector (depth ${depth})`} - {filteredNodes.length} nodes - {filteredEdges.length} relationships
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          {rfNodes.length > 0 && verdict === "CULPABLE" && (
            <span className="badge badge-culpable" style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
              <AlertCircle size={12} />
              <span>Attack Path Active (Compromise Chain Live)</span>
            </span>
          )}
          {rfNodes.length > 0 && verdict !== "CULPABLE" && (
            <span className="badge badge-exonerated" style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
              <ShieldCheck size={12} />
              <span>Isolated (No Path to Sensitive Asset)</span>
            </span>
          )}

          {/* View Mode Toggle: [ Graph | Table ] */}
          <div className="view-mode-toggle">
            <button
              type="button"
              className={`view-mode-btn ${viewMode === "graph" ? "active" : ""}`}
              onClick={() => setViewMode("graph")}
            >
              <Network size={12} />
              <span>Graph</span>
            </button>
            <button
              type="button"
              className={`view-mode-btn ${viewMode === "table" ? "active" : ""}`}
              onClick={() => setViewMode("table")}
            >
              <Table size={12} />
              <span>Table</span>
            </button>
          </div>
        </div>
      </div>

      {/* 2. Main 2-Panel Workstation (Left Filter Sidebar + Canvas/Table Viewport) */}
      <div className="canvas-body-split">
        {/* Left Facet Filter Sidebar */}
        <div className="facet-sidebar">
          {/* ENTITY TYPES */}
          <div className="facet-group">
            <div className="facet-header">Entity Types</div>
            {Object.keys(ENTITY_CONFIG).map((typeKey) => {
              const cfg = ENTITY_CONFIG[typeKey];
              const count = entityCounts[typeKey] || 0;
              const isChecked = enabledEntityTypes[typeKey] !== false;

              return (
                <div
                  key={typeKey}
                  className="facet-row"
                  onClick={() => toggleEntityType(typeKey)}
                >
                  <div className="facet-left">
                    <input
                      type="checkbox"
                      checked={isChecked}
                      onChange={() => { }}
                      className="facet-checkbox"
                    />
                    <span className="facet-square" style={{ background: cfg.color }} />
                    <span className="facet-label">{cfg.label}</span>
                  </div>
                  <span className="facet-count">{count}</span>
                </div>
              );
            })}
          </div>

          {/* RELATIONSHIPS */}
          <div className="facet-group">
            <div className="facet-header">Relationships</div>
            {Object.keys(relCounts).length === 0 ? (
              <div style={{ fontSize: 10, color: "var(--text-dim)", padding: "4px 6px" }}>
                No active edges
              </div>
            ) : (
              Object.keys(relCounts).map((relKey) => {
                const count = relCounts[relKey];
                const isChecked = enabledRelTypes[relKey] !== false;
                const relColor = getRelColor(relKey);

                return (
                  <div
                    key={relKey}
                    className="facet-row"
                    onClick={() => toggleRelType(relKey)}
                  >
                    <div className="facet-left">
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => { }}
                        className="facet-checkbox"
                      />
                      <span className="facet-square" style={{ background: relColor }} />
                      <span className="facet-label font-mono" style={{ fontSize: 10 }}>
                        {relKey}
                      </span>
                    </div>
                    <span className="facet-count">{count}</span>
                  </div>
                );
              })
            )}
          </div>

          {/* NEIGHBORHOOD */}
          <div className="facet-group">
            <div className="facet-header">Neighborhood</div>
            <select
              value={neighborhoodScope}
              onChange={(e) => setNeighborhoodScope(e.target.value)}
              className="input-field"
              style={{ fontSize: 11, padding: "5px 8px", width: "100%", marginBottom: 8 }}
            >
              <option value="entire">Entire subgraph</option>
              <option value="target">Target finding neighborhood</option>
              <option value="critical">Critical vector only</option>
            </select>

            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--text-dim)", marginBottom: 4 }}>
              <span>Hop Depth</span>
              <span className="font-mono">{depth} / 5</span>
            </div>
            <input
              type="range"
              min="1"
              max="5"
              value={depth}
              onChange={(e) => setDepth(parseInt(e.target.value, 10))}
              className="time-slider"
              style={{ accentColor: "var(--accent-world)" }}
            />
            <div style={{ fontSize: 10, color: "var(--accent-world)", marginTop: 6, lineHeight: 1.35, fontFamily: "var(--font-mono)" }}>
              {depth === 1 && "Hop 1: Finding & direct neighbors (3 nodes)"}
              {depth === 2 && "Hop 2: Extended service topology (4 nodes)"}
              {depth === 3 && "Hop 3: IAM role permissions (5 nodes)"}
              {depth === 4 && "Hop 4: Downstream reachable assets (6 nodes)"}
              {depth >= 5 && "Hop 5: Full subgraph expansion (8 nodes)"}
            </div>
          </div>
        </div>

        {/* Viewport: Either React Flow or Data Table */}
        <div className="canvas-viewport-container">
          {viewMode === "graph" ? (
            rfNodes.length > 0 ? (
              <ReactFlow
                nodes={rfNodes}
                edges={rfEdges}
                nodeTypes={nodeTypes}
                fitView
                minZoom={0.2}
                maxZoom={1.8}
                nodesConnectable={false}
                onNodeClick={(_, node) => onSelectNode(node.data.node)}
                onEdgeClick={(_, edge) => onSelectEdge(edge)}
                proOptions={{ hideAttribution: true }}
              >
                <Background gap={24} size={1} color="var(--border-hairline)" />
                <Controls position="bottom-left" />
              </ReactFlow>
            ) : hasInvestigated ? (
              /* Post-investigation: 0 paths found, clean timeline at this vt/kt */
              <div style={{
                height: "100%", display: "flex", alignItems: "center", justifyContent: "center",
                flexDirection: "column", gap: 12, padding: 32,
              }}>
                <ShieldCheck size={40} color="var(--verdict-exonerated)" style={{ opacity: 0.85 }} />
                <div style={{ fontSize: 14, fontWeight: 700, color: "var(--verdict-exonerated)" }}>
                  Clean Timeline at This Checkpoint
                </div>
                <div style={{
                  fontSize: 11, color: "var(--text-dim)", lineHeight: 1.65,
                  textAlign: "center", maxWidth: 380,
                }}>
                  FalkorDB traversal completed: <strong style={{ color: "var(--text-muted)" }}>no attack paths</strong> reach a sensitive asset
                  under the active bitemporal constraints:<br />
                  <span style={{ color: "var(--accent-world)", fontFamily: "var(--font-mono)" }}>vt: {worldTime}</span>
                  {" "}&amp;{" "}
                  <span style={{ color: "var(--accent-knowledge)", fontFamily: "var(--font-mono)" }}>kt: {knowledgeTime}</span>
                </div>
                <div style={{
                  marginTop: 4, padding: "8px 14px", borderRadius: 6,
                  background: "rgba(16,185,129,0.08)",
                  border: "1px solid rgba(16,185,129,0.2)",
                  fontSize: 11, color: "var(--text-muted)",
                  textAlign: "center",
                }}>
                  Slide to <span style={{ color: "var(--accent-world)", fontWeight: 600 }}>Day 5</span> on the timeline above
                  to see the breach discovery and attack path activation.
                </div>
              </div>
            ) : (
              /* Pre-investigation: first load */
              <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 8, color: "var(--text-muted)" }}>
                <Activity size={28} color="var(--text-dim)" style={{ opacity: 0.6 }} />
                <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-main)" }}>Awaiting Investigation</div>
                <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
                  Select an investigation preset or scrub the timeline above to run live FalkorDB openCypher traversals.
                </div>
              </div>
            )
          ) : (
            /* Table View Mode */
            <div className="table-viewport">
              <div className="data-table-section">
                <div className="data-table-header">
                  <span>Graph Entity Nodes ({filteredNodes.length})</span>
                </div>
                <table className="graph-data-table">
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Identifier (ID)</th>
                      <th>Resource Label</th>
                      <th>Discovered At</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredNodes.map((n) => (
                      <tr key={n.id} onClick={() => onSelectNode(n)} style={{ cursor: "pointer" }}>
                        <td>
                          <span
                            style={{
                              display: "inline-flex",
                              alignItems: "center",
                              gap: 6,
                              fontSize: 10,
                              fontWeight: 700,
                              color: ENTITY_CONFIG[n.entityType]?.color || "var(--text-main)",
                            }}
                          >
                            <span
                              style={{
                                width: 6,
                                height: 6,
                                borderRadius: 2,
                                background: ENTITY_CONFIG[n.entityType]?.color || "var(--text-main)",
                              }}
                            />
                            {n.entityType}
                          </span>
                        </td>
                        <td className="font-mono" style={{ fontSize: 10 }}>{n.id}</td>
                        <td style={{ fontWeight: 600 }}>{n.name || n.id}</td>
                        <td className="font-mono" style={{ fontSize: 10, color: "var(--text-dim)" }}>
                          {n.discovered_at || "Infrastructure Genesis"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="data-table-section">
                <div className="data-table-header">
                  <span>Topology Relationships ({filteredEdges.length})</span>
                </div>
                <table className="graph-data-table">
                  <thead>
                    <tr>
                      <th>Source Node</th>
                      <th>Relationship Type</th>
                      <th>Target Node</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredEdges.map((e) => (
                      <tr key={e.id} onClick={() => onSelectEdge(e)} style={{ cursor: "pointer" }}>
                        <td className="font-mono" style={{ fontSize: 10 }}>{e.source}</td>
                        <td>
                          <span
                            className="font-mono"
                            style={{
                              fontSize: 10,
                              fontWeight: 700,
                              color: getRelColor(e.type),
                              background: "rgba(0,0,0,0.3)",
                              padding: "2px 6px",
                              borderRadius: 3,
                            }}
                          >
                            {e.type}
                          </span>
                        </td>
                        <td className="font-mono" style={{ fontSize: 10 }}>{e.target}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Live Coordinate Tag */}
          <div
            style={{
              position: "absolute",
              bottom: 12,
              right: 14,
              padding: "4px 8px",
              background: "rgba(10, 12, 16, 0.85)",
              border: "1px solid var(--border-hairline)",
              borderRadius: 4,
              fontSize: 10,
              fontFamily: "var(--font-mono)",
              color: "var(--text-dim)",
              pointerEvents: "none",
            }}
          >
            vt: <span style={{ color: "var(--accent-world)" }}>{worldTime}</span> | kt: <span style={{ color: "var(--accent-knowledge)" }}>{knowledgeTime}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
