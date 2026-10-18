import React from "react";
import { AlertTriangle } from "lucide-react";

export default function DualClockSlider({
  worldTime,
  setWorldTime,
  knowledgeTime,
  setKnowledgeTime,
  onPresetSelect,
}) {
  const isBlindspotActive =
    (knowledgeTime.includes("Day 5") || knowledgeTime.includes("05")) &&
    (worldTime.includes("Day 2") || worldTime.includes("02"));

  const vtDateLabel = worldTime.includes("Day 5") ? "2026-01-05T00:00:00Z" : "2026-01-02T00:00:00Z";
  const ktDateLabel = knowledgeTime.includes("Day 5") ? "2026-01-05T00:00:00Z" : "2026-01-02T00:00:00Z";

  return (
    <div className="scrubber-deck">
      <div className="scrubber-header">
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.6px", color: "var(--text-bright)" }}>
            Bitemporal Timeline Deck
          </span>
          <span style={{ fontSize: 11, color: "var(--text-dim)" }}>
            (Independent World Reality vs Knowledge Cutoff Slicing)
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {isBlindspotActive && (
            <span className="blindspot-pill" style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
              <AlertTriangle size={11} color="var(--accent-knowledge)" />
              <span>Blindspot Delta: +72h Unmonitored</span>
            </span>
          )}

          <button
            type="button"
            className="btn-secondary"
            onClick={() => onPresetSelect("ORIGINAL_DECISION")}
          >
            Baseline (Jan 02)
          </button>

          <button
            type="button"
            className="btn-secondary"
            onClick={() => onPresetSelect("SCENARIO_A")}
          >
            Breach Discovery (Jan 05)
          </button>
        </div>
      </div>

      <div className="scrubber-track-row">
        {/* Track 1: World Time (vt) */}
        <div className="time-track">
          <div className="time-track-label">
            <span style={{ color: "var(--text-muted)" }}>
              World Validity Time (<span style={{ color: "var(--accent-world)" }}>vt</span>) - Infrastructure State:
            </span>
            <span className="font-mono" style={{ color: "var(--accent-world)", fontWeight: 600 }}>
              {vtDateLabel} ({worldTime})
            </span>
          </div>
          <input
            type="range"
            min="2"
            max="5"
            step="3"
            value={worldTime.includes("Day 5") ? 5 : 2}
            onChange={(e) => setWorldTime(e.target.value === "2" ? "Day 2 (T1)" : "Day 5")}
            className="time-slider"
            style={{ accentColor: "var(--accent-world)" }}
          />
        </div>

        {/* Track 2: Knowledge Time (kt) */}
        <div className="time-track">
          <div className="time-track-label">
            <span style={{ color: "var(--text-muted)" }}>
              Knowledge Cutoff Time (<span style={{ color: "var(--accent-knowledge)" }}>kt</span>) - Scanner State:
            </span>
            <span className="font-mono" style={{ color: "var(--accent-knowledge)", fontWeight: 600 }}>
              {ktDateLabel} ({knowledgeTime})
            </span>
          </div>
          <input
            type="range"
            min="2"
            max="5"
            step="3"
            value={knowledgeTime.includes("Day 5") ? 5 : 2}
            onChange={(e) => setKnowledgeTime(e.target.value === "2" ? "Day 2 (T1)" : "Day 5")}
            className="time-slider"
            style={{ accentColor: "var(--accent-knowledge)" }}
          />
        </div>
      </div>
    </div>
  );
}
