import React, { useState } from "react";
import { Check, Copy, Download, Code } from "lucide-react";

export default function ReceiptViewer({ receipt }) {
  const [showJson, setShowJson] = useState(false);
  const [copied, setCopied] = useState(null);

  if (!receipt) {
    return (
      <div className="receipt-dock">
        <span style={{ color: "var(--text-dim)" }}>
          Awaiting investigation receipt minting...
        </span>
        <span className="font-mono" style={{ fontSize: 10, color: "var(--text-dim)" }}>
          RFC 8785 (JCS) + SHA-256 Digest Engine Ready
        </span>
      </div>
    );
  }

  const copyToClipboard = (text, label) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 2000);
  };

  const downloadReceipt = () => {
    const blob = new Blob([JSON.stringify(receipt, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `compliance-defense-${receipt.receipt_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <div className="receipt-dock">
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ fontWeight: 700, color: "var(--text-bright)", textTransform: "uppercase", letterSpacing: "0.5px" }}>
            Audit Defense Receipt:
          </span>
          <span className="font-mono" style={{ color: "var(--accent-world)" }}>
            {receipt.receipt_id}
          </span>
          {receipt.evidence_digest && (
            <span className="font-mono" style={{ color: "var(--text-dim)", fontSize: 10 }}>
              SHA-256: {receipt.evidence_digest.substring(0, 16)}...
            </span>
          )}
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {receipt.evidence_digest && (
            <button
              type="button"
              className="btn-secondary"
              onClick={() => copyToClipboard(receipt.evidence_digest, "digest")}
              style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
            >
              {copied === "digest" ? <Check size={12} color="var(--accent-world)" /> : <Copy size={12} />}
              <span>{copied === "digest" ? "Copied Digest" : "Copy Digest"}</span>
            </button>
          )}

          {(receipt.hmac_signature || receipt.signature) && (
            <button
              type="button"
              className="btn-secondary"
              onClick={() => copyToClipboard(receipt.hmac_signature || receipt.signature, "sig")}
              style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
            >
              {copied === "sig" ? <Check size={12} color="var(--accent-world)" /> : <Copy size={12} />}
              <span>{copied === "sig" ? "Copied HMAC" : "Copy HMAC Seal"}</span>
            </button>
          )}

          <button
            type="button"
            className="btn-secondary"
            onClick={() => setShowJson(!showJson)}
            style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
          >
            <Code size={12} />
            <span>{showJson ? "Hide JCS Payload" : "Inspect JCS"}</span>
          </button>

          <button
            type="button"
            className="btn-primary"
            onClick={downloadReceipt}
            style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
          >
            <Download size={13} />
            <span>Export Legal Defense (.json)</span>
          </button>
        </div>
      </div>

      {showJson && (
        <div style={{ background: "var(--bg-deep)", borderTop: "1px solid var(--border-hairline)", padding: "12px 20px", maxHeight: 220, overflowY: "auto" }}>
          <pre className="font-mono" style={{ fontSize: 11, color: "var(--text-main)", whiteSpace: "pre-wrap" }}>
            {JSON.stringify(receipt, null, 2)}
          </pre>
        </div>
      )}
    </>
  );
}
