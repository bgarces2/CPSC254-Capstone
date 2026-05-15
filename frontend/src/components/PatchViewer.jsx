import { useState } from "react";
import "./PatchViewer.css";

const ATTACK_COLORS = {
  BOLA:                 { bg: "#b71c1c", fg: "#fff" },
  MASS_ASSIGNMENT:      { bg: "#e65100", fg: "#fff" },
  BFLA:                 { bg: "#4a148c", fg: "#fff" },
  EXCESSIVE_DATA_EXPOSURE: { bg: "#1a237e", fg: "#fff" },
  MISSING_AUTH:         { bg: "#006064", fg: "#fff" },
  VERB_TAMPERING:       { bg: "#33691e", fg: "#fff" },
  RATE_LIMIT:           { bg: "#f57f17", fg: "#000" },
  SQLI:                 { bg: "#880e4f", fg: "#fff" },
  PATH_TRAVERSAL:       { bg: "#bf360c", fg: "#fff" },
};

function AttackBadge({ type }) {
  const { bg, fg } = ATTACK_COLORS[type] ?? { bg: "#333", fg: "#fff" };
  return (
    <span className="pv-badge" style={{ background: bg, color: fg }}>
      {type.replace(/_/g, " ")}
    </span>
  );
}

function PatchCard({ patch }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  function handleCopy(e) {
    e.stopPropagation(); // don't toggle the card open/closed
    navigator.clipboard.writeText(patch.code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <div className="pv-patch-card">
      <div className="pv-patch-header" onClick={() => setOpen((o) => !o)}>
        <AttackBadge type={patch.attack_type} />
        <span className="pv-patch-file">📄 {patch.target_file}</span>
        {patch.validated && (
          <span className="pv-validated">✓ 403 validated</span>
        )}
        <span className="pv-toggle">{open ? "▲" : "▼"}</span>
      </div>

      {open && (
        <div className="pv-patch-body">
          <div className="pv-code-wrapper">
            <button
              className={`pv-copy-btn ${copied ? "pv-copy-btn--copied" : ""}`}
              onClick={handleCopy}
              title="Copy to clipboard"
            >
              {copied ? "✓ Copied" : "Copy"}
            </button>
            <pre className="pv-code">{patch.code}</pre>
          </div>
          <div className="pv-instructions">
            <strong>How to apply:</strong>
            <p>{patch.instructions}</p>
          </div>
        </div>
      )}
    </div>
  );
}

function EndpointGroup({ endpoint, patches }) {
  const [open, setOpen] = useState(true);
  const exploitCount = patches.length;

  return (
    <div className="pv-endpoint-group">
      <button className="pv-endpoint-header" onClick={() => setOpen((o) => !o)}>
        <span className="pv-endpoint-path">{endpoint}</span>
        <span className="pv-exploit-count">
          {exploitCount} fix{exploitCount !== 1 ? "es" : ""}
        </span>
        <span className="pv-toggle">{open ? "▲" : "▼"}</span>
      </button>

      {open && (
        <div className="pv-patch-list">
          {patches.map((patch, i) => (
            <PatchCard key={i} patch={patch} />
          ))}
        </div>
      )}
    </div>
  );
}

export default function PatchViewer({ patches }) {
  // Group patches by endpoint, preserving insertion order
  const grouped = patches.reduce((acc, patch) => {
    const key = patch.endpoint;
    if (!acc[key]) acc[key] = [];
    acc[key].push(patch);
    return acc;
  }, {});

  const endpoints = Object.keys(grouped);

  return (
    <div className="patch-pane">
      <div className="pane-header">
        <span className="pane-title">🛡 Proposed Security Patches</span>
        {patches.length > 0 && (
          <span className="pv-summary">
            {patches.length} patch{patches.length !== 1 ? "es" : ""} across {endpoints.length} endpoint{endpoints.length !== 1 ? "s" : ""}
          </span>
        )}
      </div>

      <div className="patch-body">
        {endpoints.length === 0 && (
          <p className="patch-placeholder">
            Patches will appear here when exploits are confirmed.
          </p>
        )}

        {endpoints.length > 0 && (
          <div className="pv-disclaimer">
            ⚠ These patches are AI-generated. Review all code carefully before
            applying to a production system. SlingShot does not guarantee
            correctness — treat each patch as a starting point, not a final fix.
          </div>
        )}

        {endpoints.map((endpoint) => (
          <EndpointGroup
            key={endpoint}
            endpoint={endpoint}
            patches={grouped[endpoint]}
          />
        ))}
      </div>
    </div>
  );
}
