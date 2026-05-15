import { useEffect, useRef, useState } from "react";
import "./AttackerTerminal.css";

// ── Event grouping ────────────────────────────────────────────────────────────
//
// We bucket the raw event stream into "attack groups" so each
// endpoint + attack_type gets its own collapsible block:
//
//   [SCAN] GET /api/v1/invoices/{invoice_id}  →  BOLA, SQLI …
//   ▼ BOLA  [EXPLOIT_CONFIRMED]               ← always visible
//     ▼ Show 3 requests                       ← dropdown toggle
//       #1 GET /invoices/1  → 200
//       #2 GET /invoices/999 → 200  …
//   ▼ SQLI  [NO_VULNERABILITY]
//     ▼ Show 8 requests
//       …

function groupEvents(events) {
  const groups = [];   // { key, endpoint, attackType, payloadDesc, attempts, verdict, isProber }
  let currentGroup = null;

  for (const ev of events) {
    if (ev.type === "endpoint") {
      // Endpoint header — not part of any group, rendered separately
      groups.push({ type: "endpoint_header", ev });
      currentGroup = null;
      continue;
    }

    if (ev.type === "payload") {
      // Start a new LLM-driven group
      currentGroup = {
        type: "attack_group",
        key: `${ev.endpoint}::${ev.attack_type}::${groups.length}`,
        endpoint: ev.endpoint,
        attackType: ev.attack_type,
        payloadDesc: { baseline: ev.baseline, attack: ev.attack },
        attempts: [],
        verdict: null,
        isProber: false,
      };
      groups.push(currentGroup);
      continue;
    }

    if (ev.type === "fuzz" && ev.attempt === 0 && ev.body_preview?.startsWith("[")) {
      // Prober announcement (RATE_LIMIT / SQLI / PATH_TRAVERSAL)
      const proberType = ev.body_preview.match(/^\[([^\]]+)\]/)?.[1] ?? "PROBE";
      currentGroup = {
        type: "attack_group",
        key: `${ev.url}::${proberType}::${groups.length}`,
        endpoint: ev.url,
        attackType: proberType,
        payloadDesc: null,
        attempts: [],
        verdict: null,
        isProber: true,
      };
      groups.push(currentGroup);
      continue;
    }

    if (ev.type === "fuzz") {
      if (!currentGroup) {
        // Orphaned fuzz event — create a catch-all group
        currentGroup = {
          type: "attack_group",
          key: `orphan::${groups.length}`,
          endpoint: ev.url ?? "unknown",
          attackType: "UNKNOWN",
          payloadDesc: null,
          attempts: [],
          verdict: null,
          isProber: false,
        };
        groups.push(currentGroup);
      }
      currentGroup.attempts.push(ev);
      continue;
    }

    if (ev.type === "verdict") {
      // Attach verdict to the current group (or find the last matching one)
      const target = currentGroup ?? [...groups].reverse().find(
        (g) => g.type === "attack_group" && g.attackType === ev.attack_type
      );
      if (target) target.verdict = ev;
      // Close the group — no more fuzz attempts expected after a verdict
      currentGroup = null;
      continue;
    }

    if (ev.type === "patch_ready") {
      groups.push({ type: "patch_banner", ev });
      continue;
    }

    if (ev.type === "error") {
      groups.push({ type: "error_line", ev });
      continue;
    }
  }

  return groups;
}

// ── Sub-components ────────────────────────────────────────────────────────────

function EndpointHeader({ ev }) {
  return (
    <div className="tg-endpoint-header">
      <span className="tg-badge badge-scan">SCAN</span>
      <span className="tg-method">{ev.method}</span>
      <span className="tg-path">{ev.path}</span>
      <span className="tg-hints">{ev.hints.join("  ·  ")}</span>
    </div>
  );
}

function AttackGroup({ group, isActive }) {
  // All groups start collapsed — user opens them manually
  const [open, setOpen] = useState(false);
  const verdict = group.verdict;
  const isExploit = verdict?.verdict === "EXPLOIT_CONFIRMED";
  const pending = !verdict;
  const stillRunning = isActive && pending;

  return (
    <div className={`tg-group ${isExploit ? "group-exploit" : pending ? "group-pending" : "group-clean"}`}>
      {/* ── Group header — always visible ── */}
      <div className="tg-group-header">
        <span className={`tg-badge ${isExploit ? "badge-exploit" : pending ? "badge-pending" : "badge-clean"}`}>
          {group.attackType}
        </span>

        {verdict && (
          <span className={`tg-verdict-label ${isExploit ? "color-red" : "color-green"}`}>
            {isExploit ? "EXPLOIT CONFIRMED" : "NO VULNERABILITY"}
          </span>
        )}
        {pending && !stillRunning && <span className="tg-verdict-label color-dim">scanning…</span>}
        {stillRunning && (
          <span className="tg-running">
            <span className="tg-running-dot" />
            {group.attempts.length > 0
              ? `${group.attempts.length} payload${group.attempts.length !== 1 ? "s" : ""} sent…`
              : "probing…"}
          </span>
        )}

        {/* Dropdown toggle — shown when there are requests to display */}
        {group.attempts.length > 0 && (
          <button
            className="tg-toggle"
            onClick={() => setOpen((o) => !o)}
            aria-expanded={open}
          >
            {open
              ? "Hide"
              : `Show ${group.attempts.length} request${group.attempts.length !== 1 ? "s" : ""}`}
          </button>
        )}
      </div>

      {/* ── Payload description (LLM-driven only) ── */}
      {group.payloadDesc && (
        <div className="tg-payload-desc">
          <span className="tg-payload-label">baseline&nbsp;</span> {group.payloadDesc.baseline}
          <br />
          <span className="tg-payload-label">attack&nbsp;&nbsp;</span> {group.payloadDesc.attack}
        </div>
      )}

      {/* ── Collapsible request list ── */}
      {open && (
        <div className="tg-attempts">
          {group.attempts.length === 0 && (
            <p className="tg-no-attempts">No requests recorded yet…</p>
          )}
          {group.attempts.map((att, i) => {
            const is2xx = att.status >= 200 && att.status < 300;
            const isSlow = group.attackType === "SQLI" && att.body_preview?.startsWith("[elapsed:");
            const elapsedMatch = isSlow && att.body_preview.match(/\[elapsed:\s*([\d.]+)s\]/);
            const elapsed = elapsedMatch ? parseFloat(elapsedMatch[1]) : null;
            const isSuspicious = elapsed !== null && elapsed >= 4.5;

            return (
              <div key={i} className={`tg-attempt ${is2xx ? "attempt-2xx" : "attempt-err"} ${isSuspicious ? "attempt-suspicious" : ""}`}>
                <span className={`tg-attempt-num color-dim`}>#{i + 1}</span>
                <span className={`tg-status ${is2xx ? "color-green" : "color-dim"}`}>
                  {att.status || "—"}
                </span>
                {elapsed !== null && (
                  <span className={`tg-elapsed ${isSuspicious ? "color-red" : "color-dim"}`}>
                    {elapsed.toFixed(2)}s{isSuspicious ? " ⚠" : ""}
                  </span>
                )}
                <span className="tg-req-method">{att.method}</span>
                <span className="tg-req-url">{att.url}</span>
                {att.body_preview && (
                  <pre className="tg-body-preview">
                    {/* Strip the elapsed prefix for cleaner display */}
                    {att.body_preview.replace(/^\[elapsed:[^\]]+\]\s*/, "")}
                  </pre>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* ── Verdict reasoning (collapsed by default, expandable) ── */}
      {verdict && (
        <details className="tg-reasoning">
          <summary>Reasoning</summary>
          <p>{verdict.reasoning}</p>
          {verdict.evidence && (
            <p className="tg-evidence"><strong>Evidence:</strong> {verdict.evidence}</p>
          )}
        </details>
      )}
    </div>
  );
}

function PatchBanner({ ev }) {
  return (
    <div className="tg-patch-banner">
      <span className="tg-badge badge-patch">PATCH</span>
      Fix generated for <strong>{ev.endpoint}</strong> → see right pane
    </div>
  );
}

function ErrorLine({ ev }) {
  return (
    <div className="tg-error-line">
      <span className="tg-badge badge-error">ERROR</span>
      {ev.message}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function AttackerTerminal({ events, scanning }) {
  const bodyRef = useRef(null);
  const bottomRef = useRef(null);
  const [userScrolled, setUserScrolled] = useState(false);
  const groups = groupEvents(events);

  // The last attack_group without a verdict is the one currently running
  const activeGroupKey = scanning
    ? [...groups].reverse().find((g) => g.type === "attack_group" && !g.verdict)?.key ?? null
    : null;

  // Detect when the user manually scrolls up — pause auto-scroll
  function handleScroll() {
    const el = bodyRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    setUserScrolled(!atBottom);
  }

  // Auto-scroll only when the user hasn't scrolled away
  useEffect(() => {
    if (!userScrolled) {
      bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [events, userScrolled]);

  // Resume auto-scroll when scan finishes
  useEffect(() => {
    if (!scanning) setUserScrolled(false);
  }, [scanning]);

  return (
    <div className="terminal-pane">
      <div className="pane-header">
        <span className="pane-title">⚔ Attacker Terminal</span>
        {scanning && <span className="blink">●</span>}
        {scanning && userScrolled && (
          <button
            className="tg-resume-scroll"
            onClick={() => {
              setUserScrolled(false);
              bottomRef.current?.scrollIntoView({ behavior: "smooth" });
            }}
          >
            ↓ Resume scroll
          </button>
        )}
      </div>

      <div className="terminal-body" ref={bodyRef} onScroll={handleScroll}>
        {groups.length === 0 && (
          <p className="terminal-placeholder">Waiting for scan to start…</p>
        )}

        {groups.map((g, i) => {
          if (g.type === "endpoint_header") return <EndpointHeader key={i} ev={g.ev} />;
          if (g.type === "attack_group")   return <AttackGroup key={g.key} group={g} isActive={g.key === activeGroupKey} />;
          if (g.type === "patch_banner")   return <PatchBanner key={i} ev={g.ev} />;
          if (g.type === "error_line")     return <ErrorLine key={i} ev={g.ev} />;
          return null;
        })}

        <div ref={bottomRef} />
      </div>
    </div>
  );
}
