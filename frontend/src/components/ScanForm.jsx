import { useState } from "react";
import "./ScanForm.css";

const API = "http://localhost:8000";

export default function ScanForm({ onScanStarted, scanning }) {
  const [specFile, setSpecFile] = useState(null);
  const [targetUrl, setTargetUrl] = useState("http://localhost:3000");
  const [stack, setStack] = useState("express");
  const [error, setError] = useState(null);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!specFile) return;
    setError(null);

    const form = new FormData();
    form.append("spec_file", specFile);
    form.append("target_url", targetUrl);
    form.append("stack", stack);

    try {
      const res = await fetch(`${API}/scan`, { method: "POST", body: form });
      if (!res.ok) {
        const err = await res.json();
        setError(err.detail || "Scan failed to start.");
        return;
      }
      const data = await res.json();
      onScanStarted(data.session_id);
    } catch (err) {
      setError("Could not reach the SlingShot backend. Is it running?");
    }
  }

  return (
    <form className="scan-form" onSubmit={handleSubmit}>
      <div className="form-row">
        <label>
          OpenAPI Spec
          <input
            type="file"
            accept=".json,.yaml,.yml"
            onChange={(e) => setSpecFile(e.target.files[0])}
            required
          />
        </label>

        <label>
          Target URL
          <input
            type="url"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="http://localhost:3000"
          />
        </label>

        <label>
          Stack
          <select value={stack} onChange={(e) => setStack(e.target.value)}>
            <option value="express">Node.js / Express</option>
            <option value="fastapi">Python / FastAPI</option>
          </select>
        </label>

        <button type="submit" disabled={scanning || !specFile}>
          {scanning ? "Scanning…" : "Launch Scan"}
        </button>
      </div>

      {error && <p className="form-error">{error}</p>}
    </form>
  );
}
