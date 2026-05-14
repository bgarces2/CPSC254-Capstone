import { useState } from "react";
import ScanForm from "./components/ScanForm";
import AttackerTerminal from "./components/AttackerTerminal";
import PatchViewer from "./components/PatchViewer";
import "./App.css";

export default function App() {
  const [sessionId, setSessionId] = useState(null);
  const [events, setEvents] = useState([]);
  const [patches, setPatches] = useState([]);
  const [scanning, setScanning] = useState(false);

  function handleScanStarted(id) {
    setSessionId(id);
    setEvents([]);
    setPatches([]);
    setScanning(true);

    const es = new EventSource(`http://localhost:8000/scan/${id}/stream`);

    es.addEventListener("endpoint_classified", (e) => {
      const d = JSON.parse(e.data);
      setEvents((prev) => [...prev, { type: "endpoint", ...d }]);
    });

    es.addEventListener("payload_generated", (e) => {
      const d = JSON.parse(e.data);
      setEvents((prev) => [...prev, { type: "payload", ...d }]);
    });

    es.addEventListener("fuzz_attempt", (e) => {
      const d = JSON.parse(e.data);
      setEvents((prev) => [...prev, { type: "fuzz", ...d }]);
    });

    es.addEventListener("verdict", (e) => {
      const d = JSON.parse(e.data);
      setEvents((prev) => [...prev, { type: "verdict", ...d }]);
    });

    es.addEventListener("patch_ready", (e) => {
      const d = JSON.parse(e.data);
      setEvents((prev) => [...prev, { type: "patch_ready", endpoint: d.endpoint }]);
      setPatches((prev) => [...prev, d]);
    });

    es.addEventListener("error_event", (e) => {
      const d = JSON.parse(e.data);
      setEvents((prev) => [...prev, { type: "error", ...d }]);
    });

    es.addEventListener("done", () => {
      setScanning(false);
      es.close();
    });

    es.onerror = () => {
      setScanning(false);
      es.close();
    };
  }

  return (
    <div className="app">
      <header className="app-header">
        <span className="logo"> SlingShot</span>
        <span className="tagline">API Security Auditor</span>
      </header>

      <ScanForm onScanStarted={handleScanStarted} scanning={scanning} />

      {sessionId && (
        <div className="duel-view">
          <AttackerTerminal events={events} scanning={scanning} />
          <PatchViewer patches={patches} />
        </div>
      )}
    </div>
  );
}
