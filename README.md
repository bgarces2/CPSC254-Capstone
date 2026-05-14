# ⚡ SlingShot

An offensive-security agent that probes APIs for logic flaws like BOLA and Mass Assignment, then automatically writes defensive middleware to block the exploits it discovers.

---

## Quick Start (5 minutes)

### Prerequisites
- Python 3.11+
- Node.js 18+
- An OpenAI API key

### 1. Set your API key

Copy the example env file and add your key:

```bash
cp .env.example .env
# then edit .env and set OPENAI_API_KEY=sk-...
```

### 2. Start the Victim API

```bash
cd victim-api
npm install
npm start
# Running on http://localhost:3000
```

### 3. Start the Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
# Running on http://localhost:8000
```

### 4. Start the Frontend

```bash
cd frontend
npm install
npm run dev
# Running on http://localhost:5173
```

### 5. Run your first audit

1. Open **http://localhost:5173**
2. Upload `victim-api/openapi.yaml` as the spec file
3. Leave the target URL as `http://localhost:3000`
4. Click **Launch Scan ⚡**

Watch the Attacker Terminal stream live fuzzing attempts on the left. When an exploit is confirmed, the generated middleware patch appears on the right.

---

## Project Structure

```
slingshot/
├── backend/              # Python / FastAPI — pipeline orchestrator + agents
│   ├── agents/           # Attacker, Judge, and Fixer LLM agents
│   ├── fuzzer/           # Multi-turn HTTP fuzzing engine
│   ├── parser/           # OpenAPI spec ingestion + endpoint classification
│   ├── models/           # Pydantic/dataclass schemas
│   ├── db/               # SQLite persistence
│   └── main.py           # FastAPI app + SSE stream
│
├── frontend/             # React / Vite — Duel View UI
│   └── src/
│       └── components/   # AttackerTerminal + PatchViewer
│
└── victim-api/           # Intentionally vulnerable Express API (scan target)
    ├── routes/           # invoices.js (BOLA), users.js (Mass Assignment)
    └── openapi.yaml      # Spec file to upload into SlingShot
```

---

## How It Works

1. **Spec Parser** reads your OpenAPI file and flags High Value endpoints
2. **Attacker Agent** (GPT-4o) generates adversarial payloads for each endpoint
3. **Fuzzing Engine** executes payloads in a multi-turn loop — the LLM calls a `make_request` tool; the engine runs the actual HTTP requests
4. **Vulnerability Judge** (GPT-4o) reviews the logs and filters false positives using a 3-check rubric
5. **Fixer Agent** (GPT-4o) generates targeted middleware to patch confirmed exploits
6. The patch is validated by re-running the original attack and confirming a `403 Forbidden`

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `OPENAI_API_KEY` | — | Required. Your OpenAI API key |
| `OPENAI_MODEL` | `gpt-4o` | Model to use for all agents |
| `TARGET_BASE_URL` | `http://localhost:3000` | Default scan target |
| `MAX_FUZZ_ATTEMPTS` | `10` | Max requests per fuzzing session |
| `DATABASE_URL` | `slingshot.db` | SQLite file path |
