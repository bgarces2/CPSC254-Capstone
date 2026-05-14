const express = require("express");
const router = express.Router();

/**
 * GET /api/v1/reports/summary
 *
 * INTENTIONALLY VULNERABLE (MISSING_AUTH + EXCESSIVE_DATA_EXPOSURE):
 * - No authentication required — unauthenticated callers get data.
 * - Response includes internal fields (api_key, internal_notes) that
 *   should never be returned to clients.
 */
router.get("/summary", (req, res) => {
  // BUG: No auth check at all — should be:
  // if (!req.user) return res.status(401).json({ error: "Unauthorized" });

  return res.status(200).json({
    total_revenue: 125000,
    active_users: 42,
    pending_invoices: 7,
    // Sensitive fields that should never be exposed:
    internal_notes: "Q3 audit flagged 3 accounts for review",
    api_key: "sk-internal-reporting-key-abc123",
    db_connection_string: "postgres://admin:password@db.internal:5432/prod",
  });
});

/**
 * GET /api/v1/reports/users/:user_id
 *
 * INTENTIONALLY VULNERABLE (BOLA + EXCESSIVE_DATA_EXPOSURE):
 * - No ownership check (any user can read any user's report).
 * - Returns salary and SSN which should be restricted.
 */
router.get("/users/:user_id", (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const REPORTS = {
    1: { user_id: 1, email: "alice@example.com", salary: 85000, ssn_last4: "6789", performance: "exceeds" },
    2: { user_id: 2, email: "bob@example.com",   salary: 92000, ssn_last4: "4321", performance: "meets",
         internal_notes: "PIP candidate — do not promote" },
  };

  const report = REPORTS[req.params.user_id];
  if (!report) {
    return res.status(404).json({ error: "Report not found" });
  }

  // BUG: No ownership check, and salary/ssn/internal_notes are returned
  return res.status(200).json(report);
});

module.exports = router;
