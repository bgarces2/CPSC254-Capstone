const express = require("express");
const router = express.Router();

// Fake invoice database
// Invoices 900-999 are owned by User B (id: 2)
// Invoices 1-99 are owned by User A (id: 1)
const INVOICES = {
  1:   { id: 1,   owner_id: 1, amount: 150.00, description: "Web design services", status: "paid" },
  2:   { id: 2,   owner_id: 1, amount: 75.50,  description: "Consulting - March",   status: "pending" },
  999: { id: 999, owner_id: 2, amount: 4200.00, description: "Enterprise contract", status: "paid",
         client_email: "bob@example.com", ssn_last4: "7890" },  // sensitive PII to make exploit obvious
  998: { id: 998, owner_id: 2, amount: 800.00, description: "Support retainer",    status: "pending" },
};

/**
 * GET /api/v1/invoices/:invoice_id
 *
 * INTENTIONALLY VULNERABLE: No ownership check.
 * Any authenticated user can read any invoice by ID.
 * This demonstrates BOLA (Broken Object Level Authorization).
 */
router.get("/:invoice_id", (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const invoice = INVOICES[req.params.invoice_id];
  if (!invoice) {
    return res.status(404).json({ error: "Invoice not found" });
  }

  // BUG: Missing ownership check — should be:
  // if (invoice.owner_id !== req.user.id) return res.status(403).json({ error: "Forbidden" });

  return res.status(200).json(invoice);
});

module.exports = router;
