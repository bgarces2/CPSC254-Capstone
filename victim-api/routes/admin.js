const express = require("express");
const router = express.Router();

// Fake user list — only admins should see this
const ALL_USERS = [
  { id: 1, email: "alice@example.com", role: "user",  salary: 85000, ssn: "123-45-6789" },
  { id: 2, email: "bob@example.com",   role: "user",  salary: 92000, ssn: "987-65-4321" },
  { id: 3, email: "carol@example.com", role: "admin", salary: 120000, ssn: "555-44-3333" },
];

/**
 * GET /api/v1/admin/users
 *
 * INTENTIONALLY VULNERABLE (BFLA): No role check.
 * Any authenticated user can call this admin endpoint.
 * Should require is_admin === true but doesn't.
 */
router.get("/users", (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  // BUG: Missing role check — should be:
  // if (!req.user.is_admin) return res.status(403).json({ error: "Forbidden" });

  return res.status(200).json({ users: ALL_USERS });
});

/**
 * DELETE /api/v1/admin/users/:user_id
 *
 * INTENTIONALLY VULNERABLE (BFLA + VERB_TAMPERING):
 * No role check, and this destructive method is accessible to any user.
 */
router.delete("/users/:user_id", (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  // BUG: Missing role check
  const idx = ALL_USERS.findIndex(u => u.id === parseInt(req.params.user_id));
  if (idx === -1) {
    return res.status(404).json({ error: "User not found" });
  }

  const deleted = ALL_USERS.splice(idx, 1)[0];
  return res.status(200).json({ message: "User deleted", user: deleted });
});

module.exports = router;
