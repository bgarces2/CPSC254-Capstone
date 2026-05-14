const express = require("express");
const router = express.Router();

// Fake user database (mutable for demo purposes)
const USERS = {
  1: { id: 1, email: "alice@example.com", bio: "Frontend dev", avatar: "alice.png", is_admin: false },
  2: { id: 2, email: "bob@example.com",   bio: "Backend dev",  avatar: "bob.png",   is_admin: false },
};

/**
 * PATCH /api/v1/user/profile
 *
 * INTENTIONALLY VULNERABLE: No field allow-list.
 * Any field in the request body is merged into the user object,
 * including privilege fields like is_admin.
 * This demonstrates Mass Assignment (Security Misconfiguration).
 */
router.patch("/profile", (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const user = USERS[req.user.id];
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  // BUG: No allow-list — should be:
  // const { bio, avatar } = req.body;
  // Object.assign(user, { bio, avatar });
  Object.assign(user, req.body);  // merges ALL fields, including is_admin

  return res.status(200).json(user);
});

/**
 * GET /api/v1/user/profile
 * Returns the current user's profile (not vulnerable).
 */
router.get("/profile", (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  return res.status(200).json(USERS[req.user.id]);
});

module.exports = router;
