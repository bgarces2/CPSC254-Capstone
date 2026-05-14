/**
 * Fake JWT middleware.
 * Maps known Bearer tokens to user objects so the victim API
 * has an authenticated user context without a real auth system.
 */

const USERS = {
  token_user_a: { id: 1, email: "alice@example.com", is_admin: false },
  token_user_b: { id: 2, email: "bob@example.com",   is_admin: false },
};

function authMiddleware(req, res, next) {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.replace("Bearer ", "").trim();

  if (USERS[token]) {
    req.user = USERS[token];
  } else {
    req.user = null;
  }

  next(); // always continue — individual routes enforce auth
}

module.exports = { authMiddleware };
