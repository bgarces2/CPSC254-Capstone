const express = require("express");
const path = require("path");
const fs = require("fs");
const router = express.Router();

// The "safe" directory files are supposed to be served from
const PUBLIC_DIR = path.join(__dirname, "../public");

/**
 * GET /api/v1/files/:filename
 *
 * INTENTIONALLY VULNERABLE (PATH TRAVERSAL):
 * Passes the filename parameter directly to fs.readFile without
 * sanitizing or canonicalizing the path.
 *
 * An attacker can request:
 *   GET /api/v1/files/../../../etc/passwd
 * and receive the contents of /etc/passwd.
 *
 * BUG: Should use path.resolve() and verify the result starts with PUBLIC_DIR.
 */
router.get("/:filename", (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  // BUG: No path sanitization — should be:
  // const safePath = path.resolve(PUBLIC_DIR, req.params.filename);
  // if (!safePath.startsWith(PUBLIC_DIR)) {
  //   return res.status(403).json({ error: "Forbidden" });
  // }

  const filePath = path.join(PUBLIC_DIR, req.params.filename);

  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) {
      // Leak the resolved path in the error — makes traversal obvious to the prober
      return res.status(404).json({
        error: `No such file or directory: ${filePath}`,
        attempted_path: filePath,
      });
    }
    return res.status(200).send(data);
  });
});

module.exports = router;
