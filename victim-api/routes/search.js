const express = require("express");
const router = express.Router();

/**
 * Fake in-memory "database" of products.
 * In a real app this would be a SQL query — we simulate the SQL
 * behavior so the error-based and response-based SQLi probes work.
 */
const PRODUCTS = [
  { id: 1, name: "Widget A", price: 9.99,  category: "widgets" },
  { id: 2, name: "Widget B", price: 14.99, category: "widgets" },
  { id: 3, name: "Gadget X", price: 49.99, category: "gadgets" },
  { id: 4, name: "Gadget Y", price: 99.99, category: "gadgets" },
];

/**
 * GET /api/v1/search?q=widget
 *
 * INTENTIONALLY VULNERABLE (SQLI — error-based simulation):
 * Reflects SQL-like error messages when the query contains special characters.
 * Simulates what a real unsanitized SQL query would leak.
 *
 * BUG: Should use parameterized queries. Instead, it echoes the raw input
 * and returns a fake DB error for SQL metacharacters.
 */
router.get("/", (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const q = req.query.q || "";

  // Simulate SQL error leakage for injection metacharacters
  const sqlMetaChars = ["'", '"', "--", ";", "/*", "*/", "\\"];
  const hasMeta = sqlMetaChars.some(c => q.includes(c));

  if (hasMeta) {
    // BUG: Real app would pass q directly into: SELECT * FROM products WHERE name LIKE '%{q}%'
    // This simulates the MySQL error that would result
    return res.status(500).json({
      error: "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '" + q + "' at line 1",
      query: `SELECT * FROM products WHERE name LIKE '%${q}%'`,
    });
  }

  const results = PRODUCTS.filter(p =>
    p.name.toLowerCase().includes(q.toLowerCase()) ||
    p.category.toLowerCase().includes(q.toLowerCase())
  );

  return res.status(200).json({ results, query: q });
});

/**
 * GET /api/v1/search/:product_id
 *
 * INTENTIONALLY VULNERABLE (SQLI — time-based simulation):
 * Simulates a slow response when a SLEEP() payload is detected,
 * mimicking what a real time-based blind SQLi would produce.
 */
router.get("/:product_id", (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const id = req.params.product_id;

  // Simulate time-based blind SQLi: if the payload contains SLEEP or pg_sleep,
  // delay the response to mimic a real DB sleep injection
  const sleepMatch = id.match(/SLEEP\((\d+)\)|pg_sleep\((\d+)\)|WAITFOR DELAY '0:0:(\d+)'/i);
  if (sleepMatch) {
    const seconds = parseInt(sleepMatch[1] || sleepMatch[2] || sleepMatch[3] || "5", 10);
    return setTimeout(() => {
      res.status(200).json({ id, result: null });
    }, seconds * 1000);
  }

  // Also leak error for SQL metacharacters
  if (["'", '"', "--", ";"].some(c => id.includes(c))) {
    return res.status(500).json({
      error: `You have an error in your SQL syntax near '${id}' at line 1`,
    });
  }

  const product = PRODUCTS.find(p => p.id === parseInt(id));
  if (!product) {
    return res.status(404).json({ error: "Product not found" });
  }

  return res.status(200).json(product);
});

module.exports = router;
