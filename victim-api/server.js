const express = require("express");
const app = express();

app.use(express.json());

// Fake auth middleware — reads the Bearer token and sets req.user
const { authMiddleware } = require("./middleware/auth");
app.use(authMiddleware);

// Routes
app.use("/api/v1/invoices", require("./routes/invoices"));
app.use("/api/v1/user", require("./routes/users"));
app.use("/api/v1/admin", require("./routes/admin"));
app.use("/api/v1/reports", require("./routes/reports"));
app.use("/api/v1/search", require("./routes/search"));
app.use("/api/v1/files", require("./routes/files"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Victim API running on http://localhost:${PORT}`);
  console.log("WARNING: This API is intentionally vulnerable. Do not expose it publicly.");
});
