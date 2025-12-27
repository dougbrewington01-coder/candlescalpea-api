// server.js
// CandleScalpEA API (DigitalOcean) - minimal Express server with PayPal webhook endpoint

const express = require("express");

const app = express();

// IMPORTANT: PayPal webhooks send JSON
app.use(express.json({ type: "*/*" }));

// --- Health check (so you can confirm the API is alive in a browser) ---
app.get("/", (req, res) => {
  res.status(200).send("CandleScalpEA API is live.");
});

app.get("/health", (req, res) => {
  res.status(200).json({ ok: true, service: "candlescalpea-api" });
});

// --- PayPal Webhook (THIS is the endpoint you point PayPal to) ---
// Use this URL in PayPal Webhooks:
// https://YOUR-API-DOMAIN/api/paypal/webhook

// Browser-friendly check (optional but helpful)
app.get("/api/paypal/webhook", (req, res) => {
  res.status(200).send("OK");
});

// Real webhook receiver
app.post("/api/paypal/webhook", (req, res) => {
  try {
    // Log the webhook so we know it hit your server.
    // (Later we’ll verify signature + update your DB based on event types.)
    console.log("✅ PayPal webhook received:");
    console.log(JSON.stringify(req.body, null, 2));

    // Always respond 200 quickly so PayPal marks it delivered.
    return res.sendStatus(200);
  } catch (err) {
    console.error("❌ Webhook error:", err);
    // Still return 200 to avoid PayPal retry storms while you're testing.
    return res.sendStatus(200);
  }
});

// --- Start server ---
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`CandleScalpEA API listening on port ${PORT}`);
});
