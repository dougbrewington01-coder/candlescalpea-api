import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";

const app = express();

/**
 * IMPORTANT:
 * PayPal needs RAW body for webhook verification
 */
app.use(
  "/api/paypal/webhook",
  bodyParser.raw({ type: "application/json" })
);

// Basic health check (THIS IS CRITICAL FOR DIGITALOCEAN)
app.get("/", (req, res) => {
  res.status(200).send("API is running");
});

// PayPal Webhook Endpoint
app.post("/api/paypal/webhook", (req, res) => {
  console.log("📩 PayPal Webhook Received");

  try {
    const webhookEvent = JSON.parse(req.body.toString());
    console.log("Event Type:", webhookEvent.event_type);
    res.sendStatus(200);
  } catch (err) {
    console.error("Webhook parse error:", err);
    res.sendStatus(400);
  }
});

// MUST use DigitalOcean PORT
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 Server listening on port ${PORT}`);
});
