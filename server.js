import express from "express";
import bodyParser from "body-parser";
import fetch from "node-fetch";
import crypto from "crypto";

const app = express();
app.use(bodyParser.json());

/* ================================
   CONFIG
================================ */
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_SECRET = process.env.PAYPAL_SECRET;
const PAYPAL_WEBHOOK_ID = process.env.PAYPAL_WEBHOOK_ID;

const PAYPAL_API = "https://api-m.paypal.com";

/* ================================
   PAYPAL AUTH
================================ */
async function getPayPalToken() {
  const auth = Buffer.from(
    `${PAYPAL_CLIENT_ID}:${PAYPAL_SECRET}`
  ).toString("base64");

  const res = await fetch(`${PAYPAL_API}/v1/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${auth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });

  const data = await res.json();
  return data.access_token;
}

/* ================================
   PAYPAL WEBHOOK VERIFY
================================ */
async function verifyWebhook(headers, body) {
  const token = await getPayPalToken();

  const res = await fetch(
    `${PAYPAL_API}/v1/notifications/verify-webhook-signature`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        auth_algo: headers["paypal-auth-algo"],
        cert_url: headers["paypal-cert-url"],
        transmission_id: headers["paypal-transmission-id"],
        transmission_sig: headers["paypal-transmission-sig"],
        transmission_time: headers["paypal-transmission-time"],
        webhook_id: PAYPAL_WEBHOOK_ID,
        webhook_event: body,
      }),
    }
  );

  const data = await res.json();
  return data.verification_status === "SUCCESS";
}

/* ================================
   PAYPAL WEBHOOK RECEIVER
================================ */
app.post("/paypal/webhook", async (req, res) => {
  const verified = await verifyWebhook(req.headers, req.body);
  if (!verified) return res.status(400).send("Invalid webhook");

  const event = req.body.event_type;
  const resource = req.body.resource;

  console.log("PayPal Event:", event);

  /*
    EVENTS YOU CARE ABOUT:
    - BILLING.SUBSCRIPTION.ACTIVATED
    - BILLING.SUBSCRIPTION.CANCELLED
    - BILLING.SUBSCRIPTION.SUSPENDED
    - PAYMENT.SALE.COMPLETED
  */

  // TODO: Update database here later
  // For now, just logging
  console.log("Subscription ID:", resource.id);

  res.sendStatus(200);
});

/* ================================
   EA PHONE-HOME LICENSE CHECK
================================ */
app.post("/ea/check", (req, res) => {
  const { account, nickname, symbol } = req.body;

  if (!account || !nickname) {
    return res.json({ allowed: false });
  }

  /*
    TEMP LOGIC:
    - Replace with DB lookup later
    - Right now: allow all valid requests
  */

  const allowed = true;

  res.json({
    allowed,
    message: allowed ? "OK" : "LICENSE_BLOCKED",
  });
});

/* ================================
   HEALTH CHECK
================================ */
app.get("/", (req, res) => {
  res.send("CandleScalpEA API running");
});

/* ================================
   START SERVER
================================ */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
