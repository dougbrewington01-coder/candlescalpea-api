import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import fetch from "node-fetch";

const app = express();
const PORT = process.env.PORT || 3000;

/* ================================
   CONFIG
================================ */
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_SECRET = process.env.PAYPAL_SECRET;
const PAYPAL_WEBHOOK_ID = "0B073228AE592314G";
const PAYPAL_API_BASE = "https://api-m.paypal.com";

/* ================================
   MIDDLEWARE
================================ */
app.use(bodyParser.json({ type: "*/*" }));

/* ================================
   PAYPAL TOKEN
================================ */
async function getPayPalAccessToken() {
  const auth = Buffer.from(
    `${PAYPAL_CLIENT_ID}:${PAYPAL_SECRET}`
  ).toString("base64");

  const res = await fetch(`${PAYPAL_API_BASE}/v1/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${auth}`,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: "grant_type=client_credentials"
  });

  const data = await res.json();
  return data.access_token;
}

/* ================================
   PAYPAL WEBHOOK VERIFY
================================ */
async function verifyPayPalWebhook(req) {
  const accessToken = await getPayPalAccessToken();

  const verificationPayload = {
    auth_algo: req.headers["paypal-auth-algo"],
    cert_url: req.headers["paypal-cert-url"],
    transmission_id: req.headers["paypal-transmission-id"],
    transmission_sig: req.headers["paypal-transmission-sig"],
    transmission_time: req.headers["paypal-transmission-time"],
    webhook_id: PAYPAL_WEBHOOK_ID,
    webhook_event: req.body
  };

  const res = await fetch(
    `${PAYPAL_API_BASE}/v1/notifications/verify-webhook-signature`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(verificationPayload)
    }
  );

  const data = await res.json();
  return data.verification_status === "SUCCESS";
}

/* ================================
   PAYPAL WEBHOOK ENDPOINT
================================ */
app.post("/paypal/webhook", async (req, res) => {
  try {
    const verified = await verifyPayPalWebhook(req);
    if (!verified) {
      return res.status(400).send("Invalid webhook");
    }

    const event = req.body.event_type;
    const resource = req.body.resource;

    console.log("PayPal Event:", event);

    if (event === "BILLING.SUBSCRIPTION.ACTIVATED") {
      console.log("Subscription activated:", resource.id);
      // TODO: mark user active
    }

    if (event === "BILLING.SUBSCRIPTION.CANCELLED") {
      console.log("Subscription cancelled:", resource.id);
      // TODO: disable user
    }

    if (event === "BILLING.SUBSCRIPTION.SUSPENDED") {
      console.log("Subscription suspended:", resource.id);
      // TODO: suspend access
    }

    if (event === "PAYMENT.SALE.COMPLETED") {
      console.log("Payment completed:", resource.id);
      // TODO: log payment
    }

    res.sendStatus(200);
  } catch (err) {
    console.error("Webhook error:", err);
    res.sendStatus(500);
  }
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
app.listen(PORT, () => {
  console.log(`API running on port ${PORT}`);
});
