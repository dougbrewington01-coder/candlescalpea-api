import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";

const app = express();

/*
  IMPORTANT:
  PayPal webhooks require the RAW body for signature verification
*/
app.use(
  "/paypal/webhook",
  express.raw({ type: "application/json" })
);

app.use(express.json());

/* =========================
   ENVIRONMENT VARIABLES
   ========================= */
const {
  PAYPAL_CLIENT_ID,
  PAYPAL_CLIENT_SECRET,
  PAYPAL_WEBHOOK_ID,
  PORT = 8080
} = process.env;

/* =========================
   BASIC HEALTH CHECK
   ========================= */
app.get("/", (req, res) => {
  res.status(200).send("CandleScalpEA API is running");
});

/* =========================
   PAYPAL ACCESS TOKEN
   ========================= */
async function getPayPalAccessToken() {
  const auth = Buffer.from(
    `${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`
  ).toString("base64");

  const response = await fetch(
    "https://api-m.paypal.com/v1/oauth2/token",
    {
      method: "POST",
      headers: {
        Authorization: `Basic ${auth}`,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: "grant_type=client_credentials"
    }
  );

  const data = await response.json();
  return data.access_token;
}

/* =========================
   PAYPAL WEBHOOK VERIFY
   ========================= */
async function verifyPayPalWebhook(headers, body) {
  const accessToken = await getPayPalAccessToken();

  const response = await fetch(
    "https://api-m.paypal.com/v1/notifications/verify-webhook-signature",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        auth_algo: headers["paypal-auth-algo"],
        cert_url: headers["paypal-cert-url"],
        transmission_id: headers["paypal-transmission-id"],
        transmission_sig: headers["paypal-transmission-sig"],
        transmission_time: headers["paypal-transmission-time"],
        webhook_id: PAYPAL_WEBHOOK_ID,
        webhook_event: JSON.parse(body.toString())
      })
    }
  );

  const data = await response.json();
  return data.verification_status === "SUCCESS";
}

/* =========================
   PAYPAL WEBHOOK ENDPOINT
   ========================= */
app.post("/paypal/webhook", async (req, res) => {
  try {
    const isValid = await verifyPayPalWebhook(req.headers, req.body);

    if (!isValid) {
      console.error("❌ Invalid PayPal webhook signature");
      return res.status(400).send("Invalid webhook");
    }

    const event = JSON.parse(req.body.toString());

    console.log("✅ PayPal Event:", event.event_type);

    /* =========================
       HANDLE SUBSCRIPTION EVENTS
       ========================= */
    switch (event.event_type) {
      case "BILLING.SUBSCRIPTION.ACTIVATED":
        console.log("🟢 Subscription Activated:", event.resource.id);
        // TODO: mark user ACTIVE in DB
        break;

      case "BILLING.SUBSCRIPTION.CANCELLED":
        console.log("🔴 Subscription Cancelled:", event.resource.id);
        // TODO: soft-lock license
        break;

      case "BILLING.SUBSCRIPTION.SUSPENDED":
        console.log("🟠 Subscription Suspended:", event.resource.id);
        // TODO: soft-lock license
        break;

      case "PAYMENT.SALE.DENIED":
      case "PAYMENT.SALE.FAILED":
        console.log("🔴 Payment Failed");
        // TODO: soft-lock license
        break;

      default:
        console.log("ℹ️ Unhandled event:", event.event_type);
    }

    res.status(200).send("OK");
  } catch (err) {
    console.error("Webhook error:", err);
    res.status(500).send("Server error");
  }
});

/* =========================
   START SERVER
   ========================= */
app.listen(PORT, () => {
  console.log(`🚀 CandleScalpEA API listening on port ${PORT}`);
});
