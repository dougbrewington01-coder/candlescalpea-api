// ==============================
// server.js (FULL FILE - FINAL)
// PayPal Webhooks + License Check (Clean YES/NO)
// ES Modules version
// ==============================

import express from "express";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import fetch from "node-fetch";

// ------------------------------
// APP SETUP
// ------------------------------
const app = express();

// IMPORTANT:
// - PayPal webhook MUST receive RAW body for signature verification.
// - Everything else uses normal JSON.
app.use(express.json({ limit: "1mb" }));

// ------------------------------
// ENV / CONFIG
// ------------------------------
const PORT = process.env.PORT || 8080;

// REQUIRED (set in your App Platform env vars):
// PAYPAL_CLIENT_ID=...
// PAYPAL_SECRET=...
// PAYPAL_WEBHOOK_ID=...
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID || "";
const PAYPAL_SECRET = process.env.PAYPAL_SECRET || "";
const PAYPAL_WEBHOOK_ID = process.env.PAYPAL_WEBHOOK_ID || "";

// OPTIONAL (recommended): EA sends this header: x-csea-key
// CSEA_API_KEY=some-long-random
const CSEA_API_KEY = process.env.CSEA_API_KEY || "";

// Live vs Sandbox
const PAYPAL_BASE =
  process.env.PAYPAL_ENV === "sandbox"
    ? "https://api-m.sandbox.paypal.com"
    : "https://api-m.paypal.com";

// ------------------------------
// SIMPLE JSON "DB"
// ------------------------------
const DATA_DIR = path.join(process.cwd(), "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");

// users.json example shape:
// [
//   {
//     "email": "user@email.com",
//     "email_verified": true,
//     "subscription_status": "active",   // active | past_due | canceled | locked
//     "paypal_subscription_id": "I-XXXX",
//     "paypal_payer_id": "XXXX",
//     "nickname": "Domino",              // CASE-SENSITIVE
//     "mt5_account": "12345678",         // optional bind
//     "promo_used": "",
//     "created_at": "2025-12-27T00:00:00Z",
//     "updated_at": "2025-12-27T00:00:00Z"
//   }
// ]

function ensureDataStore() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "[]", "utf8");
}

function readUsers() {
  ensureDataStore();
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, "utf8") || "[]");
  } catch {
    return [];
  }
}

function writeUsers(users) {
  ensureDataStore();
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), "utf8");
}

function nowISO() {
  return new Date().toISOString();
}

// ------------------------------
// HELPERS
// ------------------------------
function normStr(v) {
  return typeof v === "string" ? v.trim() : "";
}

function isDigits(v) {
  return /^[0-9]+$/.test(v);
}

function sendOk(res) {
  return res.status(200).json({ ok: true });
}

function sendNo(res, reason = "not_allowed") {
  return res.status(200).json({ ok: false, reason: String(reason || "not_allowed") });
}

// OPTIONAL: protect endpoints with API key (timing-safe)
function checkApiKey(req) {
  if (!CSEA_API_KEY) return true; // if not set, skip enforcement
  const got = (req.headers["x-csea-key"] || "").toString().trim();
  if (!got) return false;
  if (got.length !== CSEA_API_KEY.length) return false;
  return crypto.timingSafeEqual(Buffer.from(got), Buffer.from(CSEA_API_KEY));
}

// ------------------------------
// PAYPAL API HELPERS (NO SDK)
// ------------------------------
async function paypalGetAccessToken() {
  if (!PAYPAL_CLIENT_ID || !PAYPAL_SECRET) {
    throw new Error("Missing PayPal credentials");
  }

  const basic = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_SECRET}`).toString("base64");

  const resp = await fetch(`${PAYPAL_BASE}/v1/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`PayPal token error: ${resp.status} ${text}`);
  }

  const data = await resp.json();
  return data.access_token;
}

async function paypalVerifyWebhookSignature({ headers, rawBody }) {
  if (!PAYPAL_WEBHOOK_ID) throw new Error("Missing PAYPAL_WEBHOOK_ID");

  const accessToken = await paypalGetAccessToken();

  const body = {
    auth_algo: headers["paypal-auth-algo"],
    cert_url: headers["paypal-cert-url"],
    transmission_id: headers["paypal-transmission-id"],
    transmission_sig: headers["paypal-transmission-sig"],
    transmission_time: headers["paypal-transmission-time"],
    webhook_id: PAYPAL_WEBHOOK_ID,
    webhook_event: JSON.parse(rawBody || "{}"),
  };

  const resp = await fetch(`${PAYPAL_BASE}/v1/notifications/verify-webhook-signature`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Verify webhook error: ${resp.status} ${text}`);
  }

  const data = await resp.json();
  return data.verification_status === "SUCCESS";
}

// ------------------------------
// USER LOOKUPS (CASE-SENSITIVE nickname)
// ------------------------------
function getUserByNickname(users, nickname) {
  return users.find((u) => u.nickname === nickname) || null;
}

function getUserBySubscriptionId(users, subId) {
  const id = normStr(subId);
  return users.find((u) => normStr(u.paypal_subscription_id) === id) || null;
}

// ------------------------------
// LICENSE DECISION (CLEAN YES/NO)
// ------------------------------
function evaluateLicense(user, mt5Account) {
  if (!user) return { ok: false, reason: "user_not_found" };

  if (user.email_verified === false) return { ok: false, reason: "email_unverified" };

  const status = normStr(user.subscription_status).toLowerCase();

  if (status === "locked") return { ok: false, reason: "account_locked" };
  if (status !== "active") return { ok: false, reason: "subscription_inactive" };

  // MT5 bind rule: if already bound, must match
  if (user.mt5_account && String(user.mt5_account) !== String(mt5Account)) {
    return { ok: false, reason: "mt5_mismatch" };
  }

  return { ok: true };
}

// If active + not bound => bind now (first successful license check binds MT5)
function bindMt5IfNeeded(users, user, mt5Account) {
  if (!user.mt5_account) {
    user.mt5_account = String(mt5Account);
    user.updated_at = nowISO();
    writeUsers(users);
  }
}

// ------------------------------
// LICENSE CHECK ROUTES (EA calls these)
// Always returns 200 + JSON {ok:true/false}
// ------------------------------
async function licenseCheckHandler(req, res) {
  try {
    if (!checkApiKey(req)) return sendNo(res, "bad_api_key");

    const nickname = normStr(req.body?.nickname ?? req.query?.nickname);
    const mt5 = normStr(
      req.body?.mt5 ??
        req.body?.account ??
        req.body?.mt5_account ??
        req.query?.mt5 ??
        req.query?.account ??
        req.query?.mt5_account
    );

    if (!nickname) return sendNo(res, "missing_nickname");
    if (!mt5 || !isDigits(mt5)) return sendNo(res, "missing_or_bad_mt5");

    const users = readUsers();
    const user = getUserByNickname(users, nickname);

    const result = evaluateLicense(user, mt5);
    if (!result.ok) return sendNo(res, result.reason || "not_allowed");

    bindMt5IfNeeded(users, user, mt5);
    return sendOk(res);
  } catch {
    return sendNo(res, "server_error");
  }
}

// Aliases so any EA path still works
app.post("/license/check", licenseCheckHandler);
app.post("/api/license/check", licenseCheckHandler);
app.post("/license", licenseCheckHandler);
app.post("/api/license", licenseCheckHandler);

app.get("/license/check", licenseCheckHandler);
app.get("/api/license/check", licenseCheckHandler);
app.get("/license", licenseCheckHandler);
app.get("/api/license", licenseCheckHandler);

// ------------------------------
// PAYPAL WEBHOOK (RAW BODY + VERIFY)
// ------------------------------
app.post("/paypal/webhook", express.raw({ type: "*/*", limit: "2mb" }), async (req, res) => {
  try {
    const rawBody = req.body ? req.body.toString("utf8") : "";

    // Verify signature (PRODUCTION SAFE)
    const verified = await paypalVerifyWebhookSignature({
      headers: req.headers,
      rawBody,
    });

    if (!verified) {
      // return 200 so PayPal doesn't hammer retries
      return res.status(200).json({ ok: false, reason: "webhook_not_verified" });
    }

    let event = {};
    try {
      event = rawBody ? JSON.parse(rawBody) : {};
    } catch {
      return res.status(200).json({ ok: false, reason: "bad_json" });
    }

    const eventType = normStr(event.event_type).toUpperCase();
    const resource = event.resource || {};
    const subscriptionId = normStr(resource.id);

    const users = readUsers();
    const user = subscriptionId ? getUserBySubscriptionId(users, subscriptionId) : null;

    // If we can’t map it, just acknowledge
    if (!user) return res.status(200).json({ ok: true, note: "no_user_match" });

    // Map PayPal event -> your subscription_status
    if (eventType === "BILLING.SUBSCRIPTION.ACTIVATED") {
      user.subscription_status = "active";
      user.updated_at = nowISO();
      writeUsers(users);
    } else if (eventType === "BILLING.SUBSCRIPTION.CANCELLED") {
      user.subscription_status = "canceled";
      user.updated_at = nowISO();
      writeUsers(users);
    } else if (eventType === "BILLING.SUBSCRIPTION.SUSPENDED") {
      user.subscription_status = "past_due";
      user.updated_at = nowISO();
      writeUsers(users);
    } else if (eventType === "BILLING.SUBSCRIPTION.EXPIRED") {
      user.subscription_status = "canceled";
      user.updated_at = nowISO();
      writeUsers(users);
    } else if (eventType === "BILLING.SUBSCRIPTION.UPDATED") {
      user.updated_at = nowISO();
      writeUsers(users);
    }

    // Optional: payment completion can mark active (unless locked)
    if (eventType === "PAYMENT.CAPTURE.COMPLETED" || eventType === "PAYMENT.SALE.COMPLETED") {
      if (normStr(user.subscription_status).toLowerCase() !== "locked") {
        user.subscription_status = "active";
        user.updated_at = nowISO();
        writeUsers(users);
      }
    }

    return res.status(200).json({ ok: true });
  } catch {
    // Always 200 to stop retry storms
    return res.status(200).json({ ok: false, reason: "webhook_error" });
  }
});

// ------------------------------
// ADMIN-HELPER ENDPOINTS (OPTIONAL)
// ------------------------------
app.post("/admin/dev-upsert-user", (req, res) => {
  try {
    const body = req.body || {};
    const email = normStr(body.email);
    const nickname = body.nickname; // KEEP CASE-SENSITIVE as given
    const paypal_subscription_id = normStr(body.paypal_subscription_id);
    const email_verified = !!body.email_verified;

    if (!email || !nickname) {
      return res.status(200).json({ ok: false, reason: "missing_email_or_nickname" });
    }

    const users = readUsers();
    let user = users.find((u) => normStr(u.email).toLowerCase() === email.toLowerCase());

    if (!user) {
      user = {
        email,
        email_verified,
        subscription_status: normStr(body.subscription_status) || "active",
        paypal_subscription_id: paypal_subscription_id || "",
        paypal_payer_id: normStr(body.paypal_payer_id) || "",
        nickname,
        mt5_account: normStr(body.mt5_account) || "",
        promo_used: normStr(body.promo_used) || "",
        created_at: nowISO(),
        updated_at: nowISO(),
      };
      users.push(user);
    } else {
      user.email = email;
      user.nickname = nickname;
      if (paypal_subscription_id) user.paypal_subscription_id = paypal_subscription_id;
      user.email_verified = email_verified;
      if (body.subscription_status) user.subscription_status = normStr(body.subscription_status);
      if (body.mt5_account !== undefined) user.mt5_account = normStr(body.mt5_account);
      user.updated_at = nowISO();
    }

    writeUsers(users);
    return res.status(200).json({ ok: true });
  } catch {
    return res.status(200).json({ ok: false, reason: "server_error" });
  }
});

app.get("/admin/dev-users", (req, res) => {
  const users = readUsers();
  return res.status(200).json({ ok: true, users });
});

// ------------------------------
// HEALTH
// ------------------------------
app.get("/", (req, res) => res.status(200).send("CandleScalpEA API is running."));
app.get("/health", (req, res) => res.status(200).json({ ok: true }));

// HEALTH CHECK
app.get("/health", (req, res) => {
  res.status(200).json({ ok: true });
});

// ------------------------------
// LISTEN
// ------------------------------
const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0');
});
