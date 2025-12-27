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

// ------------------------------
// RAW BODY CAPTURE (PAYPAL ONLY)
// ------------------------------
app.use(
  "/paypal/webhook",
  express.raw({ type: "*/*", limit: "2mb" })
);

// ------------------------------
// JSON BODY (EVERYTHING ELSE)
// ------------------------------
app.use(express.json({ limit: "1mb" }));

// ------------------------------
// ENV / CONFIG
// ------------------------------
const PORT = process.env.PORT || 3000;

const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID || "";
const PAYPAL_SECRET = process.env.PAYPAL_SECRET || "";
const PAYPAL_WEBHOOK_ID = process.env.PAYPAL_WEBHOOK_ID || "";

const CSEA_API_KEY = process.env.CSEA_API_KEY || "";

const PAYPAL_BASE =
  process.env.PAYPAL_ENV === "sandbox"
    ? "https://api-m.sandbox.paypal.com"
    : "https://api-m.paypal.com";

// ------------------------------
// SIMPLE JSON "DB"
// ------------------------------
const DATA_DIR = path.join(process.cwd(), "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");

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
  return res.status(200).json({ ok: false, reason: String(reason) });
}

function checkApiKey(req) {
  if (!CSEA_API_KEY) return true;
  const got = (req.headers["x-csea-key"] || "").toString().trim();
  if (!got || got.length !== CSEA_API_KEY.length) return false;
  return crypto.timingSafeEqual(Buffer.from(got), Buffer.from(CSEA_API_KEY));
}

// ------------------------------
// PAYPAL API HELPERS
// ------------------------------
async function paypalGetAccessToken() {
  const basic = Buffer.from(
    `${PAYPAL_CLIENT_ID}:${PAYPAL_SECRET}`
  ).toString("base64");

  const resp = await fetch(`${PAYPAL_BASE}/v1/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });

  const data = await resp.json();
  return data.access_token;
}

async function paypalVerifyWebhookSignature({ headers, rawBody }) {
  const accessToken = await paypalGetAccessToken();

  const body = {
    auth_algo: headers["paypal-auth-algo"],
    cert_url: headers["paypal-cert-url"],
    transmission_id: headers["paypal-transmission-id"],
    transmission_sig: headers["paypal-transmission-sig"],
    transmission_time: headers["paypal-transmission-time"],
    webhook_id: PAYPAL_WEBHOOK_ID,
    webhook_event: JSON.parse(rawBody),
  };

  const resp = await fetch(
    `${PAYPAL_BASE}/v1/notifications/verify-webhook-signature`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    }
  );

  const data = await resp.json();
  return data.verification_status === "SUCCESS";
}

// ------------------------------
// LICENSE LOGIC (UNCHANGED)
// ------------------------------
function evaluateLicense(user, mt5Account) {
  if (!user) return { ok: false, reason: "user_not_found" };
  if (user.email_verified === false)
    return { ok: false, reason: "email_unverified" };

  const status = normStr(user.subscription_status).toLowerCase();
  if (status !== "active")
    return { ok: false, reason: "subscription_inactive" };

  if (user.mt5_account && String(user.mt5_account) !== String(mt5Account))
    return { ok: false, reason: "mt5_mismatch" };

  return { ok: true };
}

function bindMt5IfNeeded(users, user, mt5Account) {
  if (!user.mt5_account) {
    user.mt5_account = String(mt5Account);
    user.updated_at = nowISO();
    writeUsers(users);
  }
}

// ------------------------------
// LICENSE ROUTES (UNCHANGED)
// ------------------------------
async function licenseCheckHandler(req, res) {
  try {
    if (!checkApiKey(req)) return sendNo(res, "bad_api_key");

    const nickname = normStr(req.body?.nickname ?? req.query?.nickname);
    const mt5 = normStr(req.body?.mt5 ?? req.query?.mt5);

    if (!nickname) return sendNo(res, "missing_nickname");
    if (!mt5 || !isDigits(mt5)) return sendNo(res, "missing_or_bad_mt5");

    const users = readUsers();
    const user = users.find((u) => u.nickname === nickname);

    const result = evaluateLicense(user, mt5);
    if (!result.ok) return sendNo(res, result.reason);

    bindMt5IfNeeded(users, user, mt5);
    return sendOk(res);
  } catch {
    return sendNo(res, "server_error");
  }
}

app.all("/license", licenseCheckHandler);
app.all("/license/check", licenseCheckHandler);
app.all("/api/license", licenseCheckHandler);
app.all("/api/license/check", licenseCheckHandler);

// ------------------------------
// PAYPAL WEBHOOK (FIXED)
// ------------------------------
app.post("/paypal/webhook", async (req, res) => {
  try {
    const rawBody = req.body.toString("utf8");

    const verified = await paypalVerifyWebhookSignature({
      headers: req.headers,
      rawBody,
    });

    if (!verified) return res.status(200).json({ ok: false });

    return res.status(200).json({ ok: true });
  } catch {
    return res.status(200).json({ ok: false });
  }
});

// ------------------------------
// HEALTH
// ------------------------------
app.get("/", (req, res) =>
  res.status(200).send("CandleScalpEA API is running.")
);

app.get("/health", (req, res) =>
  res.status(200).json({ ok: true })
);

// ------------------------------
// LISTEN
// ------------------------------
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server listening on port ${PORT}`);
});
