// ==============================
// server.js (FULL FILE - LIVE AUTH)
// PayPal Webhooks + License Check + REAL Login/Register/Admin
// ES Modules version
// ==============================

import express from "express";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import fetch from "node-fetch";
import session from "express-session";
import bcrypt from "bcryptjs";

// ------------------------------
// APP SETUP
// ------------------------------
const app = express();

// DigitalOcean App Platform runs behind a proxy (needed for secure cookies)
app.set("trust proxy", 1);

// IMPORTANT:
// - PayPal webhook MUST receive RAW body for signature verification.
// - Everything else uses normal JSON.
app.use(express.json({ limit: "1mb" }));

// ------------------------------
// ENV / CONFIG
// ------------------------------
const PORT = process.env.PORT || 3000;

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

// REQUIRED for login sessions:
const SESSION_SECRET = process.env.SESSION_SECRET || "";
if (!SESSION_SECRET) {
  console.warn("WARNING: SESSION_SECRET is missing. Add it in DigitalOcean env vars.");
}

// Admin identity (your email). Add this env var in DO:
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();

// Live vs Sandbox
const PAYPAL_BASE =
  process.env.PAYPAL_ENV === "sandbox"
    ? "https://api-m.sandbox.paypal.com"
    : "https://api-m.paypal.com";

// ------------------------------
// SESSION (REAL LOGIN)
// ------------------------------
app.use(
  session({
    name: "csea_sid",
    secret: SESSION_SECRET || "dev-only-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    },
  })
);

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

function sendOk(res, extra = {}) {
  return res.status(200).json({ ok: true, ...extra });
}

function sendNo(res, reason = "not_allowed", code = 200) {
  return res.status(code).json({ ok: false, reason: String(reason || "not_allowed") });
}

// OPTIONAL: protect endpoints with API key (timing-safe)
function checkApiKey(req) {
  if (!CSEA_API_KEY) return true; // if not set, skip enforcement
  const got = (req.headers["x-csea-key"] || "").toString().trim();
  if (!got) return false;
  if (got.length !== CSEA_API_KEY.length) return false;
  return crypto.timingSafeEqual(Buffer.from(got), Buffer.from(CSEA_API_KEY));
}

function safeEmail(email) {
  return normStr(email).toLowerCase();
}

// ------------------------------
// AUTH HELPERS
// ------------------------------
function requireLogin(req, res, next) {
  if (!req.session?.userEmail) return sendNo(res, "not_logged_in", 401);
  next();
}

function requireAdmin(req, res, next) {
  const e = (req.session?.userEmail || "").toLowerCase();
  if (!e) return sendNo(res, "not_logged_in", 401);
  if (!ADMIN_EMAIL) return sendNo(res, "admin_not_configured", 403);
  if (e !== ADMIN_EMAIL) return sendNo(res, "not_admin", 403);
  next();
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

function getUserByEmail(users, email) {
  const e = safeEmail(email);
  return users.find((u) => safeEmail(u.email) === e) || null;
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
// AUTH ROUTES (REAL)
// ------------------------------
app.post("/api/register", async (req, res) => {
  try {
    const email = safeEmail(req.body?.email);
    const password = normStr(req.body?.password);
    const confirm = normStr(req.body?.confirm_password ?? req.body?.confirmPassword ?? "");

    if (!email || !email.includes("@")) return sendNo(res, "bad_email", 400);
    if (!password || password.length < 8) return sendNo(res, "password_too_short", 400);
    if (!confirm || confirm !== password) return sendNo(res, "passwords_do_not_match", 400);

    const users = readUsers();
    if (getUserByEmail(users, email)) return sendNo(res, "email_exists", 409);

    const password_hash = await bcrypt.hash(password, 12);
    const email_verify_token = crypto.randomBytes(24).toString("hex");

    const user = {
      email,
      password_hash,
      email_verified: false,
      email_verify_token,
      subscription_status: "inactive", // IMPORTANT: PayPal/webhook/admin sets to active
      paypal_subscription_id: "",
      paypal_payer_id: "",
      nickname: "",
      mt5_account: "",
      promo_used: "",
      created_at: nowISO(),
      updated_at: nowISO(),
    };

    users.push(user);
    writeUsers(users);

    // Create session immediately (user is logged in)
    req.session.userEmail = email;

    // No email service wired yet -> return verification link to show on screen
    return sendOk(res, {
      message: "registered",
      verify_url: `/api/verify-email?email=${encodeURIComponent(email)}&token=${encodeURIComponent(email_verify_token)}`,
    });
  } catch {
    return sendNo(res, "server_error", 500);
  }
});

app.get("/api/verify-email", (req, res) => {
  try {
    const email = safeEmail(req.query?.email);
    const token = normStr(req.query?.token);

    if (!email || !token) return res.status(400).send("Missing email or token.");

    const users = readUsers();
    const user = getUserByEmail(users, email);
    if (!user) return res.status(404).send("User not found.");

    if (user.email_verified) return res.status(200).send("Email already verified.");

    if (user.email_verify_token !== token) return res.status(403).send("Invalid token.");

    user.email_verified = true;
    user.email_verify_token = "";
    user.updated_at = nowISO();
    writeUsers(users);

    return res.status(200).send("Email verified. You can go back to the site and log in.");
  } catch {
    return res.status(500).send("Server error.");
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const email = safeEmail(req.body?.email);
    const password = normStr(req.body?.password);

    if (!email || !password) return sendNo(res, "missing_email_or_password", 400);

    const users = readUsers();
    const user = getUserByEmail(users, email);
    if (!user) return sendNo(res, "bad_login", 401);

    const ok = await bcrypt.compare(password, user.password_hash || "");
    if (!ok) return sendNo(res, "bad_login", 401);

    req.session.userEmail = user.email;

    return sendOk(res, { message: "logged_in" });
  } catch {
    return sendNo(res, "server_error", 500);
  }
});

app.post("/api/logout", (req, res) => {
  try {
    req.session.destroy(() => sendOk(res, { message: "logged_out" }));
  } catch {
    return sendNo(res, "server_error", 500);
  }
});

app.get("/api/me", requireLogin, (req, res) => {
  const users = readUsers();
  const user = getUserByEmail(users, req.session.userEmail);
  if (!user) return sendNo(res, "user_not_found", 404);

  const status = normStr(user.subscription_status).toLowerCase();
  const subscription_active = status === "active";
  const license_active = user.email_verified && subscription_active && status !== "locked";

  return res.status(200).json({
    ok: true,
    email: user.email,
    email_verified: !!user.email_verified,
    subscription_active,
    subscription_status: user.subscription_status,
    license_active,
    mt5_account: user.mt5_account || "",
    nickname: user.nickname || "",
    paypal_subscription_id: user.paypal_subscription_id || "",
  });
});

// ------------------------------
// *** MISSING PIECE: LINK PAYPAL SUBSCRIPTION ID TO USER ***
// This is what makes webhook matching possible.
// ------------------------------
app.post("/api/paypal/link-subscription", requireLogin, (req, res) => {
  try {
    const subId = normStr(req.body?.subscriptionID || req.body?.subscription_id || "");
    if (!subId) return sendNo(res, "missing_subscription_id", 400);

    const users = readUsers();
    const user = getUserByEmail(users, req.session.userEmail);
    if (!user) return sendNo(res, "user_not_found", 404);

    user.paypal_subscription_id = subId;
    user.updated_at = nowISO();
    writeUsers(users);

    return sendOk(res, { message: "subscription_linked" });
  } catch {
    return sendNo(res, "server_error", 500);
  }
});

// Customer saves MT5 + nickname (requires login)
app.post("/api/mt5/bind", requireLogin, (req, res) => {
  try {
    const mt5 = normStr(req.body?.mt5);
    const nickname = normStr(req.body?.nickname);

    if (!mt5 || !isDigits(mt5)) return sendNo(res, "bad_mt5", 400);
    if (!nickname) return sendNo(res, "missing_nickname", 400);

    const users = readUsers();
    const user = getUserByEmail(users, req.session.userEmail);
    if (!user) return sendNo(res, "user_not_found", 404);

    // If already bound to a different MT5, block (admin can clear it)
    if (user.mt5_account && String(user.mt5_account) !== String(mt5)) {
      return sendNo(res, "mt5_already_bound", 403);
    }

    user.mt5_account = String(mt5);
    user.nickname = nickname; // case-sensitive
    user.updated_at = nowISO();
    writeUsers(users);

    return sendOk(res);
  } catch {
    return sendNo(res, "server_error", 500);
  }
});

// Download endpoint (requires verified + active)
app.get("/api/download", requireLogin, (req, res) => {
  const users = readUsers();
  const user = getUserByEmail(users, req.session.userEmail);
  if (!user) return sendNo(res, "user_not_found", 404);

  const status = normStr(user.subscription_status).toLowerCase();
  if (!user.email_verified) return sendNo(res, "email_unverified", 403);
  if (status !== "active") return sendNo(res, "subscription_inactive", 403);

  // You can swap this later to a real file download (S3/GitHub release/etc.)
  return res.status(200).send("Download endpoint is live. Wire to your EA file next.");
});

// ------------------------------
// ADMIN ROUTES (REAL)
// ------------------------------
app.get("/api/admin/me", requireAdmin, (req, res) => {
  return sendOk(res, { admin: true, email: req.session.userEmail });
});

app.get("/api/admin/users", requireAdmin, (req, res) => {
  const users = readUsers().map((u) => ({
    email: u.email,
    email_verified: !!u.email_verified,
    subscription_status: u.subscription_status,
    mt5_account: u.mt5_account || "",
    nickname: u.nickname || "",
    paypal_subscription_id: u.paypal_subscription_id || "",
    promo_used: u.promo_used || "",
    created_at: u.created_at,
    updated_at: u.updated_at,
  }));
  return sendOk(res, { users });
});

app.post("/api/admin/users/delete", requireAdmin, (req, res) => {
  try {
    const email = safeEmail(req.body?.email);
    if (!email) return sendNo(res, "missing_email", 400);

    const users = readUsers();
    const before = users.length;
    const afterUsers = users.filter((u) => safeEmail(u.email) !== email);

    if (afterUsers.length === before) return sendNo(res, "not_found", 404);

    writeUsers(afterUsers);
    return sendOk(res);
  } catch {
    return sendNo(res, "server_error", 500);
  }
});

app.post("/api/admin/clear-mt5", requireAdmin, (req, res) => {
  try {
    const email = safeEmail(req.body?.email);
    if (!email) return sendNo(res, "missing_email", 400);

    const users = readUsers();
    const user = getUserByEmail(users, email);
    if (!user) return sendNo(res, "not_found", 404);

    user.mt5_account = "";
    user.updated_at = nowISO();
    writeUsers(users);

    return sendOk(res);
  } catch {
    return sendNo(res, "server_error", 500);
  }
});

app.post("/api/admin/set-status", requireAdmin, (req, res) => {
  try {
    const email = safeEmail(req.body?.email);
    const status = normStr(req.body?.status).toLowerCase();
    const allowed = ["active", "inactive", "past_due", "canceled", "locked"];

    if (!email) return sendNo(res, "missing_email", 400);
    if (!allowed.includes(status)) return sendNo(res, "bad_status", 400);

    const users = readUsers();
    const user = getUserByEmail(users, email);
    if (!user) return sendNo(res, "not_found", 404);

    user.subscription_status = status;
    user.updated_at = nowISO();
    writeUsers(users);

    return sendOk(res);
  } catch {
    return sendNo(res, "server_error", 500);
  }
});

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

    const verified = await paypalVerifyWebhookSignature({
      headers: req.headers,
      rawBody,
    });

    if (!verified) {
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

    if (!user) return res.status(200).json({ ok: true, note: "no_user_match" });

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
    return res.status(200).json({ ok: false, reason: "webhook_error" });
  }
});

// ------------------------------
// HEALTH
// ------------------------------
app.get("/", (req, res) => res.status(200).send("CandleScalpEA API is running."));
app.get("/health", (req, res) => res.status(200).json({ ok: true }));

// ------------------------------
// LISTEN
// ------------------------------
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server listening on port ${PORT}`);
});
