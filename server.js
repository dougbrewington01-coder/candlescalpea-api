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
app.set("trust proxy", 1);

// IMPORTANT:
// - PayPal webhook MUST receive RAW body for signature verification.
// - Everything else uses normal JSON.
app.use(express.json({ limit: "1mb" }));

// ✅ CORS (FIX for Register/Login from https://candlescalpea.com)
// If your static site is on candlescalpea.com and API is on a different domain,
// the browser will BLOCK requests unless we allow it here.
const SITE_ORIGIN = (process.env.SITE_ORIGIN || "https://candlescalpea.com").trim();

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", SITE_ORIGIN);
  res.header("Vary", "Origin");
  res.header("Access-Control-Allow-Credentials", "true");
  res.header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, x-csea-key");

  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ------------------------------
// ENV / CONFIG
// ------------------------------
const PORT = process.env.PORT || 3000;

const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID || "";
const PAYPAL_SECRET = process.env.PAYPAL_SECRET || "";
const PAYPAL_WEBHOOK_ID = process.env.PAYPAL_WEBHOOK_ID || "";

const CSEA_API_KEY = process.env.CSEA_API_KEY || "";

const SESSION_SECRET = process.env.SESSION_SECRET || "";
if (!SESSION_SECRET) {
  console.warn("WARNING: SESSION_SECRET is missing. Add it in DigitalOcean env vars.");
}

const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();

const PAYPAL_BASE =
  process.env.PAYPAL_ENV === "sandbox"
    ? "https://api-m.sandbox.paypal.com"
    : "https://api-m.paypal.com";

// ------------------------------
// SESSION (REAL LOGIN)
// ------------------------------
// DO NOTE:
// secure cookies require HTTPS. DO is HTTPS, but to avoid edge cases,
// we only force secure=true when we believe we're behind HTTPS proxy.
const FORCE_SECURE_COOKIE = (process.env.FORCE_SECURE_COOKIE || "true").toLowerCase() === "true";

app.use(
  session({
    name: "csea_sid",
    secret: SESSION_SECRET || "dev-only-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "none",
      secure: true
      domain: ".candlescalpea.com",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    },
  })
);

// ------------------------------
// STORAGE (JSON FILE + SAFE FALLBACK)
// ------------------------------
// Your original approach writes to /data/users.json.
// On some deployments, that write can fail.
// We keep the file DB, but add a fallback so your site doesn't break.

const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.join(process.cwd(), "data");

const USERS_FILE = path.join(DATA_DIR, "users.json");

// In-memory fallback store (only used if disk is not writable)
let MEMORY_USERS = null; // null means "not in memory mode"

function nowISO() {
  return new Date().toISOString();
}

function ensureDataStore() {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "[]", "utf8");
    return true;
  } catch (e) {
    // Disk not writable / path not allowed
    return false;
  }
}

function readUsers() {
  // If we already switched to memory mode:
  if (MEMORY_USERS) return MEMORY_USERS;

  // Try disk:
  const ok = ensureDataStore();
  if (!ok) {
    // Switch to memory mode automatically
    if (!MEMORY_USERS) MEMORY_USERS = [];
    return MEMORY_USERS;
  }

  try {
    const raw = fs.readFileSync(USERS_FILE, "utf8") || "[]";
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

function writeUsers(users) {
  // If in memory mode, keep it there
  if (MEMORY_USERS) {
    MEMORY_USERS = users;
    return true;
  }

  // Try disk write
  const ok = ensureDataStore();
  if (!ok) {
    // Switch to memory mode if disk write fails
    MEMORY_USERS = users;
    return false;
  }

  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), "utf8");
    return true;
  } catch {
    // Switch to memory mode if disk write fails
    MEMORY_USERS = users;
    return false;
  }
}

// Optional helper endpoint (so YOU can see what storage mode it's in)
app.get("/api/storage", (req, res) => {
  return res.json({
    ok: true,
    mode: MEMORY_USERS ? "memory_fallback" : "file_json",
    data_dir: DATA_DIR,
    users_file: USERS_FILE,
  });
});

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

  // ✅ EDIT: remove email verification requirement (no email service)
  // if (user.email_verified === false) return { ok: false, reason: "email_unverified" };

  const status = normStr(user.subscription_status).toLowerCase();

  if (status === "locked") return { ok: false, reason: "account_locked" };
  if (status !== "active") return { ok: false, reason: "subscription_inactive" };

  if (user.mt5_account && String(user.mt5_account) !== String(mt5Account)) {
    return { ok: false, reason: "mt5_mismatch" };
  }

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

    // ✅ EDIT: no email verification tokens / no verify email flow
    const user = {
      email,
      password_hash,
      email_verified: true,        // ✅ auto-verified (no email service)
      email_verify_token: "",      // ✅ unused
      subscription_status: "active", // you can change later via PayPal webhook once you store sub ID
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

    req.session.userEmail = email;

    // ✅ EDIT: no verify_url returned
    return sendOk(res, { message: "registered" });
  } catch {
    return sendNo(res, "server_error", 500);
  }
});

// ✅ EDIT: removed /api/verify-email route entirely (no email verification)

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

  // ✅ EDIT: email_verified is always true now, but keep field for UI compatibility
  const license_active = subscription_active && status !== "locked";

  return res.status(200).json({
    ok: true,
    email: user.email,
    email_verified: true, // ✅ always true (no email service)
    subscription_active,
    subscription_status: user.subscription_status,
    license_active,
    mt5_account: user.mt5_account || "",
    nickname: user.nickname || "",
  });
});

app.post("/api/mt5/bind", requireLogin, (req, res) => {
  try {
    const mt5 = normStr(req.body?.mt5);
    const nickname = normStr(req.body?.nickname);

    if (!mt5 || !isDigits(mt5)) return sendNo(res, "bad_mt5", 400);
    if (!nickname) return sendNo(res, "missing_nickname", 400);

    const users = readUsers();
    const user = getUserByEmail(users, req.session.userEmail);
    if (!user) return sendNo(res, "user_not_found", 404);

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

app.get("/api/download", requireLogin, (req, res) => {
  const users = readUsers();
  const user = getUserByEmail(users, req.session.userEmail);
  if (!user) return sendNo(res, "user_not_found", 404);

  const status = normStr(user.subscription_status).toLowerCase();

  // ✅ EDIT: removed email verification requirement
  // if (!user.email_verified) return sendNo(res, "email_unverified", 403);
  if (status !== "active") return sendNo(res, "subscription_inactive", 403);

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
    const allowed = ["active", "past_due", "canceled", "locked"];
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
// DEV ROUTES (KEEPING YOURS)
// ------------------------------
app.post("/admin/dev-upsert-user", (req, res) => {
  try {
    const body = req.body || {};
    const email = normStr(body.email);
    const nickname = body.nickname;
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
        password_hash: "",
        email_verified,
        email_verify_token: "",
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

app.post("/api/auth/register", async (req, res) => {
  const { email, password, confirm_password } = req.body;

  if (!email || !password || !confirm_password) {
    return res.status(400).json({ ok: false, error: "Missing fields" });
  }

  if (password !== confirm_password) {
    return res.status(400).json({ ok: false, error: "Passwords do not match" });
  }

  return res.json({ ok: true });
});

// ------------------------------
// LISTEN
// ------------------------------
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server listening on port ${PORT}`);
});
