// ==============================
// server.js (FULL FILE - FINAL)
// PayPal Webhooks + License Check + AUTH
// ES Modules version
// ==============================

import express from "express";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import fetch from "node-fetch";
import session from "express-session";

// ------------------------------
// APP SETUP
// ------------------------------
const app = express();

app.use(express.json({ limit: "1mb" }));

app.use(
  session({
    name: "csea.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true,
      httpOnly: true,
      sameSite: "lax",
    },
  })
);

// ------------------------------
// ENV / CONFIG
// ------------------------------
const PORT = process.env.PORT || 8080;

const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID || "";
const PAYPAL_SECRET = process.env.PAYPAL_CLIENT_SECRET || "";
const PAYPAL_WEBHOOK_ID = process.env.PAYPAL_WEBHOOK_ID || "";

const PAYPAL_BASE =
  process.env.PAYPAL_ENV === "sandbox"
    ? "https://api-m.sandbox.paypal.com"
    : "https://api-m.paypal.com";

// ------------------------------
// SIMPLE JSON DB
// ------------------------------
const DATA_DIR = path.join(process.cwd(), "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");

function ensureDataStore() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "[]", "utf8");
}

function readUsers() {
  ensureDataStore();
  return JSON.parse(fs.readFileSync(USERS_FILE, "utf8") || "[]");
}

function writeUsers(users) {
  ensureDataStore();
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), "utf8");
}

function nowISO() {
  return new Date().toISOString();
}

// ------------------------------
// AUTH HELPERS
// ------------------------------
function hashPassword(pw) {
  return crypto.createHash("sha256").update(pw).digest("hex");
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ ok: false });
  }
  next();
}

// ------------------------------
// AUTH ROUTES
// ------------------------------
app.post("/api/auth/register", (req, res) => {
  const { email, password, nickname } = req.body;

  if (!email || !password || !nickname) {
    return res.status(400).json({ ok: false });
  }

  const users = readUsers();
  if (users.find((u) => u.email === email)) {
    return res.status(400).json({ ok: false });
  }

  const user = {
    email,
    password_hash: hashPassword(password),
    nickname,
    email_verified: true,
    subscription_status: "inactive",
    created_at: nowISO(),
    updated_at: nowISO(),
  };

  users.push(user);
  writeUsers(users);

  req.session.userId = email;

  res.json({ ok: true });
});

app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;

  const users = readUsers();
  const user = users.find(
    (u) => u.email === email && u.password_hash === hashPassword(password)
  );

  if (!user) {
    return res.status(401).json({ ok: false });
  }

  req.session.userId = user.email;
  res.json({ ok: true });
});

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  const users = readUsers();
  const user = users.find((u) => u.email === req.session.userId);
  if (!user) return res.status(401).json({ ok: false });

  res.json({
    ok: true,
    email: user.email,
    nickname: user.nickname,
    subscription_status: user.subscription_status,
  });
});

// ------------------------------
// PAYPAL HELPERS (UNCHANGED)
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

// ------------------------------
// HEALTH
// ------------------------------
app.get("/", (req, res) => res.send("CandleScalpEA API running"));
app.get("/health", (req, res) => res.json({ ok: true }));

// ------------------------------
// LISTEN
// ------------------------------
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server listening on ${PORT}`);
});
