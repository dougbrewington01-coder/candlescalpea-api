import express from "express";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

/*
  TEMP IN-MEMORY STORE
  (Later we will replace this with Postgres automatically)
*/
const USERS = {
  "demo-token": {
    email: "customer@example.com",
    emailVerified: true,
    subscriptionActive: true,
    mt5Account: "123456789",
    nickname: "Domino",
    installDetected: false
  }
};

/*
  AUTH MIDDLEWARE (simple for now)
*/
function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token || !USERS[token]) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  req.user = USERS[token];
  next();
}

/*
  GET /me
  Dashboard user info
*/
app.get("/me", auth, (req, res) => {
  res.json({
    email: req.user.email,
    emailVerified: req.user.emailVerified
  });
});

/*
  GET /subscription
*/
app.get("/subscription", auth, (req, res) => {
  res.json({
    active: req.user.subscriptionActive,
    plan: "$50 / month"
  });
});

/*
  GET /license
*/
app.get("/license", auth, (req, res) => {
  res.json({
    mt5Account: req.user.mt5Account,
    nickname: req.user.nickname,
    installDetected: req.user.installDetected
  });
});

/*
  POST /license
  Save MT5 account + nickname
*/
app.post("/license", auth, (req, res) => {
  const { mt5Account, nickname } = req.body;

  if (!mt5Account || !nickname) {
    return res.status(400).json({ error: "Missing fields" });
  }

  req.user.mt5Account = mt5Account;
  req.user.nickname = nickname;

  res.json({ success: true });
});

/*
  GET /download
*/
app.get("/download", auth, (req, res) => {
  if (!req.user.emailVerified || !req.user.subscriptionActive) {
    return res.status(403).json({ error: "Access denied" });
  }

  res.json({
    url: "https://example.com/CandleScalpEA-v1.31.ex5"
  });
});

/*
  POST /install
  EA phones home after install
*/
app.post("/install", auth, (req, res) => {
  req.user.installDetected = true;
  res.json({ success: true });
});

/*
  HEALTH CHECK
*/
app.get("/", (req, res) => {
  res.send("CandleScalpEA API running");
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`API running on port ${PORT}`);
});
