-- USERS
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

-- CUSTOMER SETTINGS (MT5 + nickname)
CREATE TABLE IF NOT EXISTS customer_profile (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  mt5_account TEXT,
  nickname TEXT,
  updated_at TIMESTAMP NOT NULL DEFAULT now()
);

-- SUBSCRIPTIONS (updated by PayPal webhook later)
CREATE TABLE IF NOT EXISTS subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  paypal_subscription_id TEXT UNIQUE,
  status TEXT NOT NULL DEFAULT 'inactive', -- active | inactive | past_due | canceled
  plan_name TEXT NOT NULL DEFAULT '$50 / month',
  updated_at TIMESTAMP NOT NULL DEFAULT now()
);

-- EA INSTALL / RUNNING PINGS (EA calls this later)
CREATE TABLE IF NOT EXISTS ea_installs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  mt5_account TEXT,
  nickname TEXT,
  last_seen TIMESTAMP NOT NULL DEFAULT now()
);
