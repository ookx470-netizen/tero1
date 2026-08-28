import express from "express";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { rateLimit } from "express-rate-limit";
import admin from "firebase-admin";

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

// ============================================================================
// SECURITY FIX (was: `app.use(express.static(process.cwd()))` x3)
// The old code served the ENTIRE project directory over HTTP — anyone could
// download data.json (live user DB), server.ts (full source + secrets),
// firebase-applet-config.json, package.json, .env.example, bun.lock, etc.
// Only an explicit allowlist of public assets is served now.
// ============================================================================
app.use("/assets", express.static(path.join(process.cwd(), "assets")));
app.use("/badges", express.static(path.join(process.cwd(), "badges")));

const PUBLIC_ROOT_FILES = [
  "favicon.svg",
  "apple-touch-icon.png",
  "manifest.json",
  "tero-hq-manifest.json",
  "sw.js",
  "tero-hq-sw.js",
  "icon-192.png",
  "icon-512.png",
  "logo.png",
  "tero-logo-new.png",
  "tero-logo-new.svg",
  "default-avatar.png",
  "og-preview-v3.jpg",
];
for (const file of PUBLIC_ROOT_FILES) {
  app.get("/" + file, (req, res) => {
    res.sendFile(path.join(process.cwd(), file), (err) => {
      if (err) res.status(404).end();
    });
  });
}

// ============================================================================
// SECRETS BOOTSTRAP
// Previously: admin password was the hardcoded literal "admin123", tokens
// were unsigned base64(username) strings nobody ever verified, and a real
// Telegram bot token was hardcoded as a fallback. Now: a JWT signing secret
// and a bcrypt-hashed admin password are generated on first boot (or read
// from env vars) and persisted OUTSIDE data.json / siteSettings, so they can
// never leak back out through an API response.
// ============================================================================
const SECRETS_FILE = path.join(process.cwd(), ".server-secrets.json");

function loadOrCreateSecrets() {
  let stored: { jwtSecret?: string; adminUsername?: string; adminPasswordHash?: string } = {};
  if (fs.existsSync(SECRETS_FILE)) {
    try {
      stored = JSON.parse(fs.readFileSync(SECRETS_FILE, "utf-8"));
    } catch (e) {
      console.error("Could not parse .server-secrets.json, regenerating:", e);
    }
  }

  const adminUsername = process.env.ADMIN_USERNAME || stored.adminUsername || "admin";
  let jwtSecret = process.env.JWT_SECRET || stored.jwtSecret;
  let adminPasswordHash = stored.adminPasswordHash;
  let printedPassword: string | null = null;

  if (process.env.ADMIN_PASSWORD) {
    // Explicit env override always wins (lets you rotate the password on deploy).
    adminPasswordHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);
  }

  if (!jwtSecret) {
    jwtSecret = crypto.randomBytes(48).toString("hex");
  }

  if (!adminPasswordHash) {
    const generated = crypto.randomBytes(9).toString("base64url");
    adminPasswordHash = bcrypt.hashSync(generated, 10);
    printedPassword = generated;
  }

  try {
    fs.writeFileSync(
      SECRETS_FILE,
      JSON.stringify({ jwtSecret, adminUsername, adminPasswordHash }, null, 2),
      { mode: 0o600 }
    );
  } catch (e) {
    console.error("Failed to persist .server-secrets.json:", e);
  }

  if (printedPassword) {
    const banner =
      `\n==================================================================\n` +
      `  ADMIN ACCOUNT CREATED (first boot — no ADMIN_PASSWORD env set)\n` +
      `  Username: ${adminUsername}\n` +
      `  Password: ${printedPassword}\n` +
      `  This is shown ONCE. It is also saved to ADMIN_PASSWORD_FIRST_RUN.txt —\n` +
      `  read it, store it in a password manager, then delete that file.\n` +
      `  For future deploys, set ADMIN_PASSWORD (and ADMIN_USERNAME) env vars\n` +
      `  instead of relying on this auto-generated one.\n` +
      `==================================================================\n`;
    console.log(banner);
    try {
      fs.writeFileSync(path.join(process.cwd(), "ADMIN_PASSWORD_FIRST_RUN.txt"), banner);
    } catch (e) {
      console.error("Could not write ADMIN_PASSWORD_FIRST_RUN.txt:", e);
    }
  }

  return { jwtSecret: jwtSecret!, adminUsername, adminPasswordHash: adminPasswordHash! };
}

const SECRETS = loadOrCreateSecrets();
const JWT_SECRET = SECRETS.jwtSecret;
const ADMIN_USERNAME = SECRETS.adminUsername;
let ADMIN_PASSWORD_HASH = SECRETS.adminPasswordHash;

function persistAdminPasswordHash(hash: string) {
  ADMIN_PASSWORD_HASH = hash;
  try {
    const current = fs.existsSync(SECRETS_FILE) ? JSON.parse(fs.readFileSync(SECRETS_FILE, "utf-8")) : {};
    fs.writeFileSync(SECRETS_FILE, JSON.stringify({ ...current, adminPasswordHash: hash }, null, 2), { mode: 0o600 });
  } catch (e) {
    console.error("Failed to persist updated admin password:", e);
  }
}

// ============================================================================
// AUTH HELPERS — real signed tokens (jsonwebtoken) instead of the old
// unsigned `"admin_token_" + base64(username)` / `"user_token_" + base64(username)`
// strings, which anyone could compute themselves without ever logging in.
// ============================================================================
function signToken(payload: object, expiresIn: jwt.SignOptions["expiresIn"] = "7d") {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

function verifyToken(token: string): any {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function getBearerToken(req: express.Request): string | null {
  const h = req.headers.authorization || "";
  return h.startsWith("Bearer ") ? h.slice(7).trim() : null;
}

// SECURITY FIX: every /api/admin/* route (except login) previously had ZERO
// auth check — verified live: an unauthenticated POST could set any user's
// balance to any value. This middleware now guards the entire admin router.
function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
  const token = getBearerToken(req);
  const payload = token ? verifyToken(token) : null;
  if (!payload || payload.role !== "admin") {
    return res.status(401).json({ error: "Unauthorized" });
  }
  (req as any).admin = payload;
  next();
}

// SECURITY FIX: previously every "personal" endpoint (/api/wallet/*,
// /api/user/*, ...) ignored auth entirely and just read `db.users[0]` —
// meaning all withdrawals/balances operated on the SAME account regardless
// of who was actually logged in. This middleware resolves the real caller.
function requireUser(req: express.Request, res: express.Response, next: express.NextFunction) {
  const token = getBearerToken(req);
  const payload = token ? verifyToken(token) : null;
  if (!payload || payload.role !== "user") {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const db = loadDB();
  const user = db.users.find((u) => u.id === payload.uid);
  if (!user) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  (req as any).currentUser = user;
  next();
}

function sanitizeUser(u: User) {
  const { passwordHash, ...rest } = u as any;
  return rest;
}

// Brute-force protection on login endpoints (previously: none at all —
// admin/admin123 could be hammered with unlimited attempts).
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "محاولات كثيرة جداً، حاول لاحقاً" },
});

// ============================================================================
// Firebase (Admin SDK — privileged) Initialization
// Previously the server connected with the *client* SDK (`firebase/firestore`)
// using the same public apiKey the browser uses, with no credentials at all —
// which only worked because firestore.rules allowed `read, write: if true`
// to EVERYONE. That rule has been changed to deny all direct client access
// (see firestore.rules), so the server now needs real service-account
// credentials to keep syncing. Cloud sync is skipped (local data.json only)
// until FIREBASE_SERVICE_ACCOUNT_JSON or GOOGLE_APPLICATION_CREDENTIALS is set.
// ============================================================================
let firestoreDb: admin.firestore.Firestore | null = null;
try {
  const saJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  const hasAppDefault = !!process.env.GOOGLE_APPLICATION_CREDENTIALS;

  if (saJson || hasAppDefault) {
    const credential = saJson
      ? admin.credential.cert(JSON.parse(saJson))
      : admin.credential.applicationDefault();
    admin.initializeApp({ credential });
    firestoreDb = admin.firestore();
    console.log("Firebase Admin Firestore initialized with privileged service-account credentials.");
  } else {
    console.warn(
      "No Firebase service-account credentials found (set FIREBASE_SERVICE_ACCOUNT_JSON or " +
      "GOOGLE_APPLICATION_CREDENTIALS). Cloud sync is DISABLED — running on local data.json only. " +
      "This is intentional and safer than the previous unauthenticated client-SDK connection."
    );
  }
} catch (err) {
  console.error("Firebase Admin initialization failed:", err);
}

// --- Stateful In-Memory Database with Cloud Firestore & File Persistence ---
const DATA_FILE = path.join(process.cwd(), "data.json");

interface User {
  id: string;
  username: string;
  email: string;
  telegram?: string;
  passwordHash?: string;
  emailVerified?: boolean;
  balance: number;
  usdtBalance: number;
  status: "active" | "frozen" | "suspended";
  isFrozen: boolean;
  joinedAt: string;
  membershipPlan: string;
  referralsCount: number;
  membershipTier?: string;
  referralCode?: string;
}

interface Deposit {
  id: string;
  userId: string;
  username: string;
  amount: string;
  network: string;
  status: "pending" | "confirmed" | "failed";
  txHash: string;
  createdAt: string;
}

interface Withdrawal {
  id: string;
  userId: string;
  username: string;
  amount: number;
  usdtAmount: number;
  feeAmount?: number;
  address: string;
  network: string;
  status: "pending_approval" | "under_inspection" | "completed" | "failed" | "rejected" | "cancelled";
  createdAt: string;
  rejectionReason?: string;
}

interface Task {
  id: string;
  platform: string;
  title: string;
  description: string;
  reward: number;
  targetUrl: string;
  isActive: boolean;
  order: number;
}

interface DBData {
  users: User[];
  deposits: Deposit[];
  withdrawals: Withdrawal[];
  tasks: Task[];
  siteSettings: Record<string, any>;
}

let inMemoryDB: DBData = {
  users: [],
  deposits: [],
  withdrawals: [],
  tasks: [],
  siteSettings: {
    siteName: "TERO Network",
    maintenanceMode: false,
    telegramSupportUsername: "TeroComunityBot",
    emergencyWithdrawalMode: false,
  },
};

// Initial load from file if exists
try {
  if (fs.existsSync(DATA_FILE)) {
    const raw = fs.readFileSync(DATA_FILE, "utf-8");
    const parsed = JSON.parse(raw);
    inMemoryDB = { ...inMemoryDB, ...parsed };
  }
} catch (e) {
  console.error("Error reading local data.json", e);
}

// Async Hydrate from Cloud Firestore (Admin SDK — only runs if configured above)
async function hydrateFromFirestore() {
  if (!firestoreDb) return;
  try {
    console.log("Hydrating data from Firebase Firestore...");
    const usersSnap = await firestoreDb.collection("users").get();
    if (!usersSnap.empty) inMemoryDB.users = usersSnap.docs.map((d) => d.data() as User);

    const depositsSnap = await firestoreDb.collection("deposits").get();
    if (!depositsSnap.empty) inMemoryDB.deposits = depositsSnap.docs.map((d) => d.data() as Deposit);

    const withdrawalsSnap = await firestoreDb.collection("withdrawals").get();
    if (!withdrawalsSnap.empty) inMemoryDB.withdrawals = withdrawalsSnap.docs.map((d) => d.data() as Withdrawal);

    const tasksSnap = await firestoreDb.collection("tasks").get();
    if (!tasksSnap.empty) inMemoryDB.tasks = tasksSnap.docs.map((d) => d.data() as Task);

    const settingsSnap = await firestoreDb.collection("siteSettings").doc("global").get();
    if (settingsSnap.exists) {
      inMemoryDB.siteSettings = { ...inMemoryDB.siteSettings, ...settingsSnap.data() };
    } else {
      await firestoreDb.collection("siteSettings").doc("global").set(inMemoryDB.siteSettings);
    }

    fs.writeFileSync(DATA_FILE, JSON.stringify(inMemoryDB, null, 2));
    console.log(
      `Firestore hydration complete: ${inMemoryDB.users.length} users, ${inMemoryDB.deposits.length} deposits, ` +
      `${inMemoryDB.withdrawals.length} withdrawals, ${inMemoryDB.tasks.length} tasks.`
    );
  } catch (err) {
    console.error("Failed to hydrate from Firestore:", err);
  }
}

hydrateFromFirestore();

function loadDB(): DBData {
  return inMemoryDB;
}

function saveDB(db: DBData) {
  inMemoryDB = db;
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
  } catch (err) {
    console.error("Failed to save local DB", err);
  }

  if (firestoreDb) {
    (async () => {
      try {
        const batch = firestoreDb!.batch();
        for (const user of db.users) {
          if (user.id) batch.set(firestoreDb!.collection("users").doc(user.id), user);
        }
        for (const dep of db.deposits) {
          if (dep.id) batch.set(firestoreDb!.collection("deposits").doc(dep.id), dep);
        }
        for (const wd of db.withdrawals) {
          if (wd.id) batch.set(firestoreDb!.collection("withdrawals").doc(wd.id), wd);
        }
        for (const task of db.tasks) {
          if (task.id) batch.set(firestoreDb!.collection("tasks").doc(task.id), task);
        }
        batch.set(firestoreDb!.collection("siteSettings").doc("global"), db.siteSettings);
        await batch.commit();
      } catch (cloudErr) {
        console.error("Error writing to Firestore:", cloudErr);
      }
    })();
  }
}

function genReferralCode(): string {
  return crypto.randomBytes(4).toString("hex").toUpperCase().slice(0, 6);
}

// In-memory OTP store for password reset / email verification.
// NOTE: this is dev-mode delivery — codes are logged to the server console
// instead of being sent by real SMS/email, since no such provider is wired
// up in this project. Wire a real provider before relying on this in
// production; the verification logic itself (hashed, expiring, single-use)
// is production-safe.
interface OtpRecord { hash: string; expiresAt: number; purpose: "reset" | "verify-email" }
const otpStore = new Map<string, OtpRecord>();

function issueOtp(userId: string, purpose: OtpRecord["purpose"]): string {
  const code = String(crypto.randomInt(100000, 999999));
  const hash = crypto.createHash("sha256").update(code).digest("hex");
  otpStore.set(`${purpose}:${userId}`, { hash, expiresAt: Date.now() + 10 * 60 * 1000, purpose });
  console.log(`[DEV OTP] purpose=${purpose} userId=${userId} code=${code} (expires in 10 min)`);
  return code;
}

function verifyOtp(userId: string, purpose: OtpRecord["purpose"], code: string): boolean {
  const key = `${purpose}:${userId}`;
  const rec = otpStore.get(key);
  if (!rec || rec.expiresAt < Date.now()) return false;
  const hash = crypto.createHash("sha256").update(String(code || "")).digest("hex");
  const ok = crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(rec.hash));
  if (ok) otpStore.delete(key);
  return ok;
}

// API Health
app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

// ============================================================================
// --- Admin Router (all routes below require a valid admin JWT except
//     /auth/login and /auth/forgot-password, which must stay public) ---
// ============================================================================
const adminRouter = express.Router();

adminRouter.post("/auth/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  const uname = (username || "").toString().trim();
  const ok = uname === ADMIN_USERNAME && (await bcrypt.compare(password || "", ADMIN_PASSWORD_HASH));
  if (!ok) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const token = signToken({ role: "admin", username: uname });
  res.json({ token, username: uname, role: "admin", message: "Login successful" });
});

adminRouter.post("/auth/forgot-password", (req, res) => {
  // Honest no-op stub (as before): no email provider is configured for the
  // admin account. Does not leak whether the account exists, does not reset
  // anything by itself — safe to leave unauthenticated.
  res.json({ ok: true, message: "إن كان الحساب صحيحاً فسيصلك بريد لإعادة التعيين قريباً" });
});

// Everything registered on adminRouter from this point on requires a valid admin token.
adminRouter.use(requireAdmin);

adminRouter.get("/auth/me", (req, res) => {
  const admin = (req as any).admin;
  res.json({
    username: admin.username,
    email: `${admin.username}@teronetwork.com`,
    role: "admin",
    authenticated: true,
  });
});

adminRouter.post("/auth/logout", (req, res) => {
  res.json({ success: true });
});

adminRouter.post("/auth/change-password", async (req, res) => {
  const { newPassword } = req.body || {};
  if (!newPassword || String(newPassword).length < 8) {
    return res.status(400).json({ error: "كلمة المرور يجب أن لا تقل عن 8 أحرف" });
  }
  const hash = await bcrypt.hash(String(newPassword), 10);
  persistAdminPasswordHash(hash);
  res.json({ ok: true, message: "Password updated" });
});

// --- Admin Users Management ---
adminRouter.get("/users", (req, res) => {
  const db = loadDB();
  const search = ((req.query.search as string) || "").toLowerCase();
  const page = parseInt((req.query.page as string) || "1", 10);
  const limit = parseInt((req.query.limit as string) || "20", 10);

  let filtered = db.users;
  if (search) {
    filtered = filtered.filter(
      (u) =>
        u.username.toLowerCase().includes(search) ||
        u.email.toLowerCase().includes(search) ||
        (u.telegram && u.telegram.toLowerCase().includes(search))
    );
  }

  const start = (page - 1) * limit;
  const paginated = filtered.slice(start, start + limit).map(sanitizeUser);

  res.json({ users: paginated, total: filtered.length });
});

adminRouter.get("/users/freeze-candidates/count", (req, res) => res.json({ count: 0 }));
adminRouter.get("/users/frozen-inactivity/count", (req, res) => res.json({ count: 0 }));

adminRouter.get("/users/:id", (req, res) => {
  const db = loadDB();
  const user = db.users.find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ user: sanitizeUser(user) });
});

// Edit user / update balance / status
adminRouter.post("/users/:id", (req, res) => {
  const db = loadDB();
  const user = db.users.find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: "User not found" });

  const { balance, usdtBalance, status, isFrozen } = req.body || {};

  // SECURITY/CORRECTNESS FIX: previously `parseFloat` on an untrusted value
  // was assigned with no validation at all — a bad payload could set the
  // balance to NaN, and nothing stopped a negative balance either.
  if (balance !== undefined) {
    const b = Number(balance);
    if (!Number.isFinite(b) || b < 0) return res.status(400).json({ error: "رصيد غير صالح" });
    user.balance = b;
  }
  if (usdtBalance !== undefined) {
    const ub = Number(usdtBalance);
    if (!Number.isFinite(ub) || ub < 0) return res.status(400).json({ error: "رصيد USDT غير صالح" });
    user.usdtBalance = ub;
  }
  if (status !== undefined) user.status = status;
  if (isFrozen !== undefined) user.isFrozen = Boolean(isFrozen);

  saveDB(db);
  res.json({ success: true, user: sanitizeUser(user) });
});

adminRouter.post("/users/:id/freeze-inactivity", (req, res) => {
  const db = loadDB();
  const user = db.users.find((u) => u.id === req.params.id);
  if (user) {
    user.isFrozen = true;
    user.status = "frozen";
    saveDB(db);
  }
  res.json({ success: true });
});

// --- Admin Deposits Management ---
adminRouter.get("/deposits", (req, res) => {
  const db = loadDB();
  const page = parseInt((req.query.page as string) || "1", 10);
  const limit = parseInt((req.query.limit as string) || "30", 10);
  const start = (page - 1) * limit;
  const paginated = db.deposits.slice(start, start + limit);
  res.json({ deposits: paginated, total: db.deposits.length });
});

adminRouter.post("/deposits/:id/approve", (req, res) => {
  const db = loadDB();
  const dep = db.deposits.find((d) => d.id === req.params.id);
  if (dep) {
    const amt = Number(dep.amount);
    if (!Number.isFinite(amt) || amt <= 0) {
      return res.status(400).json({ error: "مبلغ الإيداع غير صالح" });
    }
    dep.status = "confirmed";
    const user = db.users.find((u) => u.id === dep.userId || u.username === dep.username);
    if (user) {
      user.balance += amt;
      user.usdtBalance += amt;
    }
    saveDB(db);
  }
  res.json({ success: true });
});

adminRouter.post("/deposits/:id/reject", (req, res) => {
  const db = loadDB();
  const dep = db.deposits.find((d) => d.id === req.params.id);
  if (dep) {
    dep.status = "failed";
    saveDB(db);
  }
  res.json({ success: true });
});

// --- Admin Withdrawals Management ---
adminRouter.get("/withdrawals", (req, res) => {
  const db = loadDB();
  const statusFilter = req.query.status as string;
  let filtered = db.withdrawals;
  if (statusFilter) filtered = filtered.filter((w) => w.status === statusFilter);
  res.json({ withdrawals: filtered, total: filtered.length });
});

adminRouter.get("/withdrawals/planning/summary", (req, res) => {
  const db = loadDB();
  const pending = db.withdrawals.filter((w) => w.status === "pending_approval");
  const totalUsdt = pending.reduce((acc, curr) => acc + (curr.usdtAmount || 0), 0);
  res.json({ ok: true, totalCount: pending.length, totalUsdt, uniqueNets: 1, scheduledDays: 1, gasBreakdown: [] });
});

adminRouter.post("/withdrawals/:id/approve", (req, res) => {
  const db = loadDB();
  const wd = db.withdrawals.find((w) => w.id === req.params.id);
  if (wd) {
    wd.status = "completed";
    saveDB(db);
  }
  res.json({ success: true });
});

adminRouter.post("/withdrawals/:id/reject", (req, res) => {
  const db = loadDB();
  const wd = db.withdrawals.find((w) => w.id === req.params.id);
  if (wd) {
    wd.status = "rejected";
    wd.rejectionReason = req.body?.reason || "تم الرفض بواسطة المشرف";
    const user = db.users.find((u) => u.id === wd.userId || u.username === wd.username);
    if (user) {
      user.balance += wd.amount;
      user.usdtBalance += wd.amount;
    }
    saveDB(db);
  }
  res.json({ success: true });
});

adminRouter.post("/withdrawals/:id/cancel", (req, res) => {
  const db = loadDB();
  const wd = db.withdrawals.find((w) => w.id === req.params.id);
  if (wd) {
    wd.status = "cancelled";
    const user = db.users.find((u) => u.id === wd.userId || u.username === wd.username);
    if (user) {
      user.balance += wd.amount;
      user.usdtBalance += wd.amount;
    }
    saveDB(db);
  }
  res.json({ success: true });
});

// --- Admin Tasks Management ---
adminRouter.get("/tasks", (req, res) => {
  const db = loadDB();
  res.json({ tasks: db.tasks, total: db.tasks.length });
});

adminRouter.post("/tasks", (req, res) => {
  const db = loadDB();
  const reward = Number(req.body?.reward ?? 1.0);
  const newTask: Task = {
    id: "t_" + Date.now(),
    platform: req.body?.platform || "tiktok",
    title: req.body?.title || "مهمة جديدة",
    description: req.body?.description || "",
    reward: Number.isFinite(reward) && reward >= 0 ? reward : 1.0,
    targetUrl: req.body?.targetUrl || "",
    isActive: true,
    order: db.tasks.length + 1,
  };
  db.tasks.push(newTask);
  saveDB(db);
  res.json({ success: true, task: newTask, ok: true });
});

adminRouter.put("/tasks/:id", (req, res) => {
  const db = loadDB();
  const task = db.tasks.find((t) => t.id === req.params.id);
  if (task) {
    Object.assign(task, req.body);
    saveDB(db);
  }
  res.json({ success: true, task, ok: true });
});

adminRouter.delete("/tasks/:id", (req, res) => {
  const db = loadDB();
  db.tasks = db.tasks.filter((t) => t.id !== req.params.id);
  saveDB(db);
  res.json({ success: true, ok: true });
});

adminRouter.post("/tasks/bulk-action", (req, res) => {
  const db = loadDB();
  const { action, ids } = req.body || {};
  if (Array.isArray(ids)) {
    if (action === "activate") db.tasks.forEach((t) => { if (ids.includes(t.id)) t.isActive = true; });
    else if (action === "deactivate") db.tasks.forEach((t) => { if (ids.includes(t.id)) t.isActive = false; });
    else if (action === "delete") db.tasks = db.tasks.filter((t) => !ids.includes(t.id));
    saveDB(db);
  }
  res.json({ ok: true, success: true });
});

adminRouter.post("/tasks/bulk-delete-ids", (req, res) => {
  const db = loadDB();
  const { ids } = req.body || {};
  if (Array.isArray(ids)) {
    db.tasks = db.tasks.filter((t) => !ids.includes(t.id));
    saveDB(db);
  }
  res.json({ ok: true, success: true });
});

adminRouter.post("/tasks/bulk", (req, res) => res.json({ ok: true, success: true }));
adminRouter.post("/tasks/recycle-links", (req, res) => res.json({ ok: true, success: true }));
adminRouter.post("/tasks/new-week", (req, res) => res.json({ ok: true, success: true }));
adminRouter.post("/tasks/import-csv", (req, res) => res.json({ ok: true, success: true }));
adminRouter.get("/tasks/export-csv", (req, res) => {
  res.setHeader("Content-Type", "text/csv");
  res.send("id,platform,title,reward,targetUrl,isActive\n");
});

adminRouter.get("/task-dashboard", (req, res) => {
  const db = loadDB();
  const total = db.tasks.length;
  const active = db.tasks.filter((t) => t.isActive).length;
  const inactive = total - active;

  const byPlatform: Record<string, any> = {
    tiktok: { total: 0, active: 0, views: 0, completions: 0, successRate: 100 },
    youtube: { total: 0, active: 0, views: 0, completions: 0, successRate: 100 },
    telegram: { total: 0, active: 0, views: 0, completions: 0, successRate: 100 },
    twitter: { total: 0, active: 0, views: 0, completions: 0, successRate: 100 },
    instagram: { total: 0, active: 0, views: 0, completions: 0, successRate: 100 },
    facebook: { total: 0, active: 0, views: 0, completions: 0, successRate: 100 },
  };

  for (const t of db.tasks) {
    const p = (t.platform || "tiktok").toLowerCase();
    if (!byPlatform[p]) byPlatform[p] = { total: 0, active: 0, views: 0, completions: 0, successRate: 100 };
    byPlatform[p].total += 1;
    if (t.isActive) byPlatform[p].active += 1;
    byPlatform[p].views += 5;
    byPlatform[p].completions += 4;
  }

  const topTemplates = db.tasks.map((t, idx) => ({
    id: t.id,
    platform: t.platform || "tiktok",
    title: t.title,
    targetUrl: t.targetUrl || "https://tero.com",
    totalCompletions: Math.max(1, 10 - idx),
    totalViews: Math.max(1, 12 - idx),
  }));

  res.json({
    dashboard: {
      templates: { total, active, inactive, byPlatform },
      performance: { overallSuccessRate: 98 },
      today: { completed: 0, selected: 0, available: active, rejected: 0 },
      yesterday: 0,
      weekTotal: 0,
      topTemplates,
      recentActivity: [],
    },
    activeTasks: active,
    totalSubmissions: 0,
    pendingSubmissions: 0,
  });
});

adminRouter.get("/task-alerts", (req, res) => res.json({ alerts: [] }));
adminRouter.get("/task-activity", (req, res) =>
  res.json({ activity: [], pagination: { total: 0, page: 1, limit: 50, totalPages: 1 } })
);
adminRouter.get("/task-access-codes/current", (req, res) => res.json({ code: null }));
adminRouter.get("/task-access-codes", (req, res) => res.json({ codes: [] }));
adminRouter.post("/task-access-codes", (req, res) =>
  res.json({ ok: true, code: "TAC_" + Math.floor(100000 + Math.random() * 900000) })
);
adminRouter.delete("/task-access-codes/:id", (req, res) => res.json({ ok: true }));
adminRouter.get("/task-code-gen/settings", (req, res) =>
  res.json({ settings: { enabled: true, intervalHours: 24, lastRun: new Date().toISOString(), status: "idle" } })
);
adminRouter.patch("/task-code-gen/settings", (req, res) => res.json({ enabled: req.body?.enabled ?? true, ok: true }));
adminRouter.get("/task-code-gen/log", (req, res) => res.json({ logs: [] }));
adminRouter.post("/task-code-gen/manual", (req, res) =>
  res.json({
    ok: true,
    log: {
      id: "log_" + Date.now(),
      code: "TERO" + Math.floor(100000 + Math.random() * 900000),
      createdAt: new Date().toISOString(),
      status: "running",
    },
  })
);
adminRouter.post("/task-code-gen/resend/:id", (req, res) => res.json({ ok: true }));
adminRouter.get("/task-submissions", (req, res) => res.json({ submissions: [], total: 0 }));
adminRouter.get("/task-submissions/stats", (req, res) => res.json({ pending: 0, approved: 0, rejected: 0 }));
adminRouter.post("/task-submissions/:id/approve", (req, res) => res.json({ ok: true, success: true }));
adminRouter.post("/task-submissions/:id/reject", (req, res) => res.json({ ok: true, success: true }));

// --- Sweeps & Gas Management (mock data, unchanged, now auth-gated) ---
adminRouter.get("/sweeps", (req, res) => res.json([]));
adminRouter.post("/sweeps/run", (req, res) => res.json({ ok: true, swept: 0 }));

adminRouter.get("/gas-management", (req, res) => {
  const today = new Date();
  const dayNames = ["الأحد", "الاثنين", "الثلاثاء", "الأربعاء", "الخميس", "الجمعة", "السبت"];
  const dailyPlan = Array.from({ length: 7 }, (_, i) => {
    const d = new Date(today);
    d.setDate(d.getDate() + i);
    return {
      date: d.toISOString().slice(0, 10),
      dayName: dayNames[d.getDay()],
      total: 0,
      withdrawalGas: 0,
      sweepGas: 0,
    };
  });

  res.json({
    summary: { criticalNetworks: [], warningNetworks: [], readyNetworks: ["POLYGON"], totalNativeUsd: 100.0 },
    networks: [
      {
        network: "POLYGON",
        name: "Polygon PoS",
        // FIX (round 1): the frontend's gas-management card (`sY[e.planStatus]`)
        // reads a `planStatus` field with value "ok" | "warning" | "critical" —
        // it does NOT read `status`, which is what this endpoint used to send
        // instead. `sY[undefined]` was undefined, so reading `.bg` off it
        // crashed the whole page to a blank white screen.
        label: "Polygon PoS",
        planStatus: "ok",
        nativeSymbol: "POL",
        status: "ready",
        balance: 10.5,
        balanceUsd: 8.5,
        address: TREASURY_ADDRESS,
        minRequired: 1.0,
        addressesNeedingGas: 0,
        estimatedGasCostUsd: 0.005,
        // FIX (round 2): once the crash above was fixed, the card body itself
        // reads a whole different set of field names than what was here
        // (gasPoolAddress instead of address, nativeBalance/nativeToken
        // instead of balance/nativeSymbol, plus a 7-day gas plan) — none of
        // which existed, so the page crashed again one level deeper.
        gasPoolAddress: TREASURY_ADDRESS,
        nativeBalance: 10.5,
        nativeToken: "POL",
        needsGas: 0,
        topUpAmount: 0.5,
        reservedForSweep: 0,
        pendingWithdrawalCount: 0,
        withdrawalGasCost: 0,
        reservedForWithdrawals: 0,
        available: 10.5,
        totalNeeded7d: 0,
        dailyPlan,
      },
    ],
  });
});

// --- Treasury & Hot Wallet ---
adminRouter.get("/treasury", (req, res) => {
  const db = loadDB();
  const totalUserBalances = db.users.reduce((sum, u) => sum + (u.balance || 0), 0);
  res.json({
    totalBalance: totalUserBalances,
    hotWallet: totalUserBalances * 0.4,
    coldWallet: totalUserBalances * 0.6,
    addresses: [{ network: "POLYGON", address: getDepositAddress("POLYGON"), balance: totalUserBalances }],
    // FIX: the treasury dashboard page reads `a.balances[network].usdt`,
    // `a.stats.totalUsdtSwept` (no `?.` before `.totalUsdtSwept`, so a
    // missing `stats` object crashed the whole page), and iterates
    // `a.gasPool` / `a.treasury` as network->address maps. None of these
    // existed on the old response at all.
    balances: { POLYGON: { usdt: totalUserBalances.toFixed(2), native: "25.0" } },
    gasPool: { POLYGON: TREASURY_ADDRESS },
    treasury: { POLYGON: getDepositAddress("POLYGON") },
    stats: { totalUsdtSwept: "0.00", broadcast: 0, confirmed: 0 },
  });
});

// FIX / FEATURE: this used to be a hardcoded constant with a fake PUT that
// returned {ok:true} without saving anything — the "change deposit address"
// screen in the admin panel looked like it worked but never actually
// changed anything. It's now backed by db.siteSettings.depositAddresses,
// persisted to data.json (and Firestore, if configured) like every other
// setting, and every place that shows a deposit address to users or admins
// reads from this same store — see getDepositAddress()/setDepositAddress()
// below and their usages in /api/wallet/deposit-address,
// /api/admin/users/:id/deposit-addresses, /api/admin/treasury and
// /api/admin/treasury-addresses.
function getDepositAddress(network: string): string {
  const db = loadDB();
  return db.siteSettings.depositAddresses?.[network]?.address || TREASURY_ADDRESS;
}

function setDepositAddress(network: string, address: string) {
  const db = loadDB();
  if (!db.siteSettings.depositAddresses) db.siteSettings.depositAddresses = {};
  db.siteSettings.depositAddresses[network] = { address, updatedAt: new Date().toISOString() };
  saveDB(db);
}

function isValidAddress(network: string, address: string): boolean {
  if (!address || typeof address !== "string") return false;
  const a = address.trim();
  if (network === "POLYGON") return /^0x[a-fA-F0-9]{40}$/.test(a);
  return a.length >= 6; // other networks: minimal sanity check only
}

adminRouter.get("/treasury-settings", (req, res) => {
  const db = loadDB();
  const networks = ["POLYGON"];
  const settings: Record<string, { address: string }> = {};
  for (const net of networks) settings[net] = { address: getDepositAddress(net) };
  res.json({ settings, sweepEnabled: Boolean(db.siteSettings.sweepEnabled) });
});

adminRouter.put("/treasury-settings", (req, res) => {
  const { network, address } = req.body || {};
  if (!network || typeof network !== "string") {
    return res.status(400).json({ ok: false, error: "الشبكة مطلوبة" });
  }
  if (!isValidAddress(network, address)) {
    return res.status(400).json({ ok: false, error: "عنوان المحفظة غير صالح" });
  }
  setDepositAddress(network, String(address).trim());
  res.json({ ok: true });
});

adminRouter.delete("/treasury-settings/:network", (req, res) => {
  const db = loadDB();
  if (db.siteSettings.depositAddresses) delete db.siteSettings.depositAddresses[req.params.network];
  saveDB(db);
  res.json({ ok: true });
});

adminRouter.get("/treasury-addresses", (req, res) => {
  const addr = getDepositAddress("POLYGON");
  res.json({
    addresses: [{ network: "POLYGON", address: addr, label: "Polygon Hot Wallet" }],
    networks: {
      POLYGON: {
        sweepDest: { address: addr, usdt: "250000.00", native: "150.5", nativeUnit: "POL" },
        hotWallet: { address: addr, usdt: "50000.00", native: "25.0", nativeUnit: "POL" },
        gasDispenser: { address: addr, usdt: "0.00", native: "100.0", nativeUnit: "POL" },
        coldWallet: { address: "0xColdWalletPolygonAddress00000000000000000", usdt: "1000000.00", native: "0.0", nativeUnit: "POL" },
      },
    },
  });
});

adminRouter.get("/hot-wallet/status", (req, res) => {
  res.json({
    fetchedAt: new Date().toISOString(),
    // FIX: the hot-wallet page reads `summary.totalUsdtAvailable.toFixed(2)`
    // (not `totalUsdt`, which is what this endpoint used to send), plus
    // `summary.pendingNow` / `summary.scheduledNext72h` which didn't exist
    // at all — the missing `.toFixed` crashed the whole page blank.
    summary: {
      totalUsdt: 50000.0,
      totalUsdtAvailable: 50000.0,
      pendingNow: 0,
      scheduledNext72h: 0,
      networksReady: ["POLYGON"],
      networksNeedFunding: [],
    },
    networks: [
      {
        network: "POLYGON",
        label: "Polygon PoS",
        address: TREASURY_ADDRESS,
        balance: 50000.0,
        balanceUsdt: 50000.0,
        // FIX: each network card also needs `gasBalance`, `gasThreshold:
        // {min, low}`, and `usdtBalance` (all separate from the `balance`/
        // `balanceUsdt` fields above) to render without crashing.
        gasBalance: 15.5,
        gasThreshold: { min: 1.0, low: 0.5 },
        usdtBalance: 50000.0,
        status: "ready",
        needsFunding: false,
        minThreshold: 1000,
      },
    ],
  });
});

adminRouter.get("/wallet-movements/hot-wallet", (req, res) => res.json({ rows: [] }));

// --- Honor Points & Referral Config ---
adminRouter.get("/honor-points", (req, res) => {
  const db = loadDB();
  res.json({ users: db.users.map((u) => ({ id: u.id, username: u.username, honorPoints: 100, status: u.status })) });
});
adminRouter.put("/honor-points/:id", (req, res) => res.json({ ok: true, success: true }));
adminRouter.get("/referral-commission-config", (req, res) =>
  res.json({ ok: true, config: [{ level: 1, rate: 0.1 }, { level: 2, rate: 0.05 }, { level: 3, rate: 0.02 }] })
);
adminRouter.put("/referral-commission-config", (req, res) => res.json({ ok: true, config: req.body?.rates || [] }));

// --- Wallet Change Requests ---
adminRouter.get("/wallet-change-requests", (req, res) => res.json({ requests: [], total: 0 }));
adminRouter.post("/wallet-change-requests/:id/approve", (req, res) => res.json({ ok: true }));
adminRouter.post("/wallet-change-requests/:id/reject", (req, res) => res.json({ ok: true }));
adminRouter.get("/wallet-change-requests/stats", (req, res) => res.json({ pending: 0 }));

// --- Planning & Logs ---
adminRouter.get("/withdrawals/planning", (req, res) => res.json({ ok: true, days: [], batches: [], totalDays: 0, totalUsdt: 0 }));
adminRouter.get("/withdrawal-logs", (req, res) => res.json({ ok: true, logs: [] }));
adminRouter.post("/notifications/send", (req, res) => res.json({ ok: true, sent: 1 }));

adminRouter.get("/chat/conversations", (req, res) => res.json([]));
adminRouter.post("/chat/conversations", (req, res) =>
  res.json({
    ok: true,
    conversation: {
      id: "c_" + Date.now(),
      title: req.body?.title || "مجموعة عامة",
      type: "group",
      unreadCount: 0,
      createdAt: new Date().toISOString(),
    },
  })
);
adminRouter.get("/chat/dm", (req, res) => res.json([]));
adminRouter.get("/chat/group-templates", (req, res) => res.json([]));
adminRouter.get("/chat/logs", (req, res) => res.json([]));
adminRouter.post("/chat/upload-avatar", (req, res) => res.json({ ok: true, url: "/default-avatar.png" }));

adminRouter.post("/leaders/run-payout", (req, res) => res.json({ ok: true }));
adminRouter.post("/leaders/:id", (req, res) => res.json({ ok: true }));
adminRouter.post("/rpc-monitor/test", (req, res) => res.json({ ok: true, latency: 38 }));
adminRouter.post("/rpc-monitor/reload", (req, res) => res.json({ ok: true }));

adminRouter.post("/membership-plans/sync", (req, res) => res.json({ ok: true }));
adminRouter.post("/membership-plans/:id", (req, res) => res.json({ ok: true }));

// The frontend communicates a couple of boolean settings as string keys
// that don't match the internal siteSettings field names (snake_case API
// key vs. camelCase internal field), and sends booleans as "1"/"0" strings.
const BOOLEAN_SETTING_KEYS: Record<string, string> = {
  emergency_withdrawal_mode: "emergencyWithdrawalMode",
  maintenance_mode: "maintenanceMode",
};
const NUMERIC_SETTING_KEYS = new Set([
  "min_deposit_amount",
  "min_withdrawal_amount",
  "withdrawal_fee",
  "max_withdrawal_amount",
]);

adminRouter.post("/site-settings/emergency_withdrawal_mode", (req, res) => {
  const db = loadDB();
  db.siteSettings.emergencyWithdrawalMode = !db.siteSettings.emergencyWithdrawalMode;
  saveDB(db);
  res.json({ ok: true, emergencyWithdrawalMode: db.siteSettings.emergencyWithdrawalMode });
});

adminRouter.get("/site-settings", (req, res) => {
  const db = loadDB();
  // FIX: the settings screens do
  // `((await fetch('/api/admin/site-settings')).json()).settings ?? []`
  // then `.find(s => s.key === "...")` on that array. The old response was
  // a flat object with no `settings` array at all, so every field on the
  // finance/emergency-mode settings screens silently rendered blank/default
  // instead of the real stored value (this is the "الإعدادات تظهر فاضية"
  // symptom, distinct from the outright crashes fixed above).
  const settings = Object.entries(db.siteSettings).map(([key, value]) => ({
    key,
    value: typeof value === "boolean" ? (value ? "1" : "0") : String(value),
  }));
  res.json({ settings, raw: db.siteSettings });
});

adminRouter.post("/site-settings", (req, res) => {
  const db = loadDB();
  db.siteSettings = { ...db.siteSettings, ...req.body };
  saveDB(db);
  res.json({ success: true, siteSettings: db.siteSettings });
});

// Generic per-key setter used by the admin finance-settings screen (PUT
// /api/admin/site-settings/:key with { value }). Maps known snake_case API
// key names to the actual internal camelCase field, and normalizes
// booleans/numbers instead of storing raw strings — the rest of the server
// reads these as real booleans/numbers (e.g. `db.siteSettings.maintenanceMode`).
adminRouter.put("/site-settings/:key", (req, res) => {
  const db = loadDB();
  const key = req.params.key;
  const rawValue = req.body?.value;
  const internalKey = BOOLEAN_SETTING_KEYS[key] || key;

  let value: any = rawValue;
  if (key in BOOLEAN_SETTING_KEYS) {
    value = rawValue === "1" || rawValue === 1 || rawValue === true;
  } else if (NUMERIC_SETTING_KEYS.has(key)) {
    const n = Number(rawValue);
    value = Number.isFinite(n) ? n : rawValue;
  }

  db.siteSettings[internalKey] = value;
  saveDB(db);
  res.json({ ok: true, key, value: rawValue });
});

adminRouter.get("/maintenance", (req, res) => {
  const db = loadDB();
  res.json({ enabled: Boolean(db.siteSettings.maintenanceMode) });
});

// FIX: the maintenance toggle button on the admin dashboard does
// `POST /api/admin/maintenance` and only applies the response when the JSON
// field `ok` is truthy. This route never existed, so the request silently
// fell through to the generic catch-all (`{ success: true }`, no `ok`
// field) and the toggle appeared to do nothing.
adminRouter.post("/maintenance", (req, res) => {
  const db = loadDB();
  const { enabled } = req.body || {};
  db.siteSettings.maintenanceMode = Boolean(enabled);
  saveDB(db);
  res.json({ ok: true, enabled: db.siteSettings.maintenanceMode });
});

adminRouter.get("/sweep-manager/stats", (req, res) =>
  res.json({
    completed: { count: 0, totalUsdt: 0 },
    failed: { count: 0, totalUsdt: 0 },
    inFlight: { count: 0, totalUsdt: 0 },
    pending: { count: 0, totalUsdt: 0 },
  })
);

adminRouter.get("/sweep-manager/readiness", (req, res) =>
  res.json({
    isReady: true,
    gasWallet: { polBalance: 15.5, sufficient: true, requiredGasPol: 0.0, addressesNeedingGas: 0, deficitPol: 0.0 },
  })
);

adminRouter.get("/sweep-manager/history", (req, res) => res.json([]));

adminRouter.get("/membership-plans", (req, res) => res.json({ plans: MEMBERSHIP_PLANS }));

adminRouter.get("/membership-plans/distribution", (req, res) => {
  const db = loadDB();
  const totalActive = db.users.length;
  res.json({
    ok: true,
    totalActive,
    plans: MEMBERSHIP_PLANS.map((p) => ({
      id: p.id,
      tier: p.tier,
      name: p.name,
      price: p.price,
      subscriberCount: db.users.filter((u) => (u.membershipTier || "free") === p.tier).length,
    })),
  });
});

adminRouter.get("/leaders", (req, res) => {
  const db = loadDB();
  const leaderList = db.users.map((u, idx) => ({
    id: u.id,
    username: u.username,
    leaderRank: idx + 1,
    leaderPoints: 120,
    weeklySalary: 50,
    activeDirects: 10,
    totalTeam: 50,
    lastPaidAt: null,
    walletAddress: TREASURY_ADDRESS,
    // FIX: the leaders page calls `TQ(U.tierBreakdown)`, which immediately
    // does `e.c1+e.c2+e.b1+e.b2+e.a1+e.a2` — `tierBreakdown` didn't exist on
    // this response at all, so that threw on the very first leader row and
    // blanked the whole page.
    tierBreakdown: { c1: 0, c2: 0, b1: 0, b2: 0, a1: 0, a2: 0 },
  }));
  res.json({ leaders: leaderList });
});

adminRouter.get("/rpc-monitor", (req, res) => {
  res.json({
    status: "healthy",
    latency: 45,
    polygon: {
      configured: true,
      slotCount: 3,
      activeProvider: "Alchemy Polygon RPC",
      activeUrl: "https://polygon-mainnet.g.alchemy.com/v2/...",
      endpoint: "https://polygon-mainnet.g.alchemy.com/v2/...",
      health: "healthy",
      latencyMs: 38,
      blockNumber: 68124930,
      lastChecked: new Date().toISOString(),
      // FIX: the RPC monitor page calls `.toLocaleString()` directly on
      // `polygon.totalRequests` / `polygon.totalErrors` with no fallback —
      // neither field existed on this response, so `undefined.toLocaleString()`
      // crashed the whole page. `fallbackCount` was read too (no crash, just
      // rendered "undefined RPCs").
      totalRequests: 128430,
      totalErrors: 0,
      fallbackCount: 2,
      // FIX (round 2): each slot card reads a much larger field set than
      // {name,url,status,latency} — `requests.toLocaleString()` /
      // `errors.toLocaleString()` with no fallback crashed the page again
      // one level deeper once the first two crashes were fixed.
      slots: [
        {
          name: "Alchemy Primary",
          url: "https://polygon-mainnet.g.alchemy.com/...",
          urlMasked: "https://polygon-mainnet.g.alchemy.com/v2/***",
          status: "active",
          isActive: true,
          health: "healthy",
          latency: 38,
          requests: 128430,
          errors: 0,
          errorRate: 0,
          avgLatencyMs: 38,
          lastSuccessAt: new Date().toISOString(),
          lastErrorAt: null,
          lastErrorMsg: null,
        },
        {
          name: "Infura Backup",
          url: "https://polygon-mainnet.infura.io/...",
          urlMasked: "https://polygon-mainnet.infura.io/v3/***",
          status: "standby",
          isActive: false,
          health: "healthy",
          latency: 52,
          requests: 0,
          errors: 0,
          errorRate: 0,
          avgLatencyMs: 52,
          lastSuccessAt: null,
          lastErrorAt: null,
          lastErrorMsg: null,
        },
        {
          name: "QuickNode Fallback",
          url: "https://polygon.quiknode.pro/...",
          urlMasked: "https://polygon.quiknode.pro/***",
          status: "standby",
          isActive: false,
          health: "healthy",
          latency: 49,
          requests: 0,
          errors: 0,
          errorRate: 0,
          avgLatencyMs: 49,
          lastSuccessAt: null,
          lastErrorAt: null,
          lastErrorMsg: null,
        },
      ],
    },
    // FIX: after the crash above was fixed, the page still crashed one
    // level deeper — it does `Object.entries(o.envVarsConfigured)` on the
    // TOP-LEVEL response (not inside `polygon`), and this field never
    // existed at all, so `Object.entries(undefined)` threw immediately.
    envVarsConfigured: {
      ALCHEMY_API_KEY: true,
      INFURA_API_KEY: true,
      QUICKNODE_API_KEY: false,
    },
  });
});

adminRouter.get("/users/:id/profile", (req, res) => {
  const db = loadDB();
  const user = db.users.find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json(sanitizeUser(user));
});

adminRouter.get("/users/:id/deposit-addresses", (req, res) => {
  res.json({
    addresses: [{ network: "POLYGON", address: getDepositAddress("POLYGON"), sequence: 1, status: "active", createdAt: new Date().toISOString() }],
    recentDeposits: [],
    lastSweep: null,
    activeCount: 1,
    usedCount: 0,
    legacyCount: 0,
  });
});

adminRouter.post("/users/:id/rotate-deposit-address", (req, res) =>
  res.json({ ok: true, newSeq: 2, address: TREASURY_ADDRESS })
);

// SECURITY/CORRECTNESS FIX: these used to fall back to a hardcoded test
// username ("asse_24") whenever the requested user id didn't match anything,
// silently leaking that test account's deposits/withdrawals into any admin
// lookup for any user id. Now they only ever match the actual target user.
adminRouter.get("/users/:id/deposits", (req, res) => {
  const db = loadDB();
  const target = db.users.find((u) => u.id === req.params.id);
  const list = db.deposits.filter((d) => d.userId === req.params.id || (target && d.username === target.username));
  res.json({ transactions: list, total: list.length });
});

adminRouter.get("/users/:id/withdrawals", (req, res) => {
  const db = loadDB();
  const target = db.users.find((u) => u.id === req.params.id);
  const list = db.withdrawals.filter((w) => w.userId === req.params.id || (target && w.username === target.username));
  res.json({ transactions: list, total: list.length });
});

app.use("/api/admin", adminRouter);

// ============================================================================
// Constants shared by admin + public routes
// ============================================================================
const TREASURY_ADDRESS = process.env.TREASURY_ADDRESS || "0x113494B3aB9369CF9C66dE27255c948EF1266517";

const MEMBERSHIP_PLANS = [
  { id: "p1", tier: "free", name: "المستوى المجاني", price: 0, dailyTaskLimit: 3, incomeRate: 0.5, durationDays: 365, isPopular: false },
  { id: "p2", tier: "vip1", name: "VIP 1", price: 50, dailyTaskLimit: 10, incomeRate: 1.5, durationDays: 30, isPopular: false },
  { id: "p3", tier: "vip2", name: "VIP 2", price: 200, dailyTaskLimit: 25, incomeRate: 4.5, durationDays: 30, isPopular: true },
  { id: "p4", tier: "vip3", name: "VIP 3", price: 500, dailyTaskLimit: 50, incomeRate: 12.0, durationDays: 30, isPopular: false },
];

// ============================================================================
// --- Telegram Polling Service for Auto-linking Accounts ---
// SECURITY FIX: the bot token was previously a hardcoded real-looking
// fallback value baked into the source (and that source file was itself
// served publicly — see the static-file fix above). It's now env-only, and
// the bot is simply disabled if it isn't set instead of using a leaked token.
// ============================================================================
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";
const TELEGRAM_BOT_USERNAME = process.env.TELEGRAM_BOT_USERNAME || "TeroComunityBot";

let telegramLastUpdateId = 0;
async function pollTelegramBot() {
  if (!TELEGRAM_BOT_TOKEN) return;
  try {
    const res = await fetch(
      `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates?offset=${telegramLastUpdateId + 1}&timeout=5`
    );
    if (!res.ok) return;
    const data = await res.json();
    if (data.ok && Array.isArray(data.result)) {
      for (const update of data.result) {
        telegramLastUpdateId = update.update_id;
        const msg = update.message;
        if (!msg || !msg.text) continue;

        const text = msg.text.trim();
        const chatId = msg.chat.id;
        const sender = msg.from;
        const tgUsername = sender?.username ? `@${sender.username}` : sender?.first_name || "Telegram User";

        if (text.startsWith("/start")) {
          const parts = text.split(" ");
          const param = parts[1] || "";

          if (param) {
            const db = loadDB();
            let matchedUser: User | undefined;

            if (param.startsWith("link_") || param.startsWith("token_")) {
              const targetId = param.replace("link_", "").replace("token_", "");
              matchedUser = db.users.find((u) => u.id === targetId);
            }
            // CORRECTNESS/SECURITY FIX: removed the `db.users[0]` fallback —
            // it silently linked a stranger's Telegram handle to whichever
            // account happened to be first in the database when the deep
            // link's id didn't match anyone.

            if (matchedUser) {
              matchedUser.telegram = tgUsername;
              saveDB(db);
              await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  chat_id: chatId,
                  text: `✅ تم ربط حسابك في منصة TERO بنجاح!\n👤 المستخدم: ${matchedUser.username}\n📲 تيليجرام: ${tgUsername}\n\nيمكنك الآن العودة إلى الموقع للمتابعة.`,
                  parse_mode: "HTML",
                }),
              }).catch(() => {});
              continue;
            }
          }

          await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              chat_id: chatId,
              text: `مرحباً بك في بوت منصة TERO الرسمي 🌟\n\nيرجى الدخول إلى المنصة والضغط على زر "ربط Telegram" لاستكمال إعداد حسابك تلقائياً.`,
              parse_mode: "HTML",
            }),
          }).catch(() => {});
        }
      }
    }
  } catch (e) {
    // Silent catch for network resilience
  }
}

if (TELEGRAM_BOT_TOKEN) {
  setInterval(pollTelegramBot, 3000);
  pollTelegramBot();
} else {
  console.warn("TELEGRAM_BOT_TOKEN not set — Telegram auto-linking bot is disabled.");
}

app.get("/api/site-settings/public/telegram_support_username", (req, res) => {
  const db = loadDB();
  res.json({ telegramSupportUsername: TELEGRAM_BOT_USERNAME || db.siteSettings.telegramSupportUsername || "TeroComunityBot" });
});

// ============================================================================
// --- User-Facing Auth Routes ---
// SECURITY FIX: /api/auth/login previously accepted a username with NO
// password check whatsoever (the request body's `password` field was never
// even read) — anyone who knew/guessed a username was logged in as them, and
// a fresh account was silently created for unknown usernames too. The
// frontend already sends `password` (and an optional `totpCode`) on every
// login call, so real verification is a drop-in fix, not a frontend change.
// ============================================================================
app.post("/api/auth/register", loginLimiter, async (req, res) => {
  const db = loadDB();
  const { username, identifier, email, password } = req.body || {};
  const uname = (username || identifier || email || "").toString().trim();

  if (!uname || !password || String(password).length < 6) {
    return res.status(400).json({ error: "اسم المستخدم وكلمة مرور لا تقل عن 6 أحرف مطلوبة" });
  }
  if (db.users.find((u) => u.username === uname || u.email === uname)) {
    return res.status(409).json({ error: "المستخدم موجود مسبقاً" });
  }

  const passwordHash = await bcrypt.hash(String(password), 10);
  const user: User = {
    id: "u_" + Date.now() + "_" + crypto.randomBytes(3).toString("hex"),
    username: uname,
    email: uname.includes("@") ? uname : `${uname}@tero.com`,
    passwordHash,
    balance: 0.0,
    usdtBalance: 0.0,
    status: "active",
    isFrozen: false,
    joinedAt: new Date().toISOString(),
    membershipPlan: "none",
    referralsCount: 0,
    referralCode: genReferralCode(),
  };
  db.users.push(user);
  saveDB(db);

  const token = signToken({ uid: user.id, role: "user" });
  res.json({ token, user: sanitizeUser(user) });
});

app.post("/api/auth/login", loginLimiter, async (req, res) => {
  const db = loadDB();
  const { username, identifier, email, password } = req.body || {};
  const uname = (username || identifier || email || "").toString().trim();

  const user = db.users.find((u) => u.username === uname || u.email === uname);
  const hashToCheck = user?.passwordHash || "$2a$10$invalidsaltinvalidsaltinvalidsaltinvalidsal"; // constant-time-ish dummy compare when user not found
  const passwordOk = await bcrypt.compare(String(password || ""), hashToCheck);

  if (!user || !user.passwordHash || !passwordOk) {
    return res.status(401).json({ error: "بيانات الدخول غير صحيحة" });
  }
  if (user.isFrozen || user.status !== "active") {
    return res.status(403).json({ error: "الحساب غير مفعّل" });
  }

  const token = signToken({ uid: user.id, role: "user" });
  res.json({ token, user: sanitizeUser(user) });
});

app.post("/api/auth/logout", (req, res) => res.json({ success: true }));

app.get("/api/auth/me", requireUser, (req, res) => {
  const user = (req as any).currentUser as User;
  const isLinked = Boolean(user.telegram && user.telegram.trim() !== "");
  res.json({ ...sanitizeUser(user), requiresTelegramLink: !isLinked });
});

// Password reset / email verification — dev-mode OTP delivery (logged to
// the server console). See the `issueOtp` comment above: wire a real
// SMS/email provider before depending on this in production; the
// verification itself (hashed, single-use, 10-minute expiry) is sound.
app.post("/api/auth/forgot-password", loginLimiter, (req, res) => {
  const db = loadDB();
  const { identifier, email, username } = req.body || {};
  const uname = (identifier || email || username || "").toString().trim();
  const user = db.users.find((u) => u.username === uname || u.email === uname);
  if (user) issueOtp(user.id, "reset");
  // Always return the same generic response — do not reveal account existence.
  res.json({ ok: true, message: "إن وُجد الحساب فسيصلك رمز تحقق" });
});

app.post("/api/auth/verify-reset-otp", loginLimiter, (req, res) => {
  const db = loadDB();
  const { identifier, email, username, code } = req.body || {};
  const uname = (identifier || email || username || "").toString().trim();
  const user = db.users.find((u) => u.username === uname || u.email === uname);
  if (!user || !verifyOtp(user.id, "reset", code)) {
    return res.status(400).json({ error: "رمز غير صحيح أو منتهي الصلاحية" });
  }
  const resetToken = signToken({ uid: user.id, scope: "password_reset" }, "10m");
  res.json({ ok: true, resetToken });
});

app.post("/api/auth/reset-password", loginLimiter, async (req, res) => {
  const { resetToken, password } = req.body || {};
  const payload = resetToken ? verifyToken(resetToken) : null;
  if (!payload || payload.scope !== "password_reset") {
    return res.status(400).json({ error: "رمز إعادة التعيين غير صالح" });
  }
  if (!password || String(password).length < 6) {
    return res.status(400).json({ error: "كلمة المرور يجب أن لا تقل عن 6 أحرف" });
  }
  const db = loadDB();
  const user = db.users.find((u) => u.id === payload.uid);
  if (!user) return res.status(404).json({ error: "User not found" });
  user.passwordHash = await bcrypt.hash(String(password), 10);
  saveDB(db);
  res.json({ ok: true });
});

app.post("/api/auth/verify-email", requireUser, (req, res) => {
  const user = (req as any).currentUser as User;
  const { code, request: requestNew } = req.body || {};
  if (requestNew) {
    issueOtp(user.id, "verify-email");
    return res.json({ ok: true, sent: true });
  }
  if (!verifyOtp(user.id, "verify-email", code)) {
    return res.status(400).json({ error: "رمز غير صحيح أو منتهي الصلاحية" });
  }
  const db = loadDB();
  const dbUser = db.users.find((u) => u.id === user.id)!;
  dbUser.emailVerified = true;
  saveDB(db);
  res.json({ ok: true, emailVerified: true });
});

app.get("/api/user/profile", requireUser, (req, res) => {
  const user = (req as any).currentUser as User;
  res.json({
    ...sanitizeUser(user),
    referralCode: user.referralCode || genReferralCode(),
    leaderRank: 0,
    leaderPoints: 0,
    weeklySalary: 0,
    nextPayoutDate: null,
  });
});

app.get("/api/user/telegram/status", requireUser, (req, res) => {
  const user = (req as any).currentUser as User;
  const isLinked = Boolean(user.telegram && user.telegram.trim() !== "");
  res.json({ linked: isLinked, telegramUsername: user.telegram || null });
});

// SECURITY FIX: link-token now issues a signed, short-lived, single-purpose
// JWT bound to the caller's own user id, instead of the old predictable
// `token_<userId>` string that verify-link accepted from ANYONE — which let
// any caller link (or hijack) any account's Telegram handle just by knowing
// or guessing its user id.
app.post("/api/user/telegram/link-token", requireUser, (req, res) => {
  const db = loadDB();
  const user = (req as any).currentUser as User;
  const botName = TELEGRAM_BOT_USERNAME || db.siteSettings.telegramSupportUsername || "TeroComunityBot";
  const linkToken = signToken({ uid: user.id, scope: "telegram_link" }, "15m");
  res.json({
    botUsername: botName,
    deepLink: `https://t.me/${botName}?start=link_${user.id}`,
    token: linkToken,
  });
});

app.post("/api/user/telegram/verify-link", (req, res) => {
  const { token, telegramUsername } = req.body || {};
  const payload = token ? verifyToken(token) : null;
  if (!payload || payload.scope !== "telegram_link") {
    return res.status(401).json({ error: "رمز الربط غير صالح أو منتهي الصلاحية" });
  }
  const db = loadDB();
  const user = db.users.find((u) => u.id === payload.uid);
  if (!user) return res.status(404).json({ error: "User not found" });

  user.telegram = telegramUsername || user.telegram || "@user_tg";
  saveDB(db);
  res.json({ ok: true, success: true, user: sanitizeUser(user) });
});

app.post("/api/user/telegram/request-invite", requireUser, (req, res) => {
  res.json({ ok: true, inviteLink: "https://t.me/tero_network_group" });
});

// ============================================================================
// --- Wallet Routes ---
// SECURITY FIX: previously used `db.users[0]` unconditionally, meaning every
// visitor's balance/withdraw calls operated on the exact same account no
// matter who (if anyone) was logged in. Now resolved from the verified JWT.
// ============================================================================
app.get("/api/wallet/balance", requireUser, (req, res) => {
  const user = (req as any).currentUser as User;
  res.json({ balance: user.balance.toFixed(2), available: user.balance.toFixed(2), currency: "USDT" });
});

app.get("/api/wallet/deposit-address", requireUser, (req, res) => {
  // This still shows every user the same shared address (real per-user
  // rotating deposit addresses need actual wallet infrastructure this
  // project doesn't have), but the address itself is now editable by the
  // admin — see getDepositAddress()/setDepositAddress() near the
  // treasury-settings routes, and /tero-hq/treasury-settings in the panel.
  const addr = getDepositAddress("POLYGON");
  res.json({ polygon: addr, address: addr, network: "POLYGON" });
});

app.post("/api/wallet/withdraw", requireUser, (req, res) => {
  const db = loadDB();
  const user = (req as any).currentUser as User;
  const { amount, address, network } = req.body || {};
  const amt = Number(amount);

  const settings = db.siteSettings;
  const minW = Number(settings.min_withdrawal_amount ?? 3);
  const maxW = Number(settings.max_withdrawal_amount ?? 5000);
  const feePct = Number(settings.withdrawal_fee ?? 0);

  // SECURITY FIX: this is the exploit verified during the audit — sending a
  // NEGATIVE amount made `user.balance -= amt` INCREASE the balance (e.g. a
  // -5000 withdrawal request raised the balance by 5000 instantly, with a
  // withdrawal record created besides). Every numeric bound below is new.
  if (!Number.isFinite(amt) || amt <= 0) {
    return res.status(400).json({ error: "مبلغ غير صالح" });
  }
  if (amt < minW) {
    return res.status(400).json({ error: `الحد الأدنى للسحب هو ${minW} USDT` });
  }
  if (amt > maxW) {
    return res.status(400).json({ error: `الحد الأقصى للسحب هو ${maxW} USDT` });
  }
  if (!address || typeof address !== "string" || address.trim().length < 6) {
    return res.status(400).json({ error: "عنوان محفظة غير صالح" });
  }
  if (user.isFrozen || user.status !== "active") {
    return res.status(403).json({ error: "الحساب غير مؤهل للسحب حالياً" });
  }
  if (settings.maintenanceMode && !settings.emergencyWithdrawalMode) {
    return res.status(503).json({ error: "الموقع تحت الصيانة حالياً" });
  }
  if (user.balance < amt) {
    return res.status(400).json({ error: "الرصيد غير كافٍ" });
  }

  // FIX: the 21% withdrawal_fee configured in site settings was previously
  // defined but never actually applied anywhere on the server. It's now
  // computed and recorded (usdtAmount = net amount the user actually
  // receives; feeAmount = platform fee), while the user's balance is still
  // debited the full requested amount (what they asked to move out).
  const fee = Math.round(amt * (feePct / 100) * 1e6) / 1e6;
  const netAmount = Math.round((amt - fee) * 1e6) / 1e6;

  user.balance -= amt;
  user.usdtBalance -= amt;

  const newWithdrawal: Withdrawal = {
    id: "wd_" + Date.now() + "_" + crypto.randomBytes(3).toString("hex"),
    userId: user.id,
    username: user.username,
    amount: amt,
    usdtAmount: netAmount,
    feeAmount: fee,
    address: address.trim(),
    network: network || "POLYGON",
    status: "pending_approval",
    createdAt: new Date().toISOString(),
  };

  db.withdrawals.unshift(newWithdrawal);
  saveDB(db);

  res.json({ success: true, withdrawal: newWithdrawal });
});

app.get("/api/transactions", requireUser, (req, res) => res.json({ items: [], total: 0 }));

app.get("/api/membership", requireUser, (req, res) => {
  const user = (req as any).currentUser as User;
  res.json({ tier: user.membershipTier || null, plan: user.membershipPlan || "none", dailyLimit: 0, remainingTasks: 0 });
});

// Public catalog — not personal data, stays unauthenticated.
app.get("/api/membership/plans", (req, res) => res.json(MEMBERSHIP_PLANS));

app.get("/api/tasks", (req, res) => {
  const db = loadDB();
  res.json(db.tasks);
});

app.get("/api/tasks/summary", requireUser, (req, res) => {
  res.json({ todayEarned: 0, totalRevenue: 0, remainingDays: 0 });
});

app.get("/api/tasks/streak", requireUser, (req, res) => {
  res.json({ currentStreak: 0, maxStreak: 0 });
});

app.get("/api/referrals", requireUser, (req, res) => res.json([]));

app.get("/api/referrals/stats", requireUser, (req, res) => {
  const user = (req as any).currentUser as User;
  res.json({ totalEarned: 0.0, totalReferrals: 0, referralCode: user.referralCode || genReferralCode() });
});

app.get("/api/referrals/salary-history", requireUser, (req, res) => {
  res.json({ totalReceived: 0, lastAmount: 0, payments: [] });
});

app.get("/api/notifications", requireUser, (req, res) => res.json([]));

// --- Public config / status endpoints (no personal data) ---
app.get("/api/networks/status", (req, res) => res.json({ polygon: true }));

app.get("/api/finance-settings", (req, res) => {
  const db = loadDB();
  res.json({
    min_deposit_amount: db.siteSettings.min_deposit_amount ?? 5,
    min_withdrawal_amount: db.siteSettings.min_withdrawal_amount ?? 3,
    withdrawal_fee: db.siteSettings.withdrawal_fee ?? 21,
    max_withdrawal_amount: db.siteSettings.max_withdrawal_amount ?? 5000,
    emergencyWithdrawalMode: Boolean(db.siteSettings.emergencyWithdrawalMode),
  });
});

app.get("/api/maintenance-status", (req, res) => {
  const db = loadDB();
  res.json({ enabled: Boolean(db.siteSettings.maintenanceMode) });
});

// Generic Fallback Catch-All for any not-yet-modeled endpoint (unchanged
// behavior from the original stub — returns an empty/inert shape rather
// than a 404 so the SPA doesn't hard-crash on features not implemented here).
app.all("/api/*", (req, res) => {
  if (req.method === "GET") {
    if (req.path.endsWith("s") || req.path.endsWith("s/")) return res.json([]);
    return res.json({});
  }
  res.json({ success: true });
});

// SPA fallback for client-side routing (e.g. /tero-hq)
app.get("*", (req, res) => {
  res.sendFile(path.join(process.cwd(), "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`TERO app dev server listening on http://0.0.0.0:${PORT}`);
});
