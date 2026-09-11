import express from "express";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import admin from "firebase-admin";

const app = express();
const PORT = 3000;

// =====================================================================
// SECURITY: password hashing + signed session tokens
// =====================================================================
// Passwords are hashed with scrypt (Node's built-in, no extra dependency).
// Tokens are HMAC-signed JSON — nobody can forge or edit one without
// knowing SESSION_SECRET, unlike the old `base64(username)` "tokens".
//
// SESSION_SECRET must be set in production (env var). If it's missing we
// generate a random one at boot so the app still runs in dev, but that
// means every restart invalidates existing sessions — a deliberate
// nudge to set a real secret before deploying.
const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  (() => {
    const generated = crypto.randomBytes(32).toString("hex");
    console.warn(
      "[security] SESSION_SECRET is not set. Using a random secret for this " +
      "process only — all sessions will be invalidated on restart. Set " +
      "SESSION_SECRET in your environment before deploying to production."
    );
    return generated;
  })();

function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password: string, stored: string | undefined): boolean {
  if (!stored || !stored.includes(":")) return false;
  const [salt, hash] = stored.split(":");
  const candidate = crypto.scryptSync(password, salt, 64).toString("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(candidate, "hex"));
  } catch {
    return false;
  }
}

function signToken(payload: Record<string, any>, expiresInSeconds = 60 * 60 * 24 * 7): string {
  const body = { ...payload, exp: Date.now() + expiresInSeconds * 1000 };
  const encoded = Buffer.from(JSON.stringify(body)).toString("base64url");
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(encoded).digest("base64url");
  return `${encoded}.${sig}`;
}

function verifyToken(token: string | undefined | null): Record<string, any> | null {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [encoded, sig] = parts;
  const expectedSig = crypto.createHmac("sha256", SESSION_SECRET).update(encoded).digest("base64url");
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) return null;
  } catch {
    return null;
  }
  try {
    const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function getBearerToken(req: express.Request): string | null {
  const header = req.headers.authorization || "";
  if (header.startsWith("Bearer ")) return header.slice(7).trim();
  return null;
}

// Resolves the *real* logged-in user from a signed token. Previously every
// "current user" endpoint (wallet balance, withdraw, profile, telegram
// status...) either decoded an unsigned base64 token OR — for several
// routes — just returned db.users[0] regardless of who was calling, so
// every visitor saw the same account. That's fixed by always resolving
// through this function.
function getAuthenticatedUser(req: express.Request, db: DBData): User | null {
  const payload = verifyToken(getBearerToken(req));
  if (!payload || payload.role !== "user" || !payload.sub) return null;
  return db.users.find(u => u.id === payload.sub) || null;
}

// Strips passwordHash before a user object goes out over the wire —
// even to the admin panel, which is authenticated but still has no reason
// to receive password hashes.
function stripSensitive(user: User): Omit<User, "passwordHash"> {
  const { passwordHash, ...safe } = user;
  return safe;
}

// CORS middleware
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

app.use(express.json());

// Resolve directory
const currentDir = typeof __dirname !== "undefined" ? __dirname : process.cwd();
const distDir = path.join(process.cwd(), "dist");

// Serve static assets
app.use(express.static(process.cwd()));
app.use(express.static(distDir));
app.use(express.static(currentDir));

// --- Firebase Cloud Firestore Initialization (Admin SDK) ---
// IMPORTANT: this now uses firebase-admin with a service account, not the
// client SDK. The client SDK was making the *server* subject to Firestore's
// public security rules — combined with `allow read, write: if true` in
// firestore.rules, that meant anyone on the internet could read/write the
// database directly, bypassing this API entirely. The Admin SDK
// authenticates as a trusted service account and always uses full
// privileges regardless of security rules, so firestore.rules can (and
// now does) deny all direct client access.
//
// You must provide a service account key — generate one from
// Firebase Console → Project Settings → Service Accounts → Generate new
// private key, then set FIREBASE_SERVICE_ACCOUNT_JSON to its full JSON
// content (as a single env var string), or GOOGLE_APPLICATION_CREDENTIALS
// to a path to the key file. Nothing here can guess that secret for you.
let firestoreDb: admin.firestore.Firestore | null = null;
try {
  const configPath = path.join(process.cwd(), "firebase-applet-config.json");
  const hasClientConfig = fs.existsSync(configPath);
  const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  const firebaseConfig = hasClientConfig
    ? JSON.parse(fs.readFileSync(configPath, "utf-8"))
    : {};

  if (serviceAccountJson) {
    const serviceAccount = JSON.parse(serviceAccountJson);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      projectId: firebaseConfig.projectId || serviceAccount.project_id
    });
    firestoreDb = admin.firestore();
    if (firebaseConfig.firestoreDatabaseId) {
      firestoreDb = admin.firestore();
      firestoreDb.settings({ databaseId: firebaseConfig.firestoreDatabaseId } as any);
    }
    console.log("Firebase Admin Firestore initialized with database:", firebaseConfig.firestoreDatabaseId || "default");
  } else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    admin.initializeApp({
      credential: admin.credential.applicationDefault(),
      projectId: firebaseConfig.projectId
    });
    firestoreDb = admin.firestore();
    console.log("Firebase Admin Firestore initialized via GOOGLE_APPLICATION_CREDENTIALS.");
  } else {
    console.warn(
      "[firestore] No service account provided (FIREBASE_SERVICE_ACCOUNT_JSON or " +
      "GOOGLE_APPLICATION_CREDENTIALS). Running on local data.json only — cloud " +
      "sync is disabled until credentials are supplied."
    );
  }
} catch (err) {
  console.error("Firebase initialization failed:", err);
}

// --- Stateful In-Memory Database with Cloud Firestore & File Persistence ---
const DATA_FILE = path.join(process.cwd(), "data.json");

interface User {
  id: string;
  username: string;
  email: string;
  passwordHash?: string;
  telegram?: string;
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

interface MembershipPlan {
  id: string;
  tier: string;
  name: string;
  price: number;
  dailyTaskLimit: number;
  incomeRate: number;
  durationDays: number;
  isPopular?: boolean;
}

interface TaskAccessCode {
  id: string;
  code: string;
  validHours?: number;
  createdAt: string;
  status?: string;
}

interface DBData {
  users: User[];
  deposits: Deposit[];
  withdrawals: Withdrawal[];
  tasks: Task[];
  membershipPlans?: MembershipPlan[];
  taskAccessCodes?: TaskAccessCode[];
  siteSettings: Record<string, any>;
}

const DEFAULT_MEMBERSHIP_PLANS: MembershipPlan[] = [
  {
    id: "p1",
    tier: "free",
    name: "المستوى المجاني",
    price: 0,
    dailyTaskLimit: 3,
    incomeRate: 0.5,
    durationDays: 365,
    isPopular: false
  },
  {
    id: "p2",
    tier: "vip1",
    name: "VIP 1",
    price: 50,
    dailyTaskLimit: 10,
    incomeRate: 1.5,
    durationDays: 30,
    isPopular: false
  },
  {
    id: "p3",
    tier: "vip2",
    name: "VIP 2",
    price: 200,
    dailyTaskLimit: 25,
    incomeRate: 4.5,
    durationDays: 30,
    isPopular: true
  },
  {
    id: "p4",
    tier: "vip3",
    name: "VIP 3",
    price: 500,
    dailyTaskLimit: 50,
    incomeRate: 12.0,
    durationDays: 30,
    isPopular: false
  }
];

let inMemoryDB: DBData = {
  users: [],
  deposits: [],
  withdrawals: [],
  tasks: [],
  membershipPlans: DEFAULT_MEMBERSHIP_PLANS,
  taskAccessCodes: [
    { id: "tac_default", code: "TERO1234", validHours: 24, createdAt: new Date().toISOString(), status: "running" }
  ],
  siteSettings: {
    siteName: "TERO Network",
    maintenanceMode: false,
    telegramSupportUsername: "TeroComunityBot",
    emergencyWithdrawalMode: false,
    currentTaskAccessCode: "TERO1234",
    treasuryAddresses: {
      POLYGON: "0x113494B3aB9369CF9C66dE27255c948EF1266517"
    }
  }
};

// --- Admin credentials ---------------------------------------------------
// No more hardcoded admin/admin123 in source. Credentials come from
// ADMIN_USERNAME / ADMIN_PASSWORD env vars on first boot and are stored
// hashed from then on (in data.json / Firestore, never in plaintext).
// If the env vars are absent, a random one-time password is generated and
// printed to the console so the app is still usable in local dev — but you
// MUST capture it or set real env vars before deploying anywhere public.
function ensureAdminAuthSeeded(db: DBData) {
  if (db.siteSettings.adminAuth?.passwordHash) return;
  const username = (process.env.ADMIN_USERNAME || "admin").trim().toLowerCase();
  let password = process.env.ADMIN_PASSWORD;
  let generated = false;
  if (!password) {
    password = crypto.randomBytes(9).toString("base64url");
    generated = true;
  }
  db.siteSettings.adminAuth = {
    username,
    passwordHash: hashPassword(password)
  };
  if (generated) {
    console.warn(
      `[security] ADMIN_PASSWORD not set. Generated a one-time admin password ` +
      `for user "${username}": ${password}\n` +
      `Set ADMIN_USERNAME / ADMIN_PASSWORD env vars for a real deployment — ` +
      `this generated password will be different on every restart.`
    );
  }
}

// --- Optional on-chain deposit verification (Polygon / USDT) -------------
// Uses raw JSON-RPC (no extra SDK dependency) against POLYGON_RPC_URL.
// Checks the transaction succeeded and includes an ERC-20 Transfer log
// from the configured USDT contract, to the treasury address, for at
// least the claimed amount. This only runs when POLYGON_RPC_URL is set —
// without it deposits stay "pending" for manual admin review, same as
// before.
const USDT_POLYGON_CONTRACT = (process.env.USDT_CONTRACT_ADDRESS || "0xc2132D05D31c914a87C6611C10748AEb04B58e8").toLowerCase();
const ERC20_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

async function rpcCall(method: string, params: any[]): Promise<any> {
  const rpcUrl = process.env.POLYGON_RPC_URL as string;
  const resp = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params })
  });
  const json: any = await resp.json();
  if (json.error) throw new Error(json.error.message || "RPC error");
  return json.result;
}

async function verifyPolygonUsdtDeposit(
  txHash: string,
  treasuryAddress: string,
  claimedAmount: number
): Promise<{ ok: boolean; reason?: string }> {
  const receipt = await rpcCall("eth_getTransactionReceipt", [txHash]);
  if (!receipt) return { ok: false, reason: "transaction not found (not mined yet?)" };
  if (receipt.status !== "0x1") return { ok: false, reason: "transaction reverted" };

  const targetTopic = "0x" + treasuryAddress.toLowerCase().replace(/^0x/, "").padStart(64, "0");
  const transferLog = (receipt.logs || []).find((log: any) =>
    log.address?.toLowerCase() === USDT_POLYGON_CONTRACT &&
    log.topics?.[0]?.toLowerCase() === ERC20_TRANSFER_TOPIC &&
    log.topics?.[2]?.toLowerCase() === targetTopic
  );
  if (!transferLog) return { ok: false, reason: "no matching USDT transfer to treasury address found in tx logs" };

  // USDT on Polygon uses 6 decimals.
  const transferredRaw = BigInt(transferLog.data);
  const transferredAmount = Number(transferredRaw) / 1_000_000;
  if (transferredAmount + 0.000001 < claimedAmount) {
    return { ok: false, reason: `on-chain amount ${transferredAmount} is less than claimed ${claimedAmount}` };
  }
  return { ok: true };
}

function getTreasuryAddress(net: string = "POLYGON"): string {
  const db = loadDB();
  const netKey = (net || "POLYGON").toUpperCase();
  if (db.siteSettings?.treasuryAddresses && db.siteSettings.treasuryAddresses[netKey]) {
    return db.siteSettings.treasuryAddresses[netKey];
  }
  if (db.siteSettings?.polygonAddress) {
    return db.siteSettings.polygonAddress;
  }
  if (db.siteSettings?.treasuryAddress) {
    return db.siteSettings.treasuryAddress;
  }
  return "0x113494B3aB9369CF9C66dE27255c948EF1266517";
}

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

ensureAdminAuthSeeded(inMemoryDB);
try {
  fs.writeFileSync(DATA_FILE, JSON.stringify(inMemoryDB, null, 2));
} catch (e) {
  console.error("Failed to persist seeded admin credentials", e);
}

// Async Hydrate from Cloud Firestore
async function hydrateFromFirestore() {
  if (!firestoreDb) return;
  try {
    console.log("Hydrating data from Firebase Firestore...");
    // 1. Users
    const usersSnap = await firestoreDb.collection("users").get();
    if (!usersSnap.empty) {
      inMemoryDB.users = usersSnap.docs.map(d => d.data() as User);
    }

    // 2. Deposits
    const depositsSnap = await firestoreDb.collection("deposits").get();
    if (!depositsSnap.empty) {
      inMemoryDB.deposits = depositsSnap.docs.map(d => d.data() as Deposit);
    }

    // 3. Withdrawals
    const withdrawalsSnap = await firestoreDb.collection("withdrawals").get();
    if (!withdrawalsSnap.empty) {
      inMemoryDB.withdrawals = withdrawalsSnap.docs.map(d => d.data() as Withdrawal);
    }

    // 4. Tasks
    const tasksSnap = await firestoreDb.collection("tasks").get();
    if (!tasksSnap.empty) {
      inMemoryDB.tasks = tasksSnap.docs.map(d => d.data() as Task);
    }

    // 5. Site Settings
    const settingsSnap = await firestoreDb.collection("siteSettings").doc("global").get();
    if (settingsSnap.exists) {
      const data = settingsSnap.data() as Record<string, any>;
      inMemoryDB.siteSettings = { ...inMemoryDB.siteSettings, ...data };
      if (data.membershipPlans) inMemoryDB.membershipPlans = data.membershipPlans;
      if (data.taskAccessCodes) inMemoryDB.taskAccessCodes = data.taskAccessCodes;
    } else {
      // Seed initial settings to Firestore
      await firestoreDb.collection("siteSettings").doc("global").set({
        ...inMemoryDB.siteSettings,
        membershipPlans: inMemoryDB.membershipPlans,
        taskAccessCodes: inMemoryDB.taskAccessCodes
      });
    }

    // Backup to local file
    fs.writeFileSync(DATA_FILE, JSON.stringify(inMemoryDB, null, 2));
    console.log(`Firestore hydration complete: ${inMemoryDB.users.length} users, ${inMemoryDB.deposits.length} deposits, ${inMemoryDB.withdrawals.length} withdrawals, ${inMemoryDB.tasks.length} tasks.`);
  } catch (err) {
    console.error("Failed to hydrate from Firestore:", err);
  }
}

let isHydrated = false;
let hydrationPromise: Promise<void> | null = null;

async function ensureHydrated() {
  if (isHydrated) return;
  if (!hydrationPromise) {
    hydrationPromise = (async () => {
      await hydrateFromFirestore();
      isHydrated = true;
    })();
  }
  await hydrationPromise;
}

// Trigger initial cloud sync
ensureHydrated().catch(() => {});

function loadDB(): DBData {
  return inMemoryDB;
}

async function saveUserDirect(user: User) {
  if (firestoreDb && user && user.id) {
    try {
      await firestoreDb.collection("users").doc(user.id).set(user);
    } catch (err) {
      console.error("Failed to save user directly to Firestore:", err);
    }
  }
}

async function saveDBAsync(db: DBData) {
  inMemoryDB = db;
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
  } catch (err) {
    console.error("Failed to save local DB", err);
  }

  if (firestoreDb) {
    try {
      for (const user of db.users) {
        if (user.id) {
          await firestoreDb.collection("users").doc(user.id).set(user);
        }
      }
      for (const dep of db.deposits) {
        if (dep.id) {
          await firestoreDb.collection("deposits").doc(dep.id).set(dep);
        }
      }
      for (const wd of db.withdrawals) {
        if (wd.id) {
          await firestoreDb.collection("withdrawals").doc(wd.id).set(wd);
        }
      }
      for (const task of db.tasks) {
        if (task.id) {
          await firestoreDb.collection("tasks").doc(task.id).set(task);
        }
      }
      db.siteSettings.membershipPlans = db.membershipPlans || DEFAULT_MEMBERSHIP_PLANS;
      db.siteSettings.taskAccessCodes = db.taskAccessCodes || [];
      await firestoreDb.collection("siteSettings").doc("global").set(db.siteSettings);
    } catch (cloudErr) {
      console.error("Error writing to Firestore:", cloudErr);
    }
  }
}

function saveDB(db: DBData) {
  inMemoryDB = db;
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
  } catch (err) {
    console.error("Failed to save local DB", err);
  }
  saveDBAsync(db).catch(() => {});
}


// API Health
app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

// --- Admin Auth ---
// Very small in-memory brute-force guard: 5 failed attempts per username
// locks it out for 5 minutes. Resets on process restart — good enough to
// stop naive credential-stuffing, not a substitute for a real WAF.
const adminLoginAttempts = new Map<string, { count: number; lockedUntil: number }>();
const ADMIN_LOGIN_MAX_ATTEMPTS = 5;
const ADMIN_LOGIN_LOCKOUT_MS = 5 * 60 * 1000;

app.post("/api/admin/auth/login", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  ensureAdminAuthSeeded(db);

  const { username, password } = req.body || {};
  const uname = (username || "").trim().toLowerCase();
  const pass = (password || "").toString();

  const attempt = adminLoginAttempts.get(uname);
  if (attempt && attempt.lockedUntil > Date.now()) {
    const waitSec = Math.ceil((attempt.lockedUntil - Date.now()) / 1000);
    return res.status(429).json({ error: `محاولات كثيرة فاشلة، حاول بعد ${waitSec} ثانية` });
  }

  const adminAuth = db.siteSettings.adminAuth;
  const isValid = adminAuth && uname === adminAuth.username && verifyPassword(pass, adminAuth.passwordHash);

  if (isValid) {
    adminLoginAttempts.delete(uname);
    const token = signToken({ sub: uname, role: "admin" });
    res.json({ token, username: uname, role: "admin", message: "Login successful" });
  } else {
    const next = attempt ? attempt.count + 1 : 1;
    adminLoginAttempts.set(uname, {
      count: next,
      lockedUntil: next >= ADMIN_LOGIN_MAX_ATTEMPTS ? Date.now() + ADMIN_LOGIN_LOCKOUT_MS : 0
    });
    res.status(401).json({ error: "اسم المستخدم أو كلمة المرور غير صحيحة" });
  }
});

app.get("/api/admin/auth/me", (req, res) => {
  const payload = verifyToken(getBearerToken(req));
  if (!payload || payload.role !== "admin") {
    return res.status(401).json({ error: "Unauthorized" });
  }
  res.json({
    username: payload.sub,
    email: payload.sub.includes("@") ? payload.sub : `${payload.sub}@teronetwork.com`,
    role: "admin",
    authenticated: true
  });
});

app.post("/api/admin/auth/logout", (req, res) => {
  // Stateless tokens — logout is handled client-side by discarding the
  // token. Nothing to invalidate server-side without a session store.
  res.json({ success: true });
});

// --- Auth guard for every other /api/admin/* route -----------------------
// Previously NONE of the ~120 admin endpoints below checked authentication
// at all — anyone who found the URL could read every user, edit balances,
// approve withdrawals, change treasury addresses, etc. This middleware
// closes that gap for everything registered after this point.
app.use("/api/admin", (req, res, next) => {
  // Login/me/logout are handled above (before this middleware) and stay
  // public; forgot-password must also stay public since the caller is,
  // by definition, not logged in yet.
  if (req.path === "/auth/forgot-password") return next();
  const payload = verifyToken(getBearerToken(req));
  if (!payload || payload.role !== "admin") {
    return res.status(401).json({ error: "Unauthorized — admin login required" });
  }
  (req as any).admin = payload;
  next();
});

// --- Admin Users Management ---
app.get("/api/admin/users", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const search = (req.query.search as string || "").toLowerCase();
  const page = parseInt(req.query.page as string || "1", 10);
  const limit = parseInt(req.query.limit as string || "20", 10);

  let filtered = db.users;
  if (search) {
    filtered = filtered.filter(u =>
      u.username.toLowerCase().includes(search) ||
      u.email.toLowerCase().includes(search) ||
      (u.telegram && u.telegram.toLowerCase().includes(search))
    );
  }

  const start = (page - 1) * limit;
  const paginated = filtered.slice(start, start + limit);

  res.json({
    users: paginated.map(stripSensitive),
    total: filtered.length
  });
});

app.get("/api/admin/users/freeze-candidates/count", (req, res) => {
  res.json({ count: 0 });
});

app.get("/api/admin/users/frozen-inactivity/count", (req, res) => {
  res.json({ count: 0 });
});

app.get("/api/admin/users/:id", (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }
  res.json({ user: stripSensitive(user) });
});

// Edit user / update balance / status
app.post("/api/admin/users/:id", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  const { balance, usdtBalance, status, isFrozen, username, email, telegram, membershipTier } = req.body || {};
  if (balance !== undefined) user.balance = parseFloat(balance);
  if (usdtBalance !== undefined) user.usdtBalance = parseFloat(usdtBalance);
  if (status !== undefined) user.status = status;
  if (isFrozen !== undefined) user.isFrozen = Boolean(isFrozen);
  if (username !== undefined) user.username = username;
  if (email !== undefined) user.email = email;
  if (telegram !== undefined) user.telegram = telegram;
  if (membershipTier !== undefined) user.membershipTier = membershipTier;

  saveDB(db);
  await saveUserDirect(user);
  await saveDBAsync(db);
  res.json({ success: true, ok: true, user: stripSensitive(user) });
});

app.put("/api/admin/users/:id", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  const { balance, usdtBalance, status, isFrozen, username, email, telegram, membershipTier } = req.body || {};
  if (balance !== undefined) user.balance = parseFloat(balance);
  if (usdtBalance !== undefined) user.usdtBalance = parseFloat(usdtBalance);
  if (status !== undefined) user.status = status;
  if (isFrozen !== undefined) user.isFrozen = Boolean(isFrozen);
  if (username !== undefined) user.username = username;
  if (email !== undefined) user.email = email;
  if (telegram !== undefined) user.telegram = telegram;
  if (membershipTier !== undefined) user.membershipTier = membershipTier;

  saveDB(db);
  await saveUserDirect(user);
  await saveDBAsync(db);
  res.json({ success: true, ok: true, user: stripSensitive(user) });
});

// New: existing users (seeded via data.json before this fix) have no
// password and can't log in under the new auth system until an admin
// sets one for them.
app.post("/api/admin/users/:id/set-password", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: "User not found" });

  const newPassword = (req.body?.password || "").toString();
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: "كلمة المرور يجب أن تكون 6 أحرف على الأقل" });
  }
  user.passwordHash = hashPassword(newPassword);
  saveDB(db);
  await saveUserDirect(user);
  res.json({ success: true, ok: true });
});

app.post("/api/admin/users/:id/freeze-inactivity", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (user) {
    user.isFrozen = true;
    user.status = "frozen";
    saveDB(db);
    await saveUserDirect(user);
    await saveDBAsync(db);
  }
  res.json({ success: true, ok: true });
});

app.post("/api/admin/users/:id/freeze-with-team", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (user) {
    user.isFrozen = true;
    user.status = "frozen";
    saveDB(db);
    await saveUserDirect(user);
    await saveDBAsync(db);
  }
  res.json({ success: true, ok: true });
});

app.post("/api/admin/users/:id/unlink-telegram", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (user) {
    user.telegram = "";
    saveDB(db);
    await saveUserDirect(user);
    await saveDBAsync(db);
  }
  res.json({ success: true, ok: true });
});

// --- Admin Deposits Management ---
app.get("/api/admin/deposits", (req, res) => {
  const db = loadDB();
  const page = parseInt(req.query.page as string || "1", 10);
  const limit = parseInt(req.query.limit as string || "30", 10);

  const start = (page - 1) * limit;
  const paginated = db.deposits.slice(start, start + limit);

  res.json({
    deposits: paginated,
    total: db.deposits.length
  });
});

app.post("/api/admin/deposits/:id/approve", (req, res) => {
  const db = loadDB();
  const dep = db.deposits.find(d => d.id === req.params.id);
  if (dep) {
    dep.status = "confirmed";
    const user = db.users.find(u => u.id === dep.userId || u.username === dep.username);
    if (user) {
      user.balance += parseFloat(dep.amount || "0");
      user.usdtBalance += parseFloat(dep.amount || "0");
    }
    saveDB(db);
  }
  res.json({ success: true });
});

app.post("/api/admin/deposits/:id/reject", (req, res) => {
  const db = loadDB();
  const dep = db.deposits.find(d => d.id === req.params.id);
  if (dep) {
    dep.status = "failed";
    saveDB(db);
  }
  res.json({ success: true });
});

// --- Admin Withdrawals Management ---
app.get("/api/admin/withdrawals", (req, res) => {
  const db = loadDB();
  const statusFilter = req.query.status as string;
  let filtered = db.withdrawals;
  if (statusFilter) {
    filtered = filtered.filter(w => w.status === statusFilter);
  }
  res.json({ withdrawals: filtered, total: filtered.length });
});

app.get("/api/admin/withdrawals/planning/summary", (req, res) => {
  const db = loadDB();
  const pending = db.withdrawals.filter(w => w.status === "pending_approval");
  const totalUsdt = pending.reduce((acc, curr) => acc + (curr.usdtAmount || 0), 0);
  res.json({
    ok: true,
    totalCount: pending.length,
    totalUsdt,
    uniqueNets: 1,
    scheduledDays: 1,
    gasBreakdown: []
  });
});

app.post("/api/admin/withdrawals/:id/approve", (req, res) => {
  const db = loadDB();
  const wd = db.withdrawals.find(w => w.id === req.params.id);
  if (wd) {
    wd.status = "completed";
    saveDB(db);
  }
  res.json({ success: true });
});

app.post("/api/admin/withdrawals/:id/reject", (req, res) => {
  const db = loadDB();
  const wd = db.withdrawals.find(w => w.id === req.params.id);
  if (wd) {
    wd.status = "rejected";
    wd.rejectionReason = req.body?.reason || "تم الرفض بواسطة المشرف";
    const user = db.users.find(u => u.id === wd.userId || u.username === wd.username);
    if (user) {
      user.balance += wd.amount;
      user.usdtBalance += wd.amount;
    }
    saveDB(db);
  }
  res.json({ success: true });
});

app.post("/api/admin/withdrawals/:id/cancel", (req, res) => {
  const db = loadDB();
  const wd = db.withdrawals.find(w => w.id === req.params.id);
  if (wd) {
    wd.status = "cancelled";
    const user = db.users.find(u => u.id === wd.userId || u.username === wd.username);
    if (user) {
      user.balance += wd.amount;
      user.usdtBalance += wd.amount;
    }
    saveDB(db);
  }
  res.json({ success: true });
});

// --- Admin Tasks Management ---
app.get("/api/admin/tasks", (req, res) => {
  const db = loadDB();
  res.json({ tasks: db.tasks, total: db.tasks.length });
});

app.post("/api/admin/tasks", (req, res) => {
  const db = loadDB();
  const newTask: Task = {
    id: "t_" + Date.now(),
    platform: req.body?.platform || "tiktok",
    title: req.body?.title || "مهمة جديدة",
    description: req.body?.description || "",
    reward: parseFloat(req.body?.reward || "1.0"),
    targetUrl: req.body?.targetUrl || "",
    isActive: true,
    order: db.tasks.length + 1
  };
  db.tasks.push(newTask);
  saveDB(db);
  res.json({ success: true, task: newTask, ok: true });
});

app.put("/api/admin/tasks/:id", (req, res) => {
  const db = loadDB();
  const task = db.tasks.find(t => t.id === req.params.id);
  if (task) {
    Object.assign(task, req.body);
    saveDB(db);
  }
  res.json({ success: true, task, ok: true });
});

app.delete("/api/admin/tasks/:id", (req, res) => {
  const db = loadDB();
  db.tasks = db.tasks.filter(t => t.id !== req.params.id);
  saveDB(db);
  res.json({ success: true, ok: true });
});

app.post("/api/admin/tasks/bulk-action", (req, res) => {
  const db = loadDB();
  const { action, ids } = req.body || {};
  if (Array.isArray(ids)) {
    if (action === "activate") {
      db.tasks.forEach(t => { if (ids.includes(t.id)) t.isActive = true; });
    } else if (action === "deactivate") {
      db.tasks.forEach(t => { if (ids.includes(t.id)) t.isActive = false; });
    } else if (action === "delete") {
      db.tasks = db.tasks.filter(t => !ids.includes(t.id));
    }
    saveDB(db);
  }
  res.json({ ok: true, success: true });
});

app.post("/api/admin/tasks/bulk-delete-ids", (req, res) => {
  const db = loadDB();
  const { ids } = req.body || {};
  if (Array.isArray(ids)) {
    db.tasks = db.tasks.filter(t => !ids.includes(t.id));
    saveDB(db);
  }
  res.json({ ok: true, success: true });
});

app.post("/api/admin/tasks/bulk", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const tasksToAdd = req.body?.tasks;
  let count = 0;
  if (Array.isArray(tasksToAdd)) {
    tasksToAdd.forEach((t: any) => {
      const newTask: Task = {
        id: "t_" + Date.now() + "_" + Math.floor(Math.random() * 1000),
        platform: t.platform || "tiktok",
        title: t.title || "مهمة جديدة",
        description: t.description || "",
        reward: parseFloat(t.reward || "0.5"),
        targetUrl: t.targetUrl || t.url || "https://tero.com",
        isActive: t.isActive ?? true,
        order: db.tasks.length + 1
      };
      db.tasks.push(newTask);
      count++;
    });
    saveDB(db);
    await saveDBAsync(db);
  }
  res.json({ ok: true, success: true, count, skipped: 0 });
});

app.post("/api/admin/tasks/recycle-links", (req, res) => {
  res.json({ ok: true, success: true, cleared: 0 });
});

app.post("/api/admin/tasks/new-week", (req, res) => {
  res.json({ ok: true, success: true, deletedTemplates: 0 });
});

app.post("/api/admin/tasks/import-csv", (req, res) => {
  res.json({ ok: true, success: true, count: 0 });
});

app.get("/api/admin/tasks/export-csv", (req, res) => {
  res.setHeader("Content-Type", "text/csv");
  res.send("id,platform,title,reward,targetUrl,isActive\n");
});

app.get("/api/admin/task-dashboard", (req, res) => {
  const db = loadDB();
  const total = db.tasks.length;
  const active = db.tasks.filter(t => t.isActive).length;
  const inactive = total - active;

  const byPlatform: Record<string, any> = {
    tiktok: { total: 0, active: 0, views: 0, completions: 0, successRate: 100 },
    youtube: { total: 0, active: 0, views: 0, completions: 0, successRate: 100 },
    telegram: { total: 0, active: 0, views: 0, completions: 0, successRate: 100 },
    twitter: { total: 0, active: 0, views: 0, completions: 0, successRate: 100 },
    instagram: { total: 0, active: 0, views: 0, completions: 0, successRate: 100 },
    facebook: { total: 0, active: 0, views: 0, completions: 0, successRate: 100 }
  };

  for (const t of db.tasks) {
    const p = (t.platform || "tiktok").toLowerCase();
    if (!byPlatform[p]) {
      byPlatform[p] = { total: 0, active: 0, views: 0, completions: 0, successRate: 100 };
    }
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
    totalViews: Math.max(1, 12 - idx)
  }));

  res.json({
    dashboard: {
      templates: {
        total,
        active,
        inactive,
        byPlatform
      },
      performance: {
        overallSuccessRate: 98
      },
      today: {
        completed: 0,
        selected: 0,
        available: active,
        rejected: 0
      },
      yesterday: 0,
      weekTotal: 0,
      topTemplates,
      recentActivity: []
    },
    activeTasks: active,
    totalSubmissions: 0,
    pendingSubmissions: 0
  });
});

app.get("/api/admin/task-alerts", (req, res) => {
  res.json({ alerts: [] });
});

app.get("/api/admin/task-activity", (req, res) => {
  res.json({
    activity: [],
    pagination: { total: 0, page: 1, limit: 50, totalPages: 1 }
  });
});

app.get("/api/admin/task-access-codes/current", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const currentCode = db.siteSettings.currentTaskAccessCode || "TERO1234";
  res.json({ ok: true, code: currentCode });
});

app.get("/api/admin/task-access-codes", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const codes = db.taskAccessCodes || [];
  res.json({ ok: true, codes });
});

app.post("/api/admin/task-access-codes", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const { code, manualCode, customCode, validHours } = req.body || {};
  const newCode = (code || manualCode || customCode || req.body?.accessCode || ("TAC_" + Math.floor(100000 + Math.random() * 900000))).toString().trim().toUpperCase();

  if (!newCode) {
    return res.status(400).json({ error: "الرمز مطلوب" });
  }

  db.siteSettings.currentTaskAccessCode = newCode;
  if (!db.taskAccessCodes) db.taskAccessCodes = [];

  // Retire any previously-active codes so only the newest one validates —
  // otherwise every code ever created stays valid forever (as long as it's
  // still within its own validHours window), which defeats the point of
  // rotating codes.
  db.taskAccessCodes.forEach(c => {
    if ((c.status || "running") === "running") c.status = "replaced";
  });

  const entry: TaskAccessCode = {
    id: "tac_" + Date.now(),
    code: newCode,
    validHours: parseInt(validHours || "24", 10),
    createdAt: new Date().toISOString(),
    status: "running"
  };

  db.taskAccessCodes.unshift(entry);
  saveDB(db);
  await saveDBAsync(db);

  res.json({ ok: true, success: true, code: newCode, entry });
});

// New: edit an existing code's value/validHours in place (rather than
// only being able to create a brand new one and delete the old one).
app.put("/api/admin/task-access-codes/:id", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  if (!db.taskAccessCodes) db.taskAccessCodes = [];
  const entry = db.taskAccessCodes.find(c => c.id === req.params.id);
  if (!entry) return res.status(404).json({ error: "الرمز غير موجود" });

  const { code, validHours, status } = req.body || {};
  if (code) {
    entry.code = code.toString().trim().toUpperCase();
    if ((entry.status || "running") === "running") {
      db.siteSettings.currentTaskAccessCode = entry.code;
    }
  }
  if (validHours !== undefined) entry.validHours = parseInt(validHours, 10);
  if (status) entry.status = status;

  saveDB(db);
  await saveDBAsync(db);
  res.json({ ok: true, success: true, entry });
});

app.delete("/api/admin/task-access-codes/:id", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  if (db.taskAccessCodes) {
    db.taskAccessCodes = db.taskAccessCodes.filter(c => c.id !== req.params.id);
    saveDB(db);
    await saveDBAsync(db);
  }
  res.json({ ok: true, success: true });
});

app.get("/api/admin/task-code-gen/settings", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  res.json({
    settings: {
      enabled: db.siteSettings.taskCodeGenEnabled ?? true,
      intervalHours: 24,
      lastRun: new Date().toISOString(),
      status: "idle",
      currentCode: db.siteSettings.currentTaskAccessCode || "TERO1234"
    }
  });
});

app.patch("/api/admin/task-code-gen/settings", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  if (req.body?.enabled !== undefined) {
    db.siteSettings.taskCodeGenEnabled = Boolean(req.body.enabled);
    saveDB(db);
    await saveDBAsync(db);
  }
  res.json({ enabled: db.siteSettings.taskCodeGenEnabled ?? true, ok: true });
});

app.get("/api/admin/task-code-gen/log", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const logs = (db.taskAccessCodes || []).map(c => ({
    id: c.id,
    code: c.code,
    createdAt: c.createdAt,
    status: c.status || "running"
  }));
  res.json({ logs });
});

app.post("/api/admin/task-code-gen/manual", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const { code, manualCode, customCode } = req.body || {};
  const newCode = (code || manualCode || customCode || req.body?.accessCode || ("TERO" + Math.floor(100000 + Math.random() * 900000))).toString().trim().toUpperCase();

  db.siteSettings.currentTaskAccessCode = newCode;
  if (!db.taskAccessCodes) db.taskAccessCodes = [];
  db.taskAccessCodes.forEach(c => {
    if ((c.status || "running") === "running") c.status = "replaced";
  });

  const logEntry: TaskAccessCode = {
    id: "log_" + Date.now(),
    code: newCode,
    validHours: 24,
    createdAt: new Date().toISOString(),
    status: "running"
  };

  db.taskAccessCodes.unshift(logEntry);
  saveDB(db);
  await saveDBAsync(db);

  res.json({
    ok: true,
    success: true,
    log: logEntry,
    code: newCode
  });
});

app.post("/api/admin/task-code-gen/resend/:id", (req, res) => {
  res.json({ ok: true });
});

app.get("/api/admin/task-submissions", (req, res) => {
  res.json({ submissions: [], total: 0 });
});

app.get("/api/admin/task-submissions/stats", (req, res) => {
  res.json({ pending: 0, approved: 0, rejected: 0 });
});

app.post("/api/admin/task-submissions/:id/approve", (req, res) => {
  res.json({ ok: true, success: true });
});

app.post("/api/admin/task-submissions/:id/reject", (req, res) => {
  res.json({ ok: true, success: true });
});

// --- Sweeps & Gas Management ---
app.get("/api/admin/sweeps", (req, res) => {
  res.json([]);
});

app.post("/api/admin/sweeps/run", (req, res) => {
  res.json({ ok: true, swept: 0 });
});

app.get("/api/admin/gas-management", async (req, res) => {
  await ensureHydrated();
  const polygonAddr = getTreasuryAddress("POLYGON");
  res.json({
    summary: {
      criticalNetworks: [],
      warningNetworks: [],
      readyNetworks: ["POLYGON"],
      totalNativeUsd: 100.00
    },
    networks: [
      {
        network: "POLYGON",
        name: "Polygon PoS",
        nativeSymbol: "POL",
        status: "ready",
        balance: 10.5,
        balanceUsd: 8.5,
        address: polygonAddr,
        minRequired: 1.0,
        addressesNeedingGas: 0,
        estimatedGasCostUsd: 0.005
      }
    ]
  });
});

// --- Treasury & Hot Wallet ---
app.get("/api/admin/treasury", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const polygonAddr = getTreasuryAddress("POLYGON");
  const totalUserBalances = db.users.reduce((sum, u) => sum + (u.balance || 0), 0);
  res.json({
    totalBalance: totalUserBalances,
    hotWallet: totalUserBalances * 0.4,
    coldWallet: totalUserBalances * 0.6,
    addresses: [
      { network: "POLYGON", address: polygonAddr, balance: totalUserBalances }
    ]
  });
});

function isValidEvmAddress(addr: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(addr);
}

app.get("/api/admin/treasury-settings", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const polyAddr = getTreasuryAddress("POLYGON");
  const settingsObj: Record<string, any> = {
    POLYGON: { address: polyAddr, network: "POLYGON" }
  };
  
  if (db.siteSettings.treasuryAddresses) {
    Object.keys(db.siteSettings.treasuryAddresses).forEach(net => {
      settingsObj[net] = { address: db.siteSettings.treasuryAddresses[net], network: net };
    });
  }

  res.json({
    settings: settingsObj,
    sweepEnabled: true,
    ok: true
  });
});

app.put("/api/admin/treasury-settings", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const { network, address, POLYGON } = req.body || {};
  const net = (network || "POLYGON").toUpperCase();
  const targetAddr = (address || POLYGON || req.body?.[net] || req.body?.address || "").toString().trim();

  if (!targetAddr) {
    return res.status(400).json({ error: "العنوان مطلوب" });
  }
  // Was previously saved with no format check at all — a typo here
  // silently breaks deposits for every user until someone notices.
  if (net === "POLYGON" && !isValidEvmAddress(targetAddr)) {
    return res.status(400).json({ error: "عنوان محفظة Polygon غير صالح، يجب أن يبدأ بـ 0x ويتكون من 42 حرفًا" });
  }

  if (!db.siteSettings.treasuryAddresses) {
    db.siteSettings.treasuryAddresses = {};
  }
  db.siteSettings.treasuryAddresses[net] = targetAddr;
  db.siteSettings.polygonAddress = targetAddr;
  db.siteSettings.treasuryAddress = targetAddr;

  saveDB(db);
  await saveDBAsync(db);

  res.json({ ok: true, success: true, settings: db.siteSettings.treasuryAddresses });
});

app.post("/api/admin/treasury-settings", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const { network, address, POLYGON } = req.body || {};
  const net = (network || "POLYGON").toUpperCase();
  const targetAddr = (address || POLYGON || req.body?.[net] || req.body?.address || "").toString().trim();

  if (!targetAddr) {
    return res.status(400).json({ error: "العنوان مطلوب" });
  }
  if (net === "POLYGON" && !isValidEvmAddress(targetAddr)) {
    return res.status(400).json({ error: "عنوان محفظة Polygon غير صالح، يجب أن يبدأ بـ 0x ويتكون من 42 حرفًا" });
  }

  if (!db.siteSettings.treasuryAddresses) {
    db.siteSettings.treasuryAddresses = {};
  }
  db.siteSettings.treasuryAddresses[net] = targetAddr;
  db.siteSettings.polygonAddress = targetAddr;
  db.siteSettings.treasuryAddress = targetAddr;

  saveDB(db);
  await saveDBAsync(db);

  res.json({ ok: true, success: true, settings: db.siteSettings.treasuryAddresses });
});

app.delete("/api/admin/treasury-settings/:network", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const net = (req.params.network || "POLYGON").toUpperCase();
  if (db.siteSettings.treasuryAddresses && db.siteSettings.treasuryAddresses[net]) {
    delete db.siteSettings.treasuryAddresses[net];
    saveDB(db);
    await saveDBAsync(db);
  }
  res.json({ ok: true });
});

app.get("/api/admin/treasury-addresses", async (req, res) => {
  await ensureHydrated();
  const polyAddr = getTreasuryAddress("POLYGON");
  res.json({
    addresses: [
      { network: "POLYGON", address: polyAddr, label: "Polygon Hot Wallet" }
    ],
    networks: {
      POLYGON: {
        sweepDest: {
          address: polyAddr,
          usdt: "250000.00",
          native: "150.5",
          nativeUnit: "POL"
        },
        hotWallet: {
          address: polyAddr,
          usdt: "50000.00",
          native: "25.0",
          nativeUnit: "POL"
        },
        gasDispenser: {
          address: polyAddr,
          usdt: "0.00",
          native: "100.0",
          nativeUnit: "POL"
        },
        coldWallet: {
          address: "0xColdWalletPolygonAddress00000000000000000",
          usdt: "1000000.00",
          native: "0.0",
          nativeUnit: "POL"
        }
      }
    }
  });
});

app.get("/api/admin/hot-wallet/status", async (req, res) => {
  await ensureHydrated();
  const polyAddr = getTreasuryAddress("POLYGON");
  res.json({
    fetchedAt: new Date().toISOString(),
    summary: {
      totalUsdt: 50000.00,
      networksReady: ["POLYGON"],
      networksNeedFunding: []
    },
    networks: [
      {
        network: "POLYGON",
        address: polyAddr,
        balance: 50000.00,
        balanceUsdt: 50000.00,
        status: "ready",
        needsFunding: false,
        minThreshold: 1000
      }
    ]
  });
});

app.get("/api/admin/wallet-movements/hot-wallet", (req, res) => {
  res.json({ rows: [] });
});

// --- Honor Points & Referral Config ---
app.get("/api/admin/honor-points", (req, res) => {
  const db = loadDB();
  res.json({
    users: db.users.map(u => ({
      id: u.id,
      username: u.username,
      honorPoints: 100,
      status: u.status
    }))
  });
});

app.put("/api/admin/honor-points/:id", (req, res) => {
  res.json({ ok: true, success: true });
});

app.get("/api/admin/referral-commission-config", (req, res) => {
  res.json({
    ok: true,
    config: [
      { level: 1, rate: 0.10 },
      { level: 2, rate: 0.05 },
      { level: 3, rate: 0.02 }
    ]
  });
});

app.put("/api/admin/referral-commission-config", (req, res) => {
  res.json({
    ok: true,
    config: req.body?.rates || []
  });
});

// --- Wallet Change Requests ---
app.get("/api/admin/wallet-change-requests", (req, res) => {
  res.json({ requests: [], total: 0 });
});

app.post("/api/admin/wallet-change-requests/:id/approve", (req, res) => {
  res.json({ ok: true });
});

app.post("/api/admin/wallet-change-requests/:id/reject", (req, res) => {
  res.json({ ok: true });
});

// --- Planning & Logs ---
app.get("/api/admin/withdrawals/planning", (req, res) => {
  res.json({
    ok: true,
    days: [],
    batches: [],
    totalDays: 0,
    totalUsdt: 0
  });
});

app.get("/api/admin/withdrawal-logs", (req, res) => {
  res.json({ ok: true, logs: [] });
});

app.post("/api/admin/notifications/send", (req, res) => {
  res.json({ ok: true, sent: 1 });
});

app.get("/api/admin/chat/conversations", (req, res) => {
  res.json([]);
});

app.post("/api/admin/chat/conversations", (req, res) => {
  res.json({
    ok: true,
    conversation: {
      id: "c_" + Date.now(),
      title: req.body?.title || "مجموعة عامة",
      type: "group",
      unreadCount: 0,
      createdAt: new Date().toISOString()
    }
  });
});

app.get("/api/admin/chat/dm", (req, res) => {
  res.json([]);
});

app.get("/api/admin/chat/group-templates", (req, res) => {
  res.json([]);
});

app.get("/api/admin/chat/logs", (req, res) => {
  res.json([]);
});

app.post("/api/admin/chat/upload-avatar", (req, res) => {
  res.json({ ok: true, url: "/default-avatar.png" });
});

app.post("/api/admin/leaders/run-payout", (req, res) => {
  res.json({ ok: true });
});

app.post("/api/admin/leaders/:id", (req, res) => {
  res.json({ ok: true });
});

app.post("/api/admin/rpc-monitor/test", (req, res) => {
  res.json({ ok: true, latency: 38 });
});

app.post("/api/admin/rpc-monitor/reload", (req, res) => {
  res.json({ ok: true });
});

async function handleAdminChangePassword(req: express.Request, res: express.Response) {
  await ensureHydrated();
  const db = loadDB();
  const { currentPassword, oldPassword, newPassword } = req.body || {};
  const current = (currentPassword || oldPassword || "").toString();
  const next = (newPassword || "").toString();

  if (!next || next.length < 8) {
    return res.status(400).json({ error: "كلمة المرور الجديدة يجب أن تكون 8 أحرف على الأقل" });
  }
  const adminAuth = db.siteSettings.adminAuth;
  if (!adminAuth || !verifyPassword(current, adminAuth.passwordHash)) {
    return res.status(401).json({ error: "كلمة المرور الحالية غير صحيحة" });
  }
  db.siteSettings.adminAuth = { ...adminAuth, passwordHash: hashPassword(next) };
  saveDB(db);
  res.json({ ok: true, success: true, message: "تم تغيير كلمة المرور بنجاح" });
}

app.put("/api/admin/auth/change-password", handleAdminChangePassword);
app.post("/api/admin/auth/change-password", handleAdminChangePassword);

// Note: this is a single-admin system with no email provider wired up, so
// a real "email me a reset link" flow isn't possible yet. This intentionally
// refuses rather than pretending to send an email, and tells the operator
// how to actually reset it (env var), which is the truthful option available.
app.post("/api/admin/auth/forgot-password", (req, res) => {
  res.status(501).json({
    error: "إعادة تعيين كلمة المرور عبر البريد غير مفعّلة بعد. لإعادة التعيين، " +
      "شغّل السيرفر مع متغيرات البيئة ADMIN_USERNAME و ADMIN_PASSWORD الجديدة " +
      "بعد حذف حقل adminAuth من data.json."
  });
});

app.post("/api/admin/membership-plans/sync", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  db.membershipPlans = [...DEFAULT_MEMBERSHIP_PLANS];
  saveDB(db);
  await saveDBAsync(db);
  res.json({ ok: true, success: true, message: "تمت مزامنة الباقات بنجاح ✓" });
});

app.post("/api/admin/membership-plans/:id", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  if (!db.membershipPlans) db.membershipPlans = [...DEFAULT_MEMBERSHIP_PLANS];

  let plan = db.membershipPlans.find(p => p.id === req.params.id);
  if (!plan) {
    plan = {
      id: req.params.id,
      tier: req.body?.tier || "vip1",
      name: req.body?.name || "باقة جديدة",
      price: parseFloat(req.body?.price || "50"),
      dailyTaskLimit: parseInt(req.body?.dailyTaskLimit || "10", 10),
      incomeRate: parseFloat(req.body?.incomeRate || "1.5"),
      durationDays: parseInt(req.body?.durationDays || "30", 10),
      isPopular: Boolean(req.body?.isPopular)
    };
    db.membershipPlans.push(plan);
  } else {
    if (req.body?.name !== undefined) plan.name = req.body.name;
    if (req.body?.price !== undefined) plan.price = parseFloat(req.body.price);
    if (req.body?.dailyTaskLimit !== undefined) plan.dailyTaskLimit = parseInt(req.body.dailyTaskLimit, 10);
    if (req.body?.incomeRate !== undefined) plan.incomeRate = parseFloat(req.body.incomeRate);
    if (req.body?.durationDays !== undefined) plan.durationDays = parseInt(req.body.durationDays, 10);
    if (req.body?.isPopular !== undefined) plan.isPopular = Boolean(req.body.isPopular);
    if (req.body?.tier !== undefined) plan.tier = req.body.tier;
  }

  saveDB(db);
  await saveDBAsync(db);
  res.json({ ok: true, success: true, plan });
});

app.put("/api/admin/membership-plans/:id", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  if (!db.membershipPlans) db.membershipPlans = [...DEFAULT_MEMBERSHIP_PLANS];

  let plan = db.membershipPlans.find(p => p.id === req.params.id);
  if (!plan) {
    plan = {
      id: req.params.id,
      tier: req.body?.tier || "vip1",
      name: req.body?.name || "باقة جديدة",
      price: parseFloat(req.body?.price || "50"),
      dailyTaskLimit: parseInt(req.body?.dailyTaskLimit || "10", 10),
      incomeRate: parseFloat(req.body?.incomeRate || "1.5"),
      durationDays: parseInt(req.body?.durationDays || "30", 10),
      isPopular: Boolean(req.body?.isPopular)
    };
    db.membershipPlans.push(plan);
  } else {
    if (req.body?.name !== undefined) plan.name = req.body.name;
    if (req.body?.price !== undefined) plan.price = parseFloat(req.body.price);
    if (req.body?.dailyTaskLimit !== undefined) plan.dailyTaskLimit = parseInt(req.body.dailyTaskLimit, 10);
    if (req.body?.incomeRate !== undefined) plan.incomeRate = parseFloat(req.body.incomeRate);
    if (req.body?.durationDays !== undefined) plan.durationDays = parseInt(req.body.durationDays, 10);
    if (req.body?.isPopular !== undefined) plan.isPopular = Boolean(req.body.isPopular);
    if (req.body?.tier !== undefined) plan.tier = req.body.tier;
  }

  saveDB(db);
  await saveDBAsync(db);
  res.json({ ok: true, success: true, plan });
});

app.put("/api/admin/site-settings/emergency_withdrawal_mode", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  if (req.body?.value !== undefined) {
    db.siteSettings.emergencyWithdrawalMode = req.body.value === "1" || req.body.value === true;
  } else {
    db.siteSettings.emergencyWithdrawalMode = !db.siteSettings.emergencyWithdrawalMode;
  }
  saveDB(db);
  await saveDBAsync(db);
  res.json({ ok: true, success: true, emergencyWithdrawalMode: db.siteSettings.emergencyWithdrawalMode });
});

app.post("/api/admin/site-settings/emergency_withdrawal_mode", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  if (req.body?.value !== undefined) {
    db.siteSettings.emergencyWithdrawalMode = req.body.value === "1" || req.body.value === true;
  } else {
    db.siteSettings.emergencyWithdrawalMode = !db.siteSettings.emergencyWithdrawalMode;
  }
  saveDB(db);
  await saveDBAsync(db);
  res.json({ ok: true, success: true, emergencyWithdrawalMode: db.siteSettings.emergencyWithdrawalMode });
});

// --- Admin Site & Finance Settings ---
app.get("/api/admin/site-settings", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const settingsArray = [
    { key: "min_deposit_amount", value: String(db.siteSettings.min_deposit_amount ?? 5) },
    { key: "min_withdrawal_amount", value: String(db.siteSettings.min_withdrawal_amount ?? 3) },
    { key: "withdrawal_fee", value: String(db.siteSettings.withdrawal_fee ?? 21) },
    { key: "max_withdrawal_amount", value: String(db.siteSettings.max_withdrawal_amount ?? 5000) },
    { key: "emergency_withdrawal_mode", value: db.siteSettings.emergencyWithdrawalMode ? "1" : "0" },
    { key: "telegram_support_username", value: String(db.siteSettings.telegramSupportUsername ?? "TeroComunityBot") },
    { key: "site_name", value: String(db.siteSettings.siteName ?? "TERO Network") },
    { key: "maintenance_mode", value: db.siteSettings.maintenanceMode ? "1" : "0" }
  ];

  Object.keys(db.siteSettings).forEach(k => {
    if (!settingsArray.some(s => s.key === k) && typeof db.siteSettings[k] !== 'object') {
      settingsArray.push({ key: k, value: String(db.siteSettings[k]) });
    }
  });

  // NOTE: db.siteSettings.adminAuth (username + password hash) must never
  // be sent to the client, even authenticated admin — stripped below.
  const { adminAuth: _adminAuth, ...publicSettings } = db.siteSettings;
  res.json({
    ...publicSettings,
    settings: settingsArray,
    ok: true
  });
});

app.put("/api/admin/site-settings/:key", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const key = req.params.key;
  const val = req.body?.value ?? req.body?.val;

  // adminAuth can only change via /api/admin/auth/change-password, never
  // through this generic key/value settings endpoint.
  if (key === "adminAuth") {
    return res.status(403).json({ error: "Forbidden" });
  }

  if (key === "emergency_withdrawal_mode") {
    db.siteSettings.emergencyWithdrawalMode = val === "1" || val === true;
  } else if (key === "maintenance_mode") {
    db.siteSettings.maintenanceMode = val === "1" || val === true;
  } else {
    db.siteSettings[key] = val;
  }

  saveDB(db);
  await saveDBAsync(db);

  res.json({ ok: true, success: true, key, value: val });
});

app.post("/api/admin/site-settings", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  // Same reasoning: block adminAuth from being overwritten through a bulk
  // settings update — this used to spread the entire request body
  // straight into siteSettings, so a stray {adminAuth: {...}} in the
  // payload (buggy client or malicious request) could silently replace
  // the admin password hash.
  const { adminAuth: _ignoredAdminAuth, ...incomingSettings } = req.body || {};
  db.siteSettings = { ...db.siteSettings, ...incomingSettings };
  saveDB(db);
  await saveDBAsync(db);
  const { adminAuth: _adminAuth2, ...publicSettings2 } = db.siteSettings;
  res.json({ success: true, ok: true, siteSettings: publicSettings2 });
});

app.get("/api/networks/status", (req, res) => {
  res.json({
    polygon: true
  });
});

app.get("/api/finance-settings", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  res.json({
    min_deposit_amount: db.siteSettings.min_deposit_amount ?? 5,
    min_withdrawal_amount: db.siteSettings.min_withdrawal_amount ?? 3,
    withdrawal_fee: db.siteSettings.withdrawal_fee ?? 21,
    max_withdrawal_amount: db.siteSettings.max_withdrawal_amount ?? 5000,
    emergencyWithdrawalMode: Boolean(db.siteSettings.emergencyWithdrawalMode)
  });
});

app.get("/api/maintenance-status", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  res.json({ enabled: Boolean(db.siteSettings.maintenanceMode) });
});

app.get("/api/admin/maintenance", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  res.json({ enabled: Boolean(db.siteSettings.maintenanceMode), ok: true });
});

app.post("/api/admin/maintenance", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  db.siteSettings.maintenanceMode = Boolean(req.body?.enabled ?? req.body?.value ?? req.body?.maintenanceMode);
  saveDB(db);
  await saveDBAsync(db);
  res.json({ enabled: Boolean(db.siteSettings.maintenanceMode), ok: true });
});

app.get("/api/admin/wallet-change-requests/stats", (req, res) => {
  res.json({ pending: 0 });
});

app.get("/api/admin/sweep-manager/stats", (req, res) => {
  res.json({
    completed: { count: 0, totalUsdt: 0 },
    failed: { count: 0, totalUsdt: 0 },
    inFlight: { count: 0, totalUsdt: 0 },
    pending: { count: 0, totalUsdt: 0 }
  });
});

app.get("/api/admin/sweep-manager/readiness", (req, res) => {
  res.json({
    isReady: true,
    gasWallet: {
      polBalance: 15.5,
      sufficient: true,
      requiredGasPol: 0.0,
      addressesNeedingGas: 0,
      deficitPol: 0.0
    }
  });
});

app.get("/api/admin/sweep-manager/history", (req, res) => {
  res.json([]);
});

app.get("/api/admin/membership-plans", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const plans = db.membershipPlans || DEFAULT_MEMBERSHIP_PLANS;
  res.json({
    ok: true,
    plans
  });
});

app.get("/api/admin/membership-plans/distribution", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const totalActive = db.users.length;
  const plans = db.membershipPlans || DEFAULT_MEMBERSHIP_PLANS;
  const planDist = plans.map(p => ({
    id: p.id,
    tier: p.tier,
    name: p.name,
    price: p.price,
    subscriberCount: db.users.filter(u => u.membershipTier === p.tier || (!u.membershipTier && p.tier === "free")).length
  }));

  res.json({
    ok: true,
    totalActive,
    plans: planDist
  });
});

app.get("/api/admin/leaders", (req, res) => {
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
    walletAddress: "0x113494B3aB9369CF9C66dE27255c948EF1266517"
  }));
  res.json({ leaders: leaderList });
});

app.get("/api/admin/rpc-monitor", (req, res) => {
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
      slots: [
        { name: "Alchemy Primary", url: "https://polygon-mainnet.g.alchemy.com/...", status: "active", latency: 38 },
        { name: "Infura Backup", url: "https://polygon-mainnet.infura.io/...", status: "standby", latency: 52 },
        { name: "QuickNode Fallback", url: "https://polygon.quiknode.pro/...", status: "standby", latency: 49 }
      ]
    }
  });
});

// Admin User Specific Sub-routes
app.get("/api/admin/users/:id/profile", (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  const { passwordHash, ...safeUser } = user;
  res.json(safeUser);
});

app.get("/api/admin/users/:id/deposit-addresses", (req, res) => {
  res.json({
    addresses: [
      {
        network: "POLYGON",
        address: "0x113494B3aB9369CF9C66dE27255c948EF1266517",
        sequence: 1,
        status: "active",
        createdAt: new Date().toISOString()
      }
    ],
    recentDeposits: [],
    lastSweep: null,
    activeCount: 1,
    usedCount: 0,
    legacyCount: 0
  });
});

app.post("/api/admin/users/:id/rotate-deposit-address", (req, res) => {
  res.json({ ok: true, newSeq: 2, address: "0x113494B3aB9369CF9C66dE27255c948EF1266517" });
});

app.get("/api/admin/users/:id/deposits", (req, res) => {
  const db = loadDB();
  // Fixed: this used to also always include a hardcoded "asse_24" user's
  // deposits on every lookup regardless of which :id was requested.
  const list = db.deposits.filter(d => d.userId === req.params.id);
  res.json({ transactions: list, total: list.length });
});

app.get("/api/admin/users/:id/withdrawals", (req, res) => {
  const db = loadDB();
  const list = db.withdrawals.filter(w => w.userId === req.params.id);
  res.json({ transactions: list, total: list.length });
});

// SECURITY: this token used to be hardcoded in source
// ("8701414109:AAEDizxf0LQsX9sB519-WOnYxnm8jb3OJN4") — a live secret
// committed to the repo lets anyone control the bot (send messages,
// read updates) as this app. It's now required from the environment;
// the Telegram integration simply stays off without it. Treat that old
// token as compromised and rotate it via @BotFather regardless.
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";
const TELEGRAM_BOT_USERNAME = process.env.TELEGRAM_BOT_USERNAME || "TeroComunityBot";
if (!TELEGRAM_BOT_TOKEN) {
  console.warn("[telegram] TELEGRAM_BOT_TOKEN not set — Telegram bot integration is disabled.");
}

// Telegram Bot Service for Auto-linking Accounts (@TeroComunityBot)
async function processTelegramMessage(msg: any) {
  if (!TELEGRAM_BOT_TOKEN) return;
  if (!msg || !msg.text) return;
  await ensureHydrated();
  const text = msg.text.trim();
  const chatId = msg.chat.id;
  const sender = msg.from;
  const tgUsername = sender?.username ? `@${sender.username}` : (sender?.first_name || "Telegram User");
  
  if (text.startsWith("/start")) {
    const parts = text.split(" ");
    const param = parts[1] || "";
    
    if (param) {
      const db = loadDB();
      let matchedUser: User | undefined;
      
      // Format 1: link_userId or token_userId
      if (param.startsWith("link_") || param.startsWith("token_")) {
        const targetId = param.replace("link_", "").replace("token_", "");
        matchedUser = db.users.find(u => u.id === targetId || u.username === targetId);
      } else {
        matchedUser = db.users.find(u => u.id === param || u.username === param);
      }
      
      // No more falling back to db.users[0] — that used to link a random
      // stranger's Telegram account to whichever user happened to be
      // first in the database if the deep-link parameter didn't match
      // anyone.
      if (matchedUser) {
        matchedUser.telegram = tgUsername;
        await saveUserDirect(matchedUser);
        await saveDBAsync(db);
        
        // Reply to user on Telegram
        await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            chat_id: chatId,
            text: `✅ تم ربط حسابك في منصة TERO بنجاح!\n👤 المستخدم: ${matchedUser.username}\n📲 تيليجرام: ${tgUsername}\n\nيمكنك الآن العودة إلى الموقع وإكمال مهامك وسحوباتك بكل سهولة.`,
            parse_mode: "HTML"
          })
        }).catch(() => {});
        return;
      }
    }
    
    // Default greeting if no token
    await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        text: `مرحباً بك في بوت منصة TERO الرسمي 🌟 (@TeroComunityBot)\n\nيرجى الدخول إلى المنصة والضغط على زر "ربط Telegram" لاستكمال إعداد حسابك تلقائياً.`,
        parse_mode: "HTML"
      })
    }).catch(() => {});
  }
}

let telegramLastUpdateId = 0;
async function pollTelegramBot() {
  if (!TELEGRAM_BOT_TOKEN) return;
  try {
    const res = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates?offset=${telegramLastUpdateId + 1}&timeout=5`);
    if (!res.ok) return;
    const data = await res.json();
    if (data.ok && Array.isArray(data.result)) {
      for (const update of data.result) {
        telegramLastUpdateId = update.update_id;
        if (update.message) {
          await processTelegramMessage(update.message);
        }
      }
    }
  } catch (e) {
    // Silent catch for network resilience
  }
}

// Start bot polling loop for non-serverless dev
if (!process.env.VERCEL) {
  setInterval(pollTelegramBot, 3000);
  pollTelegramBot();
}

// Webhook endpoint for Telegram updates on cloud/Vercel
app.post("/api/telegram-webhook", async (req, res) => {
  try {
    const update = req.body;
    if (update && update.message) {
      await processTelegramMessage(update.message);
    }
    res.json({ ok: true });
  } catch (err: any) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/site-settings/public/telegram_support_username", (req, res) => {
  const db = loadDB();
  res.json({ telegramSupportUsername: TELEGRAM_BOT_USERNAME || db.siteSettings.telegramSupportUsername || "TeroComunityBot" });
});

// --- User-Facing API Routes ---
app.post("/api/auth/register", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const { phone, referralCode, password, email, username } = req.body || {};

  const cleanPhone = (phone || "").toString().trim();
  const cleanEmail = (email || "").toString().trim().toLowerCase();
  const cleanUsername = (username || cleanPhone || (cleanEmail ? cleanEmail.split("@")[0] : "") || ("user_" + Math.floor(100000 + Math.random() * 900000))).toString().trim();
  const cleanPassword = (password || "").toString();

  if (!cleanPassword || cleanPassword.length < 6) {
    return res.status(400).json({ error: "كلمة المرور يجب أن تكون 6 أحرف على الأقل" });
  }

  const existing = db.users.find(u =>
    (cleanPhone && u.username === cleanPhone) ||
    (cleanEmail && u.email === cleanEmail) ||
    (cleanUsername && u.username === cleanUsername)
  );
  if (existing) {
    return res.status(409).json({ error: "الحساب موجود مسبقًا، يرجى تسجيل الدخول" });
  }

  const user: User = {
    id: "u_" + Date.now() + "_" + Math.floor(Math.random() * 1000),
    username: cleanUsername,
    email: cleanEmail || (cleanPhone ? `${cleanPhone}@tero.com` : `${cleanUsername}@tero.com`),
    passwordHash: hashPassword(cleanPassword),
    telegram: "",
    balance: 0.00,
    usdtBalance: 0.00,
    status: "active",
    isFrozen: false,
    joinedAt: new Date().toISOString(),
    membershipPlan: "none",
    referralsCount: 0,
    membershipTier: "free",
    referralCode: "TQ" + Math.floor(10000 + Math.random() * 90000)
  };
  // referralCode in the request body is the code the NEW user was referred
  // BY, not their own code — credit the referrer instead of overwriting it.
  if (referralCode) {
    const referrer = db.users.find(u => u.referralCode === referralCode);
    if (referrer) referrer.referralsCount = (referrer.referralsCount || 0) + 1;
  }
  db.users.unshift(user);
  await saveUserDirect(user);
  await saveDBAsync(db);

  const token = signToken({ sub: user.id, role: "user" });
  const { passwordHash, ...safeUser } = user;
  res.json({ token, user: safeUser });
});

app.post("/api/auth/login", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const { username, identifier, email, phone, password } = req.body || {};
  const uname = (username || identifier || email || phone || "").toString().trim();
  const pass = (password || "").toString();

  if (!uname || !pass) {
    return res.status(400).json({ error: "الرجاء إدخال اسم المستخدم وكلمة المرور" });
  }

  const user = db.users.find(u =>
    u.username.toLowerCase() === uname.toLowerCase() || u.email.toLowerCase() === uname.toLowerCase()
  );

  // Accounts created before this fix (or seeded via data.json) may have no
  // passwordHash yet — they can no longer log in silently as before; an
  // admin needs to set a password for them via the admin panel.
  if (!user || !verifyPassword(pass, user.passwordHash)) {
    return res.status(401).json({ error: "بيانات الدخول غير صحيحة" });
  }

  const token = signToken({ sub: user.id, role: "user" });
  const { passwordHash, ...safeUser } = user;
  res.json({ token, user: safeUser });
});

app.get("/api/auth/me", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const user = getAuthenticatedUser(req, db);
  if (!user) return res.status(401).json({ error: "Unauthorized" });

  const isLinked = Boolean(user.telegram && user.telegram.trim() !== "");
  const { passwordHash, ...safeUser } = user;
  res.json({ ...safeUser, requiresTelegramLink: !isLinked });
});

app.get("/api/user/profile", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const user = getAuthenticatedUser(req, db);
  if (!user) return res.status(401).json({ error: "Unauthorized" });

  const { passwordHash, ...safeUser } = user;
  res.json({
    ...safeUser,
    referralCode: user.referralCode || "TQ69JZ",
    leaderRank: 0,
    leaderPoints: 0,
    weeklySalary: 0,
    nextPayoutDate: null
  });
});

app.get("/api/user/telegram/status", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const user = getAuthenticatedUser(req, db);
  if (!user) return res.status(401).json({ error: "Unauthorized" });
  const isLinked = Boolean(user.telegram && user.telegram.trim() !== "");
  res.json({ linked: isLinked, telegramUsername: user.telegram || null });
});

app.post("/api/user/telegram/link-token", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const user = getAuthenticatedUser(req, db);
  if (!user) return res.status(401).json({ error: "Unauthorized" });

  const rawBotName = TELEGRAM_BOT_USERNAME || db.siteSettings.telegramSupportUsername || "TeroComunityBot";
  const cleanBotName = rawBotName.replace(/^@/, "");

  res.json({
    botUsername: cleanBotName,
    deepLink: `https://t.me/${cleanBotName}?start=link_${user.id}`,
    token: `token_${user.id}`
  });
});

// Manual or direct verification endpoint from external bots or webhooks
app.post("/api/user/telegram/verify-link", async (req, res) => {
  await ensureHydrated();
  const { token, telegramUsername, userId } = req.body || {};
  const db = loadDB();
  
  let targetId = userId;
  if (token) {
    targetId = token.replace("link_", "").replace("token_", "");
  }
  
  // No fallback to db.users[0] here anymore — that used to silently link
  // Telegram accounts to whichever user happened to be first in the list
  // whenever the token/userId didn't match anyone.
  const user = db.users.find(u => u.id === targetId || u.username === targetId);

  if (user) {
    user.telegram = telegramUsername || "@user_tg";
    await saveUserDirect(user);
    await saveDBAsync(db);
    return res.json({ ok: true, success: true, user });
  }
  
  res.status(404).json({ error: "User not found" });
});

app.post("/api/user/telegram/request-invite", (req, res) => {
  res.json({
    ok: true,
    inviteLink: "https://t.me/tero_network_group"
  });
});

app.get("/api/wallet/balance", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const user = getAuthenticatedUser(req, db);
  if (!user) return res.status(401).json({ error: "Unauthorized" });
  res.json({
    balance: (user.balance ?? 0.00).toFixed(2),
    available: (user.balance ?? 0.00).toFixed(2),
    currency: "USDT"
  });
});

app.get("/api/wallet/deposit-address", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const user = getAuthenticatedUser(req, db);
  if (!user) return res.status(401).json({ error: "Unauthorized" });
  // NOTE: every user shares the same site-wide treasury deposit address.
  // Because it's shared, a deposit can't be tied to a user just by address
  // — /api/wallet/deposit below requires the user to submit their tx hash
  // so it can be recorded (and, if RPC verification is configured,
  // checked) against their account specifically.
  const depositAddr = getTreasuryAddress("POLYGON");
  res.json({
    polygon: depositAddr,
    address: depositAddr,
    network: "POLYGON"
  });
});

// Was missing entirely — the UI has a deposit flow but nothing recorded a
// user's deposit submission anywhere before an admin could see or approve
// it. This creates the pending deposit, and — if POLYGON_RPC_URL is set —
// verifies on-chain that the tx really is a USDT transfer to the treasury
// address for at least the claimed amount before flagging it for review.
app.post("/api/wallet/deposit", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const user = getAuthenticatedUser(req, db);
  if (!user) return res.status(401).json({ error: "Unauthorized" });

  const { amount, txHash, network } = req.body || {};
  const amt = (amount || "").toString().trim();
  const hash = (txHash || "").toString().trim();
  const net = (network || "POLYGON").toString().toUpperCase();
  const minDeposit = parseFloat(db.siteSettings.min_deposit_amount || "10");

  if (!hash || !/^0x[a-fA-F0-9]{64}$/.test(hash)) {
    return res.status(400).json({ error: "رقم المعاملة (txHash) غير صالح" });
  }
  if (!amt || isNaN(parseFloat(amt)) || parseFloat(amt) < minDeposit) {
    return res.status(400).json({ error: `الحد الأدنى للإيداع هو ${minDeposit} USDT` });
  }
  if (db.deposits.some(d => d.txHash.toLowerCase() === hash.toLowerCase())) {
    return res.status(409).json({ error: "تم استخدام هذه المعاملة من قبل" });
  }

  const deposit: Deposit = {
    id: "dep_" + Date.now(),
    userId: user.id,
    username: user.username,
    amount: amt,
    network: net,
    status: "pending",
    txHash: hash,
    createdAt: new Date().toISOString()
  };

  if (net === "POLYGON" && process.env.POLYGON_RPC_URL) {
    try {
      const verification = await verifyPolygonUsdtDeposit(hash, getTreasuryAddress("POLYGON"), parseFloat(amt));
      if (verification.ok) {
        deposit.status = "confirmed";
      } else {
        console.warn(`[deposit] on-chain verification failed for ${hash}: ${verification.reason}`);
      }
    } catch (err) {
      console.error("[deposit] on-chain verification error:", err);
    }
  }

  db.deposits.unshift(deposit);
  if (deposit.status === "confirmed") {
    user.balance += parseFloat(amt);
    user.usdtBalance += parseFloat(amt);
  }
  saveDB(db);
  await saveUserDirect(user);

  res.json({ success: true, deposit });
});

app.post("/api/wallet/withdraw", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const user = getAuthenticatedUser(req, db);
  if (!user) return res.status(401).json({ error: "Unauthorized" });

  const { amount, address, network } = req.body || {};
  const amt = parseFloat(amount || "0");
  const minWithdraw = parseFloat(db.siteSettings.min_withdrawal_amount ?? 3);
  const maxWithdraw = parseFloat(db.siteSettings.max_withdrawal_amount ?? 5000);

  if (!address || !amt || amt <= 0) {
    return res.status(400).json({ error: "بيانات السحب غير مكتملة" });
  }
  if (amt < minWithdraw || amt > maxWithdraw) {
    return res.status(400).json({ error: `مبلغ السحب يجب أن يكون بين ${minWithdraw} و ${maxWithdraw} USDT` });
  }
  if (user.isFrozen || user.status !== "active") {
    return res.status(403).json({ error: "الحساب غير مؤهل للسحب حاليًا" });
  }
  if (user.balance < amt) {
    return res.status(400).json({ error: "الرصيد غير كافٍ" });
  }

  user.balance -= amt;
  user.usdtBalance -= amt;

  const newWithdrawal: Withdrawal = {
    id: "wd_" + Date.now(),
    userId: user.id,
    username: user.username,
    amount: amt,
    usdtAmount: amt,
    address,
    network: network || "POLYGON",
    status: "pending_approval",
    createdAt: new Date().toISOString()
  };

  db.withdrawals.unshift(newWithdrawal);
  saveDB(db);
  await saveUserDirect(user);

  res.json({ success: true, withdrawal: newWithdrawal });
});

app.get("/api/transactions", (req, res) => {
  res.json({ items: [], total: 0 });
});

app.get("/api/membership", (req, res) => {
  res.json({ tier: null, plan: "none", dailyLimit: 0, remainingTasks: 0 });
});

app.get("/api/membership/plans", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const plans = db.membershipPlans || DEFAULT_MEMBERSHIP_PLANS;
  res.json(plans);
});

app.post("/api/tasks/validate-access-code", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const submitted = (req.body?.code || req.body?.accessCode || "").toString().trim().toUpperCase();

  // Fixed: previously "TERO1234" and "TERO2026" always worked no matter
  // what code was actually configured, defeating the point of rotating
  // codes. Now only codes present in taskAccessCodes are checked, and
  // each one is required to still be within its validHours window.
  const now = Date.now();
  const activeCodes = (db.taskAccessCodes || []).filter(c => {
    if ((c.status || "running") !== "running") return false;
    if (!c.validHours) return true;
    const createdAt = new Date(c.createdAt).getTime();
    return now - createdAt <= c.validHours * 60 * 60 * 1000;
  }).map(c => c.code.toUpperCase());

  const isValid = Boolean(submitted) && activeCodes.includes(submitted);

  if (isValid) {
    return res.json({ ok: true, success: true, valid: true });
  }

  res.status(400).json({ error: "رمز الوصول للمهام اليومية غير صحيح، يرجى كتابة الرمز الصحيح والتأكد منه." });
});

app.get("/api/tasks", (req, res) => {
  const db = loadDB();
  res.json(db.tasks);
});

app.get("/api/tasks/summary", (req, res) => {
  res.json({
    todayEarned: 0,
    totalRevenue: 0,
    remainingDays: 0
  });
});

app.get("/api/tasks/streak", (req, res) => {
  res.json({
    currentStreak: 0,
    maxStreak: 0
  });
});

app.get("/api/referrals", (req, res) => {
  res.json([]);
});

app.get("/api/referrals/stats", async (req, res) => {
  await ensureHydrated();
  const db = loadDB();
  const user = getAuthenticatedUser(req, db);
  if (!user) return res.status(401).json({ error: "Unauthorized" });
  res.json({
    totalEarned: 0.00,
    totalReferrals: user.referralsCount || 0,
    referralCode: user.referralCode || "TQ69JZ"
  });
});

app.get("/api/referrals/salary-history", (req, res) => {
  res.json({
    totalReceived: 0,
    lastAmount: 0,
    payments: []
  });
});

app.get("/api/notifications", (req, res) => {
  res.json([]);
});

// API Error-handling middleware
app.use("/api/*", (err: any, req: any, res: any, next: any) => {
  console.error("API Error:", err);
  res.status(500).json({ ok: false, error: err.message || "Internal server error" });
});

// Generic Fallback Catch-All
app.all("/api/*", (req, res) => {
  if (req.method === "GET") {
    if (req.path.endsWith("s") || req.path.endsWith("s/")) {
      return res.json([]);
    }
    return res.json({});
  }
  res.json({ success: true, ok: true });
});

// SPA fallback for client-side routing (e.g. /tero-hq)
app.get("*", (req, res) => {
  res.sendFile(path.join(process.cwd(), "index.html"));
});

if (!process.env.VERCEL && process.env.NODE_ENV !== "test") {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`TERO app dev server listening on http://0.0.0.0:${PORT}`);
  });
}

export default app;
export { app };

