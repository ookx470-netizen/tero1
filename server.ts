import express from "express";
import path from "path";
import fs from "fs";
import { initializeApp } from "firebase/app";
import {
  initializeFirestore,
  getFirestore,
  collection,
  doc,
  getDocs,
  getDoc,
  setDoc,
  deleteDoc,
  Firestore
} from "firebase/firestore";

const app = express();
const PORT = 3000;

app.use(express.json());

// Resolve directory
const currentDir = typeof __dirname !== "undefined" ? __dirname : process.cwd();
const distDir = path.join(process.cwd(), "dist");

// Serve static assets
app.use(express.static(process.cwd()));
app.use(express.static(distDir));
app.use(express.static(currentDir));

// --- Firebase Cloud Firestore Initialization ---
let firestoreDb: Firestore | null = null;
try {
  const configPath = path.join(process.cwd(), "firebase-applet-config.json");
  if (fs.existsSync(configPath)) {
    const firebaseConfig = JSON.parse(fs.readFileSync(configPath, "utf-8"));
    const firebaseApp = initializeApp(firebaseConfig);
    firestoreDb = firebaseConfig.firestoreDatabaseId
      ? initializeFirestore(firebaseApp, {}, firebaseConfig.firestoreDatabaseId)
      : getFirestore(firebaseApp);
    console.log("Firebase Firestore initialized successfully with database:", firebaseConfig.firestoreDatabaseId || "default");
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
    emergencyWithdrawalMode: false
  }
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

// Async Hydrate from Cloud Firestore
async function hydrateFromFirestore() {
  if (!firestoreDb) return;
  try {
    console.log("Hydrating data from Firebase Firestore...");
    // 1. Users
    const usersSnap = await getDocs(collection(firestoreDb, "users"));
    if (!usersSnap.empty) {
      inMemoryDB.users = usersSnap.docs.map(d => d.data() as User);
    }

    // 2. Deposits
    const depositsSnap = await getDocs(collection(firestoreDb, "deposits"));
    if (!depositsSnap.empty) {
      inMemoryDB.deposits = depositsSnap.docs.map(d => d.data() as Deposit);
    }

    // 3. Withdrawals
    const withdrawalsSnap = await getDocs(collection(firestoreDb, "withdrawals"));
    if (!withdrawalsSnap.empty) {
      inMemoryDB.withdrawals = withdrawalsSnap.docs.map(d => d.data() as Withdrawal);
    }

    // 4. Tasks
    const tasksSnap = await getDocs(collection(firestoreDb, "tasks"));
    if (!tasksSnap.empty) {
      inMemoryDB.tasks = tasksSnap.docs.map(d => d.data() as Task);
    }

    // 5. Site Settings
    const settingsSnap = await getDoc(doc(firestoreDb, "siteSettings", "global"));
    if (settingsSnap.exists()) {
      inMemoryDB.siteSettings = { ...inMemoryDB.siteSettings, ...settingsSnap.data() };
    } else {
      // Seed initial settings to Firestore
      await setDoc(doc(firestoreDb, "siteSettings", "global"), inMemoryDB.siteSettings);
    }

    // Backup to local file
    fs.writeFileSync(DATA_FILE, JSON.stringify(inMemoryDB, null, 2));
    console.log(`Firestore hydration complete: ${inMemoryDB.users.length} users, ${inMemoryDB.deposits.length} deposits, ${inMemoryDB.withdrawals.length} withdrawals, ${inMemoryDB.tasks.length} tasks.`);
  } catch (err) {
    console.error("Failed to hydrate from Firestore:", err);
  }
}

// Trigger initial cloud sync
hydrateFromFirestore();

function loadDB(): DBData {
  return inMemoryDB;
}

function saveDB(db: DBData) {
  inMemoryDB = db;
  // 1. Local backup
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
  } catch (err) {
    console.error("Failed to save local DB", err);
  }

  // 2. Sync to Cloud Firestore asynchronously
  if (firestoreDb) {
    (async () => {
      try {
        // Save users
        for (const user of db.users) {
          if (user.id) {
            await setDoc(doc(firestoreDb!, "users", user.id), user);
          }
        }
        // Save deposits
        for (const dep of db.deposits) {
          if (dep.id) {
            await setDoc(doc(firestoreDb!, "deposits", dep.id), dep);
          }
        }
        // Save withdrawals
        for (const wd of db.withdrawals) {
          if (wd.id) {
            await setDoc(doc(firestoreDb!, "withdrawals", wd.id), wd);
          }
        }
        // Save tasks
        for (const task of db.tasks) {
          if (task.id) {
            await setDoc(doc(firestoreDb!, "tasks", task.id), task);
          }
        }
        // Save site settings
        await setDoc(doc(firestoreDb!, "siteSettings", "global"), db.siteSettings);
      } catch (cloudErr) {
        console.error("Error writing to Firestore:", cloudErr);
      }
    })();
  }
}


// API Health
app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

// --- Admin Auth ---
app.post("/api/admin/auth/login", (req, res) => {
  const { username, password } = req.body || {};
  const uname = username?.trim();
  
  if (uname === "admin" && password === "admin123") {
    const token = "admin_token_" + Buffer.from(uname).toString("base64");
    res.json({
      token,
      username: uname,
      role: "admin",
      message: "Login successful"
    });
  } else {
    res.status(401).json({ error: "Invalid credentials" });
  }
});

app.get("/api/admin/auth/me", (req, res) => {
  res.json({
    username: "admin",
    email: "admin@teronetwork.com",
    role: "admin",
    authenticated: true
  });
});

app.post("/api/admin/auth/logout", (req, res) => {
  res.json({ success: true });
});

// --- Admin Users Management ---
app.get("/api/admin/users", (req, res) => {
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
    users: paginated,
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
  res.json({ user });
});

// Edit user / update balance / status
app.post("/api/admin/users/:id", (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  const { balance, usdtBalance, status, isFrozen } = req.body || {};
  if (balance !== undefined) user.balance = parseFloat(balance);
  if (usdtBalance !== undefined) user.usdtBalance = parseFloat(usdtBalance);
  if (status !== undefined) user.status = status;
  if (isFrozen !== undefined) user.isFrozen = Boolean(isFrozen);

  saveDB(db);
  res.json({ success: true, user });
});

app.post("/api/admin/users/:id/freeze-inactivity", (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (user) {
    user.isFrozen = true;
    user.status = "frozen";
    saveDB(db);
  }
  res.json({ success: true });
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

app.post("/api/admin/tasks/bulk", (req, res) => {
  res.json({ ok: true, success: true });
});

app.post("/api/admin/tasks/recycle-links", (req, res) => {
  res.json({ ok: true, success: true });
});

app.post("/api/admin/tasks/new-week", (req, res) => {
  res.json({ ok: true, success: true });
});

app.post("/api/admin/tasks/import-csv", (req, res) => {
  res.json({ ok: true, success: true });
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

app.get("/api/admin/task-access-codes/current", (req, res) => {
  res.json({ code: null });
});

app.get("/api/admin/task-access-codes", (req, res) => {
  res.json({ codes: [] });
});

app.post("/api/admin/task-access-codes", (req, res) => {
  res.json({ ok: true, code: "TAC_" + Math.floor(100000 + Math.random() * 900000) });
});

app.delete("/api/admin/task-access-codes/:id", (req, res) => {
  res.json({ ok: true });
});

app.get("/api/admin/task-code-gen/settings", (req, res) => {
  res.json({
    settings: {
      enabled: true,
      intervalHours: 24,
      lastRun: new Date().toISOString(),
      status: "idle"
    }
  });
});

app.patch("/api/admin/task-code-gen/settings", (req, res) => {
  res.json({ enabled: req.body?.enabled ?? true, ok: true });
});

app.get("/api/admin/task-code-gen/log", (req, res) => {
  res.json({ logs: [] });
});

app.post("/api/admin/task-code-gen/manual", (req, res) => {
  res.json({
    ok: true,
    log: {
      id: "log_" + Date.now(),
      code: "TERO" + Math.floor(100000 + Math.random() * 900000),
      createdAt: new Date().toISOString(),
      status: "running"
    }
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

app.get("/api/admin/gas-management", (req, res) => {
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
        address: "0x113494B3aB9369CF9C66dE27255c948EF1266517",
        minRequired: 1.0,
        addressesNeedingGas: 0,
        estimatedGasCostUsd: 0.005
      }
    ]
  });
});

// --- Treasury & Hot Wallet ---
app.get("/api/admin/treasury", (req, res) => {
  const db = loadDB();
  const totalUserBalances = db.users.reduce((sum, u) => sum + (u.balance || 0), 0);
  res.json({
    totalBalance: totalUserBalances,
    hotWallet: totalUserBalances * 0.4,
    coldWallet: totalUserBalances * 0.6,
    addresses: [
      { network: "POLYGON", address: "0x113494B3aB9369CF9C66dE27255c948EF1266517", balance: totalUserBalances }
    ]
  });
});

app.get("/api/admin/treasury-settings", (req, res) => {
  res.json({
    settings: {
      POLYGON: "0x113494B3aB9369CF9C66dE27255c948EF1266517"
    }
  });
});

app.put("/api/admin/treasury-settings", (req, res) => {
  res.json({ ok: true });
});

app.delete("/api/admin/treasury-settings/:network", (req, res) => {
  res.json({ ok: true });
});

app.get("/api/admin/treasury-addresses", (req, res) => {
  res.json({
    addresses: [
      { network: "POLYGON", address: "0x113494B3aB9369CF9C66dE27255c948EF1266517", label: "Polygon Hot Wallet" }
    ],
    networks: {
      POLYGON: {
        sweepDest: {
          address: "0x113494B3aB9369CF9C66dE27255c948EF1266517",
          usdt: "250000.00",
          native: "150.5",
          nativeUnit: "POL"
        },
        hotWallet: {
          address: "0x113494B3aB9369CF9C66dE27255c948EF1266517",
          usdt: "50000.00",
          native: "25.0",
          nativeUnit: "POL"
        },
        gasDispenser: {
          address: "0x113494B3aB9369CF9C66dE27255c948EF1266517",
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

app.get("/api/admin/hot-wallet/status", (req, res) => {
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
        address: "0x113494B3aB9369CF9C66dE27255c948EF1266517",
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

app.post("/api/admin/auth/change-password", (req, res) => {
  res.json({ ok: true, message: "Password updated" });
});

app.post("/api/admin/auth/forgot-password", (req, res) => {
  res.json({ ok: true, message: "Reset email sent" });
});

app.post("/api/admin/membership-plans/sync", (req, res) => {
  res.json({ ok: true });
});

app.post("/api/admin/membership-plans/:id", (req, res) => {
  res.json({ ok: true });
});

app.post("/api/admin/site-settings/emergency_withdrawal_mode", (req, res) => {
  const db = loadDB();
  db.siteSettings.emergencyWithdrawalMode = !db.siteSettings.emergencyWithdrawalMode;
  saveDB(db);
  res.json({ ok: true, emergencyWithdrawalMode: db.siteSettings.emergencyWithdrawalMode });
});

// --- Admin Site & Finance Settings ---
app.get("/api/admin/site-settings", (req, res) => {
  const db = loadDB();
  res.json(db.siteSettings);
});

app.post("/api/admin/site-settings", (req, res) => {
  const db = loadDB();
  db.siteSettings = { ...db.siteSettings, ...req.body };
  saveDB(db);
  res.json({ success: true, siteSettings: db.siteSettings });
});

app.get("/api/networks/status", (req, res) => {
  res.json({
    polygon: true
  });
});

app.get("/api/finance-settings", (req, res) => {
  const db = loadDB();
  res.json({
    min_deposit_amount: db.siteSettings.min_deposit_amount ?? 5,
    min_withdrawal_amount: db.siteSettings.min_withdrawal_amount ?? 3,
    withdrawal_fee: db.siteSettings.withdrawal_fee ?? 21,
    max_withdrawal_amount: db.siteSettings.max_withdrawal_amount ?? 5000,
    emergencyWithdrawalMode: Boolean(db.siteSettings.emergencyWithdrawalMode)
  });
});

app.get("/api/maintenance-status", (req, res) => {
  const db = loadDB();
  res.json({ enabled: Boolean(db.siteSettings.maintenanceMode) });
});

app.get("/api/admin/maintenance", (req, res) => {
  const db = loadDB();
  res.json({ enabled: Boolean(db.siteSettings.maintenanceMode) });
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

app.get("/api/admin/membership-plans", (req, res) => {
  res.json({
    plans: [
      {
        "id": "p1",
        "tier": "free",
        "name": "المستوى المجاني",
        "price": 0,
        "dailyTaskLimit": 3,
        "incomeRate": 0.5,
        "durationDays": 365,
        "isPopular": false
      },
      {
        "id": "p2",
        "tier": "vip1",
        "name": "VIP 1",
        "price": 50,
        "dailyTaskLimit": 10,
        "incomeRate": 1.5,
        "durationDays": 30,
        "isPopular": false
      },
      {
        "id": "p3",
        "tier": "vip2",
        "name": "VIP 2",
        "price": 200,
        "dailyTaskLimit": 25,
        "incomeRate": 4.5,
        "durationDays": 30,
        "isPopular": true
      },
      {
        "id": "p4",
        "tier": "vip3",
        "name": "VIP 3",
        "price": 500,
        "dailyTaskLimit": 50,
        "incomeRate": 12.0,
        "durationDays": 30,
        "isPopular": false
      }
    ]
  });
});

app.get("/api/admin/membership-plans/distribution", (req, res) => {
  const db = loadDB();
  const totalActive = db.users.length;
  res.json({
    ok: true,
    totalActive,
    plans: [
      { id: "p1", tier: "free", name: "المستوى المجاني", price: 0, subscriberCount: db.users.filter(u => !u.membershipTier || u.membershipTier === "free").length },
      { id: "p2", tier: "vip1", name: "VIP 1", price: 50, subscriberCount: db.users.filter(u => u.membershipTier === "vip1").length },
      { id: "p3", tier: "vip2", name: "VIP 2", price: 200, subscriberCount: db.users.filter(u => u.membershipTier === "vip2").length },
      { id: "p4", tier: "vip3", name: "VIP 3", price: 500, subscriberCount: db.users.filter(u => u.membershipTier === "vip3").length }
    ]
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
  const user = db.users.find(u => u.id === req.params.id) || db.users[0];
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json(user);
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
  const list = db.deposits.filter(d => d.userId === req.params.id || d.username === "asse_24");
  res.json({ transactions: list, total: list.length });
});

app.get("/api/admin/users/:id/withdrawals", (req, res) => {
  const db = loadDB();
  const list = db.withdrawals.filter(w => w.userId === req.params.id || w.username === "asse_24");
  res.json({ transactions: list, total: list.length });
});

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "8701414109:AAEDizxf0LQsX9sB519-WOnYxnm8jb3OJN4";
const TELEGRAM_BOT_USERNAME = process.env.TELEGRAM_BOT_USERNAME || "TeroComunityBot";

// Telegram Polling Service for Auto-linking Accounts
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
        const msg = update.message;
        if (!msg || !msg.text) continue;
        
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
            
            if (!matchedUser && db.users.length > 0) {
              matchedUser = db.users[0];
            }
            
            if (matchedUser) {
              matchedUser.telegram = tgUsername;
              saveDB(db);
              
              // Reply to user on Telegram
              await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  chat_id: chatId,
                  text: `✅ تم ربط حسابك في منصة TERO بنجاح!\n👤 المستخدم: ${matchedUser.username}\n📲 تيليجرام: ${tgUsername}\n\nيمكنك الآن العودة إلى الموقع للمتابعة.`,
                  parse_mode: "HTML"
                })
              }).catch(() => {});
              continue;
            }
          }
          
          // Default greeting if no token
          await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              chat_id: chatId,
              text: `مرحباً بك في بوت منصة TERO الرسمي 🌟\n\nيرجى الدخول إلى المنصة والضغط على زر "ربط Telegram" لاستكمال إعداد حسابك تلقائياً.`,
              parse_mode: "HTML"
            })
          }).catch(() => {});
        }
      }
    }
  } catch (e) {
    // Silent catch for network resilience
  }
}

// Start bot polling loop
setInterval(pollTelegramBot, 3000);
pollTelegramBot();

app.get("/api/site-settings/public/telegram_support_username", (req, res) => {
  const db = loadDB();
  res.json({ telegramSupportUsername: TELEGRAM_BOT_USERNAME || db.siteSettings.telegramSupportUsername || "TeroComunityBot" });
});

// --- User-Facing API Routes ---
app.post("/api/auth/login", (req, res) => {
  const db = loadDB();
  const { username, identifier, email } = req.body || {};
  const uname = username || identifier || email || "asse_24";
  let user = db.users.find(u => u.username === uname || u.email === uname);
  if (!user) {
    user = {
      id: "u_" + Date.now(),
      username: uname,
      email: `${uname}@tero.com`,
      balance: 0.00,
      usdtBalance: 0.00,
      status: "active",
      isFrozen: false,
      joinedAt: new Date().toISOString(),
      membershipPlan: "none",
      referralsCount: 0
    };
    db.users.push(user);
    saveDB(db);
  }

  res.json({
    token: "user_token_" + Buffer.from(uname).toString("base64"),
    user
  });
});

app.get("/api/auth/me", (req, res) => {
  const db = loadDB();
  const authHeader = req.headers.authorization || "";
  let user = db.users[0];
  if (authHeader.startsWith("Bearer user_token_")) {
    try {
      const b64 = authHeader.replace("Bearer user_token_", "");
      const uname = Buffer.from(b64, "base64").toString("utf8");
      const found = db.users.find(u => u.username === uname || u.email === uname);
      if (found) user = found;
    } catch {}
  }
  
  const isLinked = Boolean(user && user.telegram && user.telegram.trim() !== "");
  res.json({
    ...(user || { id: "u1", username: "asse_24", email: "asse_24@tero.com" }),
    requiresTelegramLink: !isLinked
  });
});

app.get("/api/user/profile", (req, res) => {
  const db = loadDB();
  const user = db.users[0] || { id: "u1", username: "asse_24", balance: 0.00 };
  res.json({
    ...user,
    referralCode: user.referralCode || "TQ69JZ",
    leaderRank: 0,
    leaderPoints: 0,
    weeklySalary: 0,
    nextPayoutDate: null
  });
});

app.get("/api/user/telegram/status", (req, res) => {
  const db = loadDB();
  const authHeader = req.headers.authorization || "";
  let user = db.users[0];
  if (authHeader.startsWith("Bearer user_token_")) {
    try {
      const b64 = authHeader.replace("Bearer user_token_", "");
      const uname = Buffer.from(b64, "base64").toString("utf8");
      const found = db.users.find(u => u.username === uname || u.email === uname);
      if (found) user = found;
    } catch {}
  }
  const isLinked = Boolean(user && user.telegram && user.telegram.trim() !== "");
  res.json({ linked: isLinked, telegramUsername: user?.telegram || null });
});

app.post("/api/user/telegram/link-token", (req, res) => {
  const db = loadDB();
  const authHeader = req.headers.authorization || "";
  let user = db.users[0];
  if (authHeader.startsWith("Bearer user_token_")) {
    try {
      const b64 = authHeader.replace("Bearer user_token_", "");
      const uname = Buffer.from(b64, "base64").toString("utf8");
      const found = db.users.find(u => u.username === uname || u.email === uname);
      if (found) user = found;
    } catch {}
  }
  
  const botName = TELEGRAM_BOT_USERNAME || db.siteSettings.telegramSupportUsername || "TeroComunityBot";
  const linkId = user?.id || "u1";
  
  res.json({
    botUsername: botName,
    deepLink: `https://t.me/${botName}?start=link_${linkId}`,
    token: `token_${linkId}`
  });
});

// Manual or direct verification endpoint from external bots or webhooks
app.post("/api/user/telegram/verify-link", (req, res) => {
  const { token, telegramUsername, userId } = req.body || {};
  const db = loadDB();
  
  let targetId = userId;
  if (token) {
    targetId = token.replace("link_", "").replace("token_", "");
  }
  
  let user = db.users.find(u => u.id === targetId || u.username === targetId);
  if (!user && db.users.length > 0) user = db.users[0];
  
  if (user) {
    user.telegram = telegramUsername || "@user_tg";
    saveDB(db);
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

app.get("/api/wallet/balance", (req, res) => {
  const db = loadDB();
  const user = db.users[0];
  res.json({
    balance: (user?.balance ?? 0.00).toFixed(2),
    available: (user?.balance ?? 0.00).toFixed(2),
    currency: "USDT"
  });
});

app.get("/api/wallet/deposit-address", (req, res) => {
  const depositAddr = "0x113494B3aB9369CF9C66dE27255c948EF1266517";
  res.json({
    polygon: depositAddr,
    address: depositAddr,
    network: "POLYGON"
  });
});

app.post("/api/wallet/withdraw", (req, res) => {
  const db = loadDB();
  const { amount, address, network } = req.body || {};
  const amt = parseFloat(amount || "0");
  const user = db.users[0];

  if (user && user.balance >= amt) {
    user.balance -= amt;
    user.usdtBalance -= amt;
  }

  const newWithdrawal: Withdrawal = {
    id: "wd_" + Date.now(),
    userId: user?.id || "u1",
    username: user?.username || "asse_24",
    amount: amt,
    usdtAmount: amt,
    address: address || "0x...",
    network: network || "POLYGON",
    status: "pending_approval",
    createdAt: new Date().toISOString()
  };

  db.withdrawals.unshift(newWithdrawal);
  saveDB(db);

  res.json({ success: true, withdrawal: newWithdrawal });
});

app.get("/api/transactions", (req, res) => {
  res.json({ items: [], total: 0 });
});

app.get("/api/membership", (req, res) => {
  res.json({ tier: null, plan: "none", dailyLimit: 0, remainingTasks: 0 });
});

app.get("/api/membership/plans", (req, res) => {
  res.json([
    {
      "id": "p1",
      "tier": "free",
      "name": "المستوى المجاني",
      "price": 0,
      "dailyTaskLimit": 3,
      "incomeRate": 0.5,
      "durationDays": 365,
      "isPopular": false
    },
    {
      "id": "p2",
      "tier": "vip1",
      "name": "VIP 1",
      "price": 50,
      "dailyTaskLimit": 10,
      "incomeRate": 1.5,
      "durationDays": 30,
      "isPopular": false
    },
    {
      "id": "p3",
      "tier": "vip2",
      "name": "VIP 2",
      "price": 200,
      "dailyTaskLimit": 25,
      "incomeRate": 4.5,
      "durationDays": 30,
      "isPopular": true
    },
    {
      "id": "p4",
      "tier": "vip3",
      "name": "VIP 3",
      "price": 500,
      "dailyTaskLimit": 50,
      "incomeRate": 12.0,
      "durationDays": 30,
      "isPopular": false
    }
  ]);
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

app.get("/api/referrals/stats", (req, res) => {
  const db = loadDB();
  const user = db.users[0];
  res.json({ totalEarned: 0.00, totalReferrals: 0, referralCode: user?.referralCode || "TQ69JZ" });
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

// Generic Fallback Catch-All
app.all("/api/*", (req, res) => {
  if (req.method === "GET") {
    if (req.path.endsWith("s") || req.path.endsWith("s/")) {
      return res.json([]);
    }
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
