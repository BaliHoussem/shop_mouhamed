import express from "express";
import session from "express-session";
import helmet from "helmet";
import multer from "multer";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ====== Admin password ======
const ADMIN_PASSWORD_PLAIN = process.env.ADMIN_PASSWORD || "mouhamedAstro";
const ADMIN_PASSWORD_HASH = bcrypt.hashSync(ADMIN_PASSWORD_PLAIN, 10);

// ====== Paths ======
const DATA_FILE = path.join(__dirname, "data.json");
const PUBLIC_DIR = path.join(__dirname, "public");
const UPLOADS_DIR = path.join(PUBLIC_DIR, "uploads");

// Ensure folders
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ====== Default shipping (58 wilayas) ======
const DEFAULT_SHIPPING = [
  { id: 1, name: "أدرار", home: 1000, office: 700 },
  { id: 2, name: "الشلف", home: 800, office: 500 },
  { id: 3, name: "الأغواط", home: 900, office: 600 },
  { id: 4, name: "أم البواقي", home: 800, office: 500 },
  { id: 5, name: "باتنة", home: 850, office: 550 },
  { id: 6, name: "بجاية", home: 800, office: 500 },
  { id: 7, name: "بسكرة", home: 900, office: 600 },
  { id: 8, name: "بشار", home: 1100, office: 800 },
  { id: 9, name: "البليدة", home: 600, office: 350 },
  { id: 10, name: "البويرة", home: 700, office: 450 },
  { id: 11, name: "تمنراست", home: 1300, office: 1000 },
  { id: 12, name: "تبسة", home: 850, office: 550 },
  { id: 13, name: "تلمسان", home: 900, office: 600 },
  { id: 14, name: "تيارت", home: 850, office: 550 },
  { id: 15, name: "تيزي وزو", home: 700, office: 450 },
  { id: 16, name: "الجزائر", home: 500, office: 250 },
  { id: 17, name: "الجلفة", home: 900, office: 600 },
  { id: 18, name: "جيجل", home: 850, office: 550 },
  { id: 19, name: "سطيف", home: 800, office: 500 },
  { id: 20, name: "سعيدة", home: 900, office: 600 },
  { id: 21, name: "سكيكدة", home: 850, office: 550 },
  { id: 22, name: "سيدي بلعباس", home: 900, office: 600 },
  { id: 23, name: "عنابة", home: 850, office: 550 },
  { id: 24, name: "قالمة", home: 850, office: 550 },
  { id: 25, name: "قسنطينة", home: 800, office: 500 },
  { id: 26, name: "المدية", home: 700, office: 450 },
  { id: 27, name: "مستغانم", home: 850, office: 550 },
  { id: 28, name: "المسيلة", home: 850, office: 550 },
  { id: 29, name: "معسكر", home: 850, office: 550 },
  { id: 30, name: "ورقلة", home: 1000, office: 700 },
  { id: 31, name: "وهران", home: 800, office: 500 },
  { id: 32, name: "البيض", home: 1000, office: 700 },
  { id: 33, name: "إليزي", home: 1200, office: 900 },
  { id: 34, name: "برج بوعريريج", home: 800, office: 500 },
  { id: 35, name: "بومرداس", home: 650, office: 400 },
  { id: 36, name: "الطارف", home: 900, office: 600 },
  { id: 37, name: "تندوف", home: 1200, office: 900 },
  { id: 38, name: "تيسمسيلت", home: 850, office: 550 },
  { id: 39, name: "الوادي", home: 1000, office: 700 },
  { id: 40, name: "خنشلة", home: 850, office: 550 },
  { id: 41, name: "سوق أهراس", home: 900, office: 600 },
  { id: 42, name: "تيبازة", home: 650, office: 400 },
  { id: 43, name: "ميلة", home: 850, office: 550 },
  { id: 44, name: "عين الدفلى", home: 750, office: 500 },
  { id: 45, name: "النعامة", home: 1000, office: 700 },
  { id: 46, name: "عين تموشنت", home: 850, office: 550 },
  { id: 47, name: "غرداية", home: 950, office: 650 },
  { id: 48, name: "غليزان", home: 850, office: 550 },
  { id: 49, name: "تيميمون", home: 1100, office: 800 },
  { id: 50, name: "برج باجي مختار", home: 1400, office: 1100 },
  { id: 51, name: "أولاد جلال", home: 900, office: 600 },
  { id: 52, name: "بني عباس", home: 1100, office: 800 },
  { id: 53, name: "عين صالح", home: 1300, office: 1000 },
  { id: 54, name: "عين قزام", home: 1400, office: 1100 },
  { id: 55, name: "تقرت", home: 1000, office: 700 },
  { id: 56, name: "جانت", home: 1200, office: 900 },
  { id: 57, name: "المغير", home: 950, office: 650 },
  { id: 58, name: "المنيعة", home: 950, office: 650 },
];

// ====== Helpers ======
function writeData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), "utf-8");
}

function readData() {
  if (!fs.existsSync(DATA_FILE)) {
    const initial = {
      settings: {
        product_name: "خلاط Ninja Blend",
        product_desc: "خلاط قوي لتحضير العصائر في ثوانٍ.",
        price: 3800,
        old_price: 5500,
        images: [
          "https://images.unsplash.com/photo-1570222094114-d054a817e56b?auto=format&fit=crop&q=80&w=1200",
        ],
        updated_at: new Date().toISOString(),
      },
      shipping: DEFAULT_SHIPPING,
      orders: [],
    };
    writeData(initial);
    return initial;
  }

  const db = JSON.parse(fs.readFileSync(DATA_FILE, "utf-8"));

  // Backfill shipping
  if (!Array.isArray(db.shipping) || db.shipping.length < 58) {
    db.shipping = DEFAULT_SHIPPING;
    writeData(db);
  }

  if (!db.settings) db.settings = {};
  if (!Array.isArray(db.orders)) db.orders = [];

  return db;
}

function requireAdmin(req, res, next) {
  if (req.session?.isAdmin) return next();
  return res.status(401).json({ ok: false, error: "UNAUTHORIZED" });
}

function isValidPhone(p) {
  const phone = String(p || "").replace(/\s+/g, "");
  return /^(0)(5|6|7)\d{8}$/.test(phone);
}

function clampInt(n, min, max) {
  const x = Number(n);
  if (!Number.isFinite(x)) return min;
  return Math.max(min, Math.min(max, Math.trunc(x)));
}

function computeShipping(db, wilayaId, shipType) {
  const w = (db.shipping || []).find((x) => x.id === Number(wilayaId));
  if (!w) return { ship: 0, wilaya: null };
  const ship =
    shipType === "office" ? Number(w.office || 0) : Number(w.home || 0);
  return { ship, wilaya: w };
}

// ====== Anti-spam basic (10s per IP) ======
const lastOrderByIp = new Map();
function canOrder(ip) {
  const now = Date.now();
  const last = lastOrderByIp.get(ip) || 0;
  if (now - last < 10_000) return false;
  lastOrderByIp.set(ip, now);
  return true;
}

// ====== Middleware ======
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    name: "sid",
    secret: process.env.SESSION_SECRET || "change_this_secret_in_prod",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
    },
  }),
);

app.use(express.static(PUBLIC_DIR));

// ====== Multer upload ======
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase() || ".jpg";
    const safe = `${Date.now()}_${crypto.randomBytes(6).toString("hex")}${ext}`;
    cb(null, safe);
  },
});
const upload = multer({ storage, limits: { fileSize: 6 * 1024 * 1024 } });

// ====== Pages ======
app.get("/admin", (_req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "admin.html"));
});

// ====== Public APIs ======
app.get("/api/settings", (_req, res) => {
  const db = readData();
  res.json({ ok: true, settings: db.settings });
});

app.get("/api/shipping", (_req, res) => {
  const db = readData();
  res.json({ ok: true, shipping: db.shipping });
});

app.post("/api/order", (req, res) => {
  try {
    const ip =
      req.headers["x-forwarded-for"]?.toString().split(",")[0]?.trim() ||
      req.socket.remoteAddress ||
      "unknown";
    if (!canOrder(ip))
      return res.status(429).json({ ok: false, error: "RATE_LIMIT" });

    const db = readData();

    const name = String(req.body?.name || "").trim();
    const phone = String(req.body?.phone || "").replace(/\s+/g, "");
    const wilaya_id = Number(req.body?.wilaya_id);
    const shipping_type =
      req.body?.shipping_type === "office" ? "office" : "home";
    const quantity = clampInt(req.body?.quantity, 1, 20);

    if (!name)
      return res.status(400).json({ ok: false, error: "NAME_REQUIRED" });
    if (!isValidPhone(phone))
      return res.status(400).json({ ok: false, error: "PHONE_INVALID" });

    const { ship, wilaya } = computeShipping(db, wilaya_id, shipping_type);
    if (!wilaya)
      return res.status(400).json({ ok: false, error: "WILAYA_REQUIRED" });

    const product_price = clampInt(db.settings?.price, 0, 999999999);
    const subtotal = product_price * quantity;
    const total = subtotal + ship;

    const order = {
      id: crypto.randomUUID(),
      created_at: new Date().toISOString(),
      customer_name: name,
      phone,
      wilaya_id: wilaya.id,
      wilaya_name: wilaya.name,
      shipping_type,
      quantity,
      product_price,
      shipping_price: ship,
      subtotal,
      total,
      status: "new",
    };

    db.orders.unshift(order);
    writeData(db);

    res.json({ ok: true, order_id: order.id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: "SERVER_ERROR" });
  }
});

// ====== Admin auth ======
app.post("/api/admin/login", (req, res) => {
  const password = String(req.body?.password || "");
  const ok = bcrypt.compareSync(password, ADMIN_PASSWORD_HASH);
  if (!ok) return res.status(401).json({ ok: false, error: "BAD_PASSWORD" });
  req.session.isAdmin = true;
  res.json({ ok: true });
});

app.post("/api/admin/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/admin/me", (req, res) => {
  res.json({ ok: true, isAdmin: !!req.session?.isAdmin });
});

// ====== Admin settings ======
app.get("/api/admin/settings", requireAdmin, (_req, res) => {
  const db = readData();
  res.json({ ok: true, settings: db.settings });
});

app.put("/api/admin/settings", requireAdmin, (req, res) => {
  const db = readData();

  const product_name = String(req.body?.product_name || "").trim();
  const product_desc = String(req.body?.product_desc || "").trim();
  const price = clampInt(req.body?.price, 0, 999999999);
  const old_price = clampInt(req.body?.old_price, 0, 999999999);
  const images = Array.isArray(req.body?.images)
    ? req.body.images.filter((x) => typeof x === "string")
    : db.settings.images;

  if (!product_name)
    return res.status(400).json({ ok: false, error: "PRODUCT_NAME_REQUIRED" });
  if (price <= 0)
    return res.status(400).json({ ok: false, error: "PRICE_INVALID" });

  db.settings = {
    ...db.settings,
    product_name,
    product_desc,
    price,
    old_price,
    images,
    updated_at: new Date().toISOString(),
  };
  writeData(db);
  res.json({ ok: true, settings: db.settings });
});

// ====== Admin shipping ======
app.get("/api/admin/shipping", requireAdmin, (_req, res) => {
  const db = readData();
  res.json({ ok: true, shipping: db.shipping });
});

app.put("/api/admin/shipping", requireAdmin, (req, res) => {
  const db = readData();
  const incoming = req.body?.shipping;

  if (!Array.isArray(incoming))
    return res.status(400).json({ ok: false, error: "BAD_SHIPPING" });

  const map = new Map(incoming.map((x) => [Number(x.id), x]));
  const updated = db.shipping.map((w) => {
    const it = map.get(w.id);
    const home = clampInt(it?.home ?? w.home, 0, 100000);
    const office = clampInt(it?.office ?? w.office, 0, 100000);
    return { ...w, home, office };
  });

  db.shipping = updated;
  writeData(db);
  res.json({ ok: true, shipping: db.shipping });
});

// ====== Admin images ======
app.post(
  "/api/admin/images",
  requireAdmin,
  upload.array("images", 12),
  (req, res) => {
    const files = req.files || [];
    const urls = files.map((f) => `/uploads/${f.filename}`);
    res.json({ ok: true, urls });
  },
);

app.delete("/api/admin/images/:filename", requireAdmin, (req, res) => {
  const filename = String(req.params.filename || "");
  if (!/^[a-zA-Z0-9._-]+$/.test(filename))
    return res.status(400).json({ ok: false, error: "BAD_FILENAME" });

  const full = path.join(UPLOADS_DIR, filename);
  if (fs.existsSync(full)) fs.unlinkSync(full);

  const db = readData();
  const url = `/uploads/${filename}`;
  db.settings.images = (db.settings.images || []).filter((u) => u !== url);
  db.settings.updated_at = new Date().toISOString();
  writeData(db);

  res.json({ ok: true });
});

// ====== Admin orders ======
app.get("/api/admin/orders", requireAdmin, (req, res) => {
  const db = readData();
  const status = String(req.query?.status || "").trim();
  const orders = status
    ? db.orders.filter((o) => o.status === status)
    : db.orders;
  res.json({ ok: true, orders });
});

app.put("/api/admin/orders/:id/status", requireAdmin, (req, res) => {
  const id = String(req.params.id || "");
  const status = String(req.body?.status || "new");
  const allowed = new Set([
    "new",
    "confirmed",
    "shipped",
    "delivered",
    "cancelled",
  ]);
  if (!allowed.has(status))
    return res.status(400).json({ ok: false, error: "BAD_STATUS" });

  const db = readData();
  const order = db.orders.find((o) => o.id === id);
  if (!order) return res.status(404).json({ ok: false, error: "NOT_FOUND" });

  order.status = status;
  writeData(db);
  res.json({ ok: true });
});

// ✅ NEW: delete order
app.delete("/api/admin/orders/:id", requireAdmin, (req, res) => {
  const id = String(req.params.id || "");
  const db = readData();
  const before = db.orders.length;
  db.orders = db.orders.filter((o) => o.id !== id);

  if (db.orders.length === before)
    return res.status(404).json({ ok: false, error: "NOT_FOUND" });
  writeData(db);
  res.json({ ok: true });
});

// health
app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`✅ Server running: http://localhost:${PORT}`);
  console.log(`✅ Admin panel:   http://localhost:${PORT}/admin`);
});
