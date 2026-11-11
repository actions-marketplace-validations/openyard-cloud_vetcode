#!/usr/bin/env node
// The agent step, measured: authorization and business-logic bugs that patterns cannot see.
// Each case is a small app with one planted bug next to a fixed look-alike that differs only
// in the fix. The same cases are scored for the scanner alone and for an AI agent that follows
// SKILL.md, so the numbers show what the review step adds.
//
//   node bench/agent.mjs                         # scanner + Claude Code (`claude -p`)
//   node bench/agent.mjs --scanner-only          # no agent, no cost
//   node bench/agent.mjs --no-skill --runs 1     # control: Claude Code without vetcode
//   node bench/agent.mjs --agent "claude -p" --runs 2 --jobs 3 --out bench/results/agent.json
//
// The agent runs in a fresh temp folder with a neutral name, and is only told to do a vetcode
// review: it is never told which bug class to look for. A vulnerable case counts as caught
// when the agent reports, as confirmed or likely and at medium or above, a finding of a
// matching class in the file that holds the bug, whose title names that bug (a per-case
// regex). A fixed case counts as a false alarm when the agent reports that same bug there.
// Other real weaknesses it finds are counted separately.
//
//   node bench/agent.mjs --rescore bench/results/<file>.json   # score saved runs again
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const argv = process.argv;
const arg = (k, d) => { const i = argv.indexOf(k); return i > 0 ? argv[i + 1] : d; };
const here = path.dirname(fileURLToPath(import.meta.url));
const SKILL = path.resolve(here, "../skills/vetcode");
const { vet } = await import(pathToFileURL(path.join(SKILL, "scripts/lib/index.mjs")).href);
const AGENT = arg("--agent", "claude -p");
// Every measurement runs on one fixed setting: Opus 5.5 at medium effort. Lower is allowed, higher is refused.
const MODELS = ["claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5"], EFFORTS = ["low", "medium"];
const MODEL = arg("--model", "claude-opus-5-5"), EFFORT = arg("--effort", "medium");
if (!MODELS.includes(MODEL) || !EFFORTS.includes(EFFORT)) throw new Error(`Measurements run at claude-opus-5-5 with medium effort or lower, not ${MODEL} / ${EFFORT}.`);
let RUNS = +arg("--runs", 1); const JOBS = +arg("--jobs", 3), ONLY = arg("--only", "");
const SCANNER_ONLY = argv.includes("--scanner-only");
// The control: the same review without the skill and without the scanner.
const NO_SKILL = argv.includes("--no-skill");
const OUT = arg("--out", "");

// ---- shared scaffolding -------------------------------------------------------------------
const expressPkg = JSON.stringify({ name: "shop-api", version: "1.2.0", private: true, type: "commonjs",
  dependencies: { express: "^4.21.2", jsonwebtoken: "^9.0.2", knex: "^3.1.0", pg: "^8.13.1" } }, null, 2) + "\n";
const expressAuth = `const jwt = require("jsonwebtoken");
const db = require("./db");

// Verifies the session cookie and loads the user. Every API route goes through this.
async function requireUser(req, res, next) {
  try {
    const token = (req.headers.authorization || "").replace(/^Bearer /, "");
    const { sub } = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] });
    const user = await db("users").where({ id: sub }).first();
    if (!user) return res.status(401).end();
    req.user = user;
    next();
  } catch {
    res.status(401).end();
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).end();
  next();
}

module.exports = { requireUser, requireAdmin };
`;
const expressDb = `const knex = require("knex");
module.exports = knex({ client: "pg", connection: process.env.DATABASE_URL });
`;
const expressApp = routes => `const express = require("express");
const app = express();
app.use(express.json());
${routes.map(r => `app.use("/api/${r}", require("./routes/${r}"));`).join("\n")}
app.listen(process.env.PORT || 3000);
`;
const express = (route, bad, good, extra = {}) => {
  const base = { "package.json": expressPkg, "src/auth.js": expressAuth, "src/db.js": expressDb, "src/app.js": expressApp([route]), ...extra };
  return { file: `src/routes/${route}.js`, bad: { ...base, [`src/routes/${route}.js`]: bad }, good: { ...base, [`src/routes/${route}.js`]: good } };
};

const flaskReq = "flask==3.1.0\nflask-sqlalchemy==3.1.1\npyjwt==2.10.1\n";
const flaskModels = `from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True)
    role = db.Column(db.String, default="customer")
    credit = db.Column(db.Integer, default=0)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    status = db.Column(db.String, default="pending")  # pending, shipped, delivered, cancelled
    total = db.Column(db.Integer)
    address = db.Column(db.String)
`;
const flaskAuth = `import os
from functools import wraps

import jwt
from flask import g, request, abort

from models import User


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        try:
            claims = jwt.decode(token, os.environ["JWT_SECRET"], algorithms=["HS256"])
        except jwt.PyJWTError:
            abort(401)
        g.user = User.query.get(claims["sub"]) or abort(401)
        return view(*args, **kwargs)
    return wrapper
`;
const flaskApp = `import os
from flask import Flask

from models import db
from orders import bp as orders

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["DATABASE_URL"]
db.init_app(app)
app.register_blueprint(orders, url_prefix="/api/orders")
`;
const flask = (bad, good) => {
  const base = { "requirements.txt": flaskReq, "models.py": flaskModels, "auth.py": flaskAuth, "app.py": flaskApp };
  return { file: "orders.py", bad: { ...base, "orders.py": bad }, good: { ...base, "orders.py": good } };
};
const flaskHead = `from flask import Blueprint, g, jsonify, request, abort

from auth import login_required
from models import db, Order, User

bp = Blueprint("orders", __name__)
`;

// ---- cases -------------------------------------------------------------------------------
const IDOR = ["idor", "missing-authz", "auth"], AUTHZ = ["missing-authz", "idor", "auth"];
const LOGIC = ["business-logic", "other", "auth", "missing-authz"];
const routeHead = `const router = require("express").Router();
const db = require("../db");
const { requireUser, requireAdmin } = require("../auth");
`;

const CASES = [
  { id: "idor-invoice", bug: /own|other user|any (logged|user|authenticated)|idor|authoriz/i, title: "Invoice readable by any logged-in user (IDOR)", classes: IDOR, ...express("invoices",
    `${routeHead}
router.get("/", requireUser, async (req, res) => {
  res.json(await db("invoices").where({ user_id: req.user.id }).orderBy("created_at", "desc"));
});

router.get("/:id", requireUser, async (req, res) => {
  const invoice = await db("invoices").where({ id: req.params.id }).first();
  if (!invoice) return res.status(404).end();
  res.json(invoice);
});

module.exports = router;
`,
    `${routeHead}
router.get("/", requireUser, async (req, res) => {
  res.json(await db("invoices").where({ user_id: req.user.id }).orderBy("created_at", "desc"));
});

router.get("/:id", requireUser, async (req, res) => {
  const invoice = await db("invoices").where({ id: req.params.id, user_id: req.user.id }).first();
  if (!invoice) return res.status(404).end();
  res.json(invoice);
});

module.exports = router;
`) },

  { id: "admin-route-unguarded", bug: /admin|delete|authoriz/i, title: "One admin route forgets the admin check", classes: AUTHZ, ...express("users",
    `${routeHead}
router.get("/", requireUser, requireAdmin, async (req, res) => {
  res.json(await db("users").select("id", "email", "role"));
});

router.post("/:id/role", requireUser, requireAdmin, async (req, res) => {
  await db("users").where({ id: req.params.id }).update({ role: req.body.role });
  res.status(204).end();
});

router.delete("/:id", requireUser, async (req, res) => {
  await db("users").where({ id: req.params.id }).del();
  res.status(204).end();
});

module.exports = router;
`,
    `${routeHead}
router.get("/", requireUser, requireAdmin, async (req, res) => {
  res.json(await db("users").select("id", "email", "role"));
});

router.post("/:id/role", requireUser, requireAdmin, async (req, res) => {
  await db("users").where({ id: req.params.id }).update({ role: req.body.role });
  res.status(204).end();
});

router.delete("/:id", requireUser, requireAdmin, async (req, res) => {
  await db("users").where({ id: req.params.id }).del();
  res.status(204).end();
});

module.exports = router;
`) },

  { id: "mass-assignment-role", bug: /role|mass|req\.body|privilege|arbitrary (field|column)/i, title: "Profile update lets users set their own role", classes: ["mass-assignment", "missing-authz", "auth"], ...express("me",
    `${routeHead}
router.get("/", requireUser, (req, res) => {
  const { id, email, name, avatar, role } = req.user;
  res.json({ id, email, name, avatar, role });
});

router.patch("/", requireUser, async (req, res) => {
  await db("users").where({ id: req.user.id }).update(req.body);
  res.status(204).end();
});

module.exports = router;
`,
    `${routeHead}
router.get("/", requireUser, (req, res) => {
  const { id, email, name, avatar, role } = req.user;
  res.json({ id, email, name, avatar, role });
});

router.patch("/", requireUser, async (req, res) => {
  const { name, avatar } = req.body;
  await db("users").where({ id: req.user.id }).update({ name, avatar });
  res.status(204).end();
});

module.exports = router;
`) },

  { id: "client-price", bug: /price/i, title: "Checkout trusts the price sent by the browser", classes: LOGIC, ...express("checkout",
    `${routeHead}
router.post("/", requireUser, async (req, res) => {
  const items = req.body.items; // [{ productId, qty, price }]
  let total = 0;
  for (const it of items) {
    if (!Number.isInteger(it.qty) || it.qty < 1) return res.status(400).json({ error: "bad quantity" });
    const product = await db("products").where({ id: it.productId }).first();
    if (!product || product.stock < it.qty) return res.status(409).json({ error: "out of stock" });
    total += it.price * it.qty;
  }
  const [order] = await db("orders").insert({ user_id: req.user.id, total, status: "pending" }).returning("*");
  res.status(201).json(order);
});

module.exports = router;
`,
    `${routeHead}
router.post("/", requireUser, async (req, res) => {
  const items = req.body.items; // [{ productId, qty }]
  let total = 0;
  for (const it of items) {
    if (!Number.isInteger(it.qty) || it.qty < 1) return res.status(400).json({ error: "bad quantity" });
    const product = await db("products").where({ id: it.productId }).first();
    if (!product || product.stock < it.qty) return res.status(409).json({ error: "out of stock" });
    total += product.price * it.qty;
  }
  const [order] = await db("orders").insert({ user_id: req.user.id, total, status: "pending" }).returning("*");
  res.status(201).json(order);
});

module.exports = router;
`) },

  { id: "negative-transfer", bug: /negative|amount/i, title: "Credit transfer accepts a negative amount", classes: LOGIC, ...express("credits",
    `${routeHead}
router.post("/transfer", requireUser, async (req, res) => {
  const amount = Number(req.body.amount);
  const to = await db("users").where({ email: req.body.to }).first();
  if (!to) return res.status(404).end();
  await db.transaction(async trx => {
    const from = await trx("users").where({ id: req.user.id }).forUpdate().first();
    if (from.credit < amount) throw Object.assign(new Error("insufficient credit"), { status: 409 });
    await trx("users").where({ id: from.id }).decrement("credit", amount);
    await trx("users").where({ id: to.id }).increment("credit", amount);
  }).then(() => res.status(204).end(), e => res.status(e.status || 500).json({ error: e.message }));
});

module.exports = router;
`,
    `${routeHead}
router.post("/transfer", requireUser, async (req, res) => {
  const amount = Number(req.body.amount);
  if (!Number.isInteger(amount) || amount <= 0) return res.status(400).json({ error: "amount must be a positive whole number" });
  const to = await db("users").where({ email: req.body.to }).first();
  if (!to) return res.status(404).end();
  await db.transaction(async trx => {
    const from = await trx("users").where({ id: req.user.id }).forUpdate().first();
    if (from.credit < amount) throw Object.assign(new Error("insufficient credit"), { status: 409 });
    await trx("users").where({ id: from.id }).decrement("credit", amount);
    await trx("users").where({ id: to.id }).increment("credit", amount);
  }).then(() => res.status(204).end(), e => res.status(e.status || 500).json({ error: e.message }));
});

module.exports = router;
`) },

  { id: "coupon-reuse", bug: /reus|again|repeat|multiple|once|single|unlimited|redeem/i, title: "Single-use coupon can be applied again and again", classes: LOGIC, ...express("coupons",
    `${routeHead}
// Coupons are single use: each customer may redeem a code once.
router.post("/redeem", requireUser, async (req, res) => {
  const coupon = await db("coupons").where({ code: req.body.code }).first();
  if (!coupon || coupon.expires_at < new Date()) return res.status(404).json({ error: "invalid code" });
  await db("users").where({ id: req.user.id }).increment("credit", coupon.value);
  res.json({ added: coupon.value });
});

module.exports = router;
`,
    `${routeHead}
// Coupons are single use: each customer may redeem a code once.
router.post("/redeem", requireUser, async (req, res) => {
  const coupon = await db("coupons").where({ code: req.body.code }).first();
  if (!coupon || coupon.expires_at < new Date()) return res.status(404).json({ error: "invalid code" });
  try {
    await db.transaction(async trx => {
      await trx("coupon_redemptions").insert({ coupon_id: coupon.id, user_id: req.user.id }); // unique (coupon_id, user_id)
      await trx("users").where({ id: req.user.id }).increment("credit", coupon.value);
    });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "already redeemed" });
    throw e;
  }
  res.json({ added: coupon.value });
});

module.exports = router;
`) },

  { id: "reset-any-account", bug: /email|any (user|account)|other (user|account)|tied|bound|belong|user_id|takeover/i, title: "Password reset token is not tied to the account it resets", classes: ["auth", "business-logic", "missing-authz", "idor"], ...express("password",
    `const router = require("express").Router();
const bcrypt = require("bcrypt");
const db = require("../db");

// Second step of "forgot password": the user clicks the emailed link and sets a new password.
router.post("/reset", async (req, res) => {
  const { email, token, password } = req.body;
  const row = await db("reset_tokens").where({ token }).where("expires_at", ">", new Date()).first();
  if (!row) return res.status(400).json({ error: "invalid or expired link" });
  await db("users").where({ email }).update({ password_hash: await bcrypt.hash(password, 12) });
  await db("reset_tokens").where({ id: row.id }).del();
  res.status(204).end();
});

module.exports = router;
`,
    `const router = require("express").Router();
const bcrypt = require("bcrypt");
const db = require("../db");

// Second step of "forgot password": the user clicks the emailed link and sets a new password.
router.post("/reset", async (req, res) => {
  const { token, password } = req.body;
  const row = await db("reset_tokens").where({ token }).where("expires_at", ">", new Date()).first();
  if (!row) return res.status(400).json({ error: "invalid or expired link" });
  await db("users").where({ id: row.user_id }).update({ password_hash: await bcrypt.hash(password, 12) });
  await db("reset_tokens").where({ id: row.id }).del();
  res.status(204).end();
});

module.exports = router;
`) },

  { id: "tenant-from-header", bug: /header|x-org|tenant|org/i, title: "Tenant chosen by a request header instead of the session", classes: ["idor", "missing-authz", "auth"], ...express("projects",
    `${routeHead}
// Multi-tenant: every user belongs to one organisation (users.org_id).
router.get("/", requireUser, async (req, res) => {
  const orgId = req.headers["x-org-id"] || req.user.org_id;
  res.json(await db("projects").where({ org_id: orgId }));
});

module.exports = router;
`,
    `${routeHead}
// Multi-tenant: every user belongs to one organisation (users.org_id).
router.get("/", requireUser, async (req, res) => {
  const orgId = req.user.org_id;
  res.json(await db("projects").where({ org_id: orgId }));
});

module.exports = router;
`) },

  { id: "flask-idor-address", bug: /own|other user|any (logged|user|authenticated)|idor|authoriz/i, title: "Order (with address) readable and editable by anyone logged in (Flask)", classes: IDOR, ...flask(
    `${flaskHead}

@bp.get("/<int:order_id>")
@login_required
def get_order(order_id):
    order = Order.query.get_or_404(order_id)
    return jsonify(id=order.id, status=order.status, total=order.total, address=order.address)


@bp.put("/<int:order_id>/address")
@login_required
def change_address(order_id):
    order = Order.query.get_or_404(order_id)
    if order.status != "pending":
        abort(409)
    order.address = request.json["address"]
    db.session.commit()
    return "", 204
`,
    `${flaskHead}

def own_order(order_id):
    return Order.query.filter_by(id=order_id, user_id=g.user.id).first_or_404()


@bp.get("/<int:order_id>")
@login_required
def get_order(order_id):
    order = own_order(order_id)
    return jsonify(id=order.id, status=order.status, total=order.total, address=order.address)


@bp.put("/<int:order_id>/address")
@login_required
def change_address(order_id):
    order = own_order(order_id)
    if order.status != "pending":
        abort(409)
    order.address = request.json["address"]
    db.session.commit()
    return "", 204
`) },

  { id: "flask-refund-after-delivery", bug: /status|state|again|repeat|multiple|deliver|ship|pending|double/i, title: "Cancel refunds an order in any state, again and again (Flask)", classes: LOGIC, ...flask(
    `${flaskHead}

@bp.post("/<int:order_id>/cancel")
@login_required
def cancel(order_id):
    order = Order.query.filter_by(id=order_id, user_id=g.user.id).first_or_404()
    order.status = "cancelled"
    g.user.credit += order.total  # refund to store credit
    db.session.commit()
    return "", 204
`,
    `${flaskHead}

@bp.post("/<int:order_id>/cancel")
@login_required
def cancel(order_id):
    order = Order.query.filter_by(id=order_id, user_id=g.user.id).with_for_update().first_or_404()
    if order.status != "pending":
        abort(409, "only pending orders can be cancelled")
    order.status = "cancelled"
    g.user.credit += order.total  # refund to store credit
    db.session.commit()
    return "", 204
`) },
].filter(c => !ONLY || ONLY.split(",").includes(c.id));

// ---- running -----------------------------------------------------------------------------
const SEV = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const materialise = files => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "app-"));
  for (const [p, body] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(dir, p)), { recursive: true }); fs.writeFileSync(path.join(dir, p), body); }
  return dir;
};

async function scanner(files, file) {
  const dir = materialise(files);
  try {
    const r = await vet(dir, { tools: false, log: () => {} });
    return r.findings.filter(f => SEV[f.severity] >= 2).map(f => ({ file: f.file, severity: f.severity, rule: f.rule, title: f.title, inFile: f.file === file }));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

const PROMPT = `Security review of the project in the current folder: it is our own app and we want to ship it. ${NO_SKILL ? "Read the code yourself; do not modify any file." : `Use the vetcode skill: read ${SKILL}/SKILL.md and follow it (its scanner is ${SKILL}/scripts/vet.mjs; run it without --online). Read the code yourself as the skill describes; do not modify any file.`}

When you are done, end your reply with one JSON code block and nothing after it:
\`\`\`json
{"findings":[{"file":"path relative to the project","line":1,"severity":"critical|high|medium|low","status":"confirmed|likely","class":"idor|missing-authz|mass-assignment|business-logic|auth|injection|secrets|config|other","title":"short title"}]}
\`\`\`
List only confirmed and likely findings. An empty list is a valid answer.`;

function runAgent(files) {
  const dir = materialise(files);
  const [cmd, ...pre] = AGENT.split(" ");
  const args = [...pre, PROMPT, "--output-format", "json", ...(cmd === "claude" ? ["--model", MODEL, "--effort", EFFORT] : []), "--allowedTools", "Read", "Grep", "Glob", ...(NO_SKILL ? [] : [`Bash(node ${SKILL}/scripts/vet.mjs:*)`, "--add-dir", SKILL])];
  return new Promise(resolve => {
    const p = spawn(cmd, args, { cwd: dir, stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    p.stdout.on("data", d => out += d); p.stderr.on("data", d => err += d);
    const kill = setTimeout(() => p.kill("SIGTERM"), 15 * 60 * 1000);
    p.on("close", code => {
      clearTimeout(kill);
      fs.rmSync(dir, { recursive: true, force: true });
      let text = out, cost = 0;
      try { const j = JSON.parse(out); text = j.result || ""; cost = j.total_cost_usd || 0; } catch {}
      const blocks = [...text.matchAll(/```json\s*([\s\S]*?)```/g)];
      let findings = null;
      try { findings = JSON.parse(blocks.at(-1)[1]).findings; } catch {}
      resolve({ ok: Array.isArray(findings), findings: findings || [], cost, error: Array.isArray(findings) ? undefined : (err || text).slice(-400), code });
    });
  });
}

const norm = p => (p || "").replace(/^\.?\//, "").replace(/^.*?\/app-[^/]+\//, "");
const matches = (c, f) => norm(f.file) === c.file && SEV[f.severity] >= 2 && c.classes.includes(f.class) && c.bug.test(f.title || "");

async function pool(tasks, n) {
  const out = []; let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, tasks.length) }, async () => { while (i < tasks.length) { const k = i++; out[k] = await tasks[k](); } }));
  return out;
}

const results = [];
for (const c of CASES) {
  const sb = await scanner(c.bad, c.file), sg = await scanner(c.good, c.file);
  results.push({ id: c.id, title: c.title, file: c.file, scanner: { caught: sb.some(f => f.inFile), falseAlarm: sg.some(f => f.inFile), bad: sb, good: sg }, agent: [] });
}

const RESCORE = arg("--rescore", "");
if (RESCORE) {
  const saved = JSON.parse(fs.readFileSync(RESCORE, "utf8"));
  RUNS = saved.runs || RUNS;
  for (const [k, c] of CASES.entries()) {
    const old = saved.results.find(r => r.id === c.id);
    results[k].agent = (old?.agent || []).map(run => Object.fromEntries(["bad", "good"].map(side => {
      const a = run[side];
      return [side, { ...a, hit: a.findings.some(f => matches(c, f)), other: a.findings.filter(f => !matches(c, f) && SEV[f.severity] >= 2).length }];
    })));
  }
} else if (!SCANNER_ONLY) {
  const tasks = [];
  for (const [k, c] of CASES.entries()) for (let r = 0; r < RUNS; r++) for (const side of ["bad", "good"]) tasks.push(async () => {
    const a = await runAgent(c[side]);
    process.stderr.write(`${c.id} ${side} run ${r + 1}: ${a.ok ? a.findings.length + " findings" : "no JSON"}${a.cost ? ` ($${a.cost.toFixed(2)})` : ""}\n`);
    return { k, r, side, ...a };
  });
  for (const t of await pool(tasks, JOBS)) {
    const c = CASES[t.k], res = results[t.k];
    (res.agent[t.r] ||= {})[t.side] = { ok: t.ok, hit: t.findings.some(f => matches(c, f)), other: t.findings.filter(f => !matches(c, f) && SEV[f.severity] >= 2).length, findings: t.findings, cost: t.cost, error: t.error };
  }
}

// ---- report ------------------------------------------------------------------------------
const pct = (a, b) => b ? `${(100 * a / b).toFixed(0)}%` : "–";
const n = CASES.length;
const sCaught = results.filter(r => r.scanner.caught).length, sFalse = results.filter(r => r.scanner.falseAlarm).length;
console.log(`\n${n} cases: authorization and business-logic bugs, each next to a fixed look-alike.\n`);
console.log("| Case | Scanner | Agent: caught | Agent: false alarm on the fix |\n|---|---|---|---|");
for (const r of results) {
  const runs = r.agent.filter(a => a?.bad && a?.good);
  const caught = runs.filter(a => a.bad.hit).length, fa = runs.filter(a => a.good.hit).length;
  console.log(`| ${r.title} | ${r.scanner.caught ? "caught" : "missed"}${r.scanner.falseAlarm ? " (also flags the fix)" : ""} | ${SCANNER_ONLY ? "–" : `${caught}/${runs.length}`} | ${SCANNER_ONLY ? "–" : `${fa}/${runs.length}`} |`);
}
const all = results.flatMap(r => r.agent.filter(a => a?.bad && a?.good));
const aCaught = all.filter(a => a.bad.hit).length, aFalse = all.filter(a => a.good.hit).length;
const cost = all.reduce((s, a) => s + (a.bad.cost || 0) + (a.good.cost || 0), 0);
const broken = all.filter(a => !a.bad.ok || !a.good.ok).length;
console.log(`\nScanner alone: caught ${sCaught}/${n} (${pct(sCaught, n)}), flagged ${sFalse}/${n} fixes.`);
if (!SCANNER_ONLY) {
  console.log(`Scanner + agent (${AGENT}, ${RUNS} run${RUNS > 1 ? "s" : ""} per case): caught ${aCaught}/${all.length} (${pct(aCaught, all.length)}), false alarms on the fix ${aFalse}/${all.length} (${pct(aFalse, all.length)}).`);
  console.log(`Other findings at medium or above: ${all.reduce((s, a) => s + a.bad.other, 0)} on vulnerable apps, ${all.reduce((s, a) => s + a.good.other, 0)} on fixed ones. Runs without a parsable answer: ${broken}. Agent cost: $${cost.toFixed(2)}.`);
}
if (OUT) {
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify({ date: new Date().toISOString().slice(0, 10), agent: SCANNER_ONLY ? null : AGENT, runs: RUNS, results }, null, 2) + "\n");
  console.log(`\nWrote ${OUT}`);
}
