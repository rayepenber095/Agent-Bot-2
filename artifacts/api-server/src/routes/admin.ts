import { Router } from "express";
import { pool, query } from "../lib/db.js";
import { requireAuth, requireAdmin } from "../middleware/auth.js";
import { getAppSettings, invalidateSecurityModeCache } from "../lib/security.js";

const router = Router();

// All admin routes require auth + admin role
router.use(requireAuth, requireAdmin);

// ─── LIST ALL USERS (with sensitive data) ─────────────────────
router.get("/users", async (req, res) => {
  const rows = await pool
    .query("SELECT * FROM users ORDER BY id")
    .then((r) => r.rows);
  res.json(rows);
});

// ─── UPDATE BALANCE ───────────────────────────────────────────
router.patch("/users/:id/balance", async (req, res) => {
  const { delta, note } = req.body ?? {};
  if (delta === undefined) { res.status(400).json({ error: "delta required" }); return; }
  const { id } = req.params;

  await pool.query("UPDATE users SET balance = balance + $1 WHERE id = $2", [parseFloat(String(delta)), id]);
  await pool.query(
    "INSERT INTO transactions (receiver_id, amount, type, status, note, reference) VALUES ($1,$2,'admin_adjustment','completed',$3,$4)",
    [id, Math.abs(parseFloat(String(delta))), note ?? "Admin balance adjustment", `ADJ-${Date.now()}`]
  );
  res.json({ ok: true });
});

// ─── UPDATE ROLE ──────────────────────────────────────────────
router.patch("/users/:id/role", async (req, res) => {
  const { role } = req.body ?? {};
  const validRoles = ["user", "seller", "moderator", "admin", "sudo"];
  if (!role || !validRoles.includes(role)) {
    res.status(400).json({ error: `Role must be one of: ${validRoles.join(", ")}` });
    return;
  }
  await pool.query("UPDATE users SET role = $1 WHERE id = $2", [role, req.params.id]);
  res.json({ ok: true });
});

// ─── DELETE USER ──────────────────────────────────────────────
router.delete("/users/:id", async (req, res) => {
  await pool.query("DELETE FROM users WHERE id = $1", [req.params.id]);
  res.json({ ok: true });
});

// ─── LOCK / UNLOCK USER ───────────────────────────────────────
router.post("/users/:id/lock", async (req, res) => {
  await pool.query("UPDATE users SET is_locked = TRUE WHERE id = $1", [req.params.id]);
  res.json({ ok: true });
});

router.post("/users/:id/unlock", async (req, res) => {
  await pool.query("UPDATE users SET is_locked = FALSE, failed_logins = 0 WHERE id = $1", [req.params.id]);
  res.json({ ok: true });
});

// ─── SECURITY MODE ────────────────────────────────────────────
router.post("/security-mode", async (req, res) => {
  const { mode } = req.body ?? {};
  if (!["vulnerable", "hardened"].includes(mode)) {
    res.status(400).json({ error: "mode must be 'vulnerable' or 'hardened'" });
    return;
  }
  await pool.query(
    "UPDATE app_settings SET security_mode = $1, updated_at = NOW(), updated_by = $2 WHERE id = 1",
    [mode, req.user!.id]
  );
  invalidateSecurityModeCache();
  res.json({ ok: true, message: `Security mode set to: ${mode}` });
});

router.get("/security-mode", async (req, res) => {
  const settings = await getAppSettings();
  res.json(settings);
});

// ─── REQUEST LOGS ─────────────────────────────────────────────
router.get("/logs", async (req, res) => {
  const { limit = "100", offset = "0", type } = req.query as Record<string, string>;
  const params: unknown[] = [parseInt(limit, 10) || 100, parseInt(offset, 10) || 0];
  let sql = "SELECT * FROM request_logs";
  if (type) { params.push(type); sql += ` WHERE event_type = $${params.length}`; }
  sql += ` ORDER BY timestamp DESC LIMIT $1 OFFSET $2`;
  const rows = await pool.query(sql, params).then((r) => r.rows);
  res.json(rows);
});

// ─── SECURITY EVENTS ──────────────────────────────────────────
router.get("/security-events", async (req, res) => {
  const { limit = "100", offset = "0" } = req.query as Record<string, string>;
  const rows = await pool
    .query(
      "SELECT * FROM request_logs WHERE is_suspicious = TRUE ORDER BY timestamp DESC LIMIT $1 OFFSET $2",
      [parseInt(limit, 10) || 100, parseInt(offset, 10) || 0]
    )
    .then((r) => r.rows);
  res.json(rows);
});

export default router;
