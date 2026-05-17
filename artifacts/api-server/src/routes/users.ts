import { Router } from "express";
import { query, pool } from "../lib/db.js";
import { requireAuth, optionalAuth } from "../middleware/auth.js";

const router = Router();

// ─── LIST USERS ──────────────────────────────────────────────
router.get("/", optionalAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { search, limit = "20", offset = "0" } = req.query as Record<string, string>;

  try {
    let rows: unknown[];

    if (mode === "vulnerable") {
      // [VULN-A03] SQLi via search param — string concatenation
      // Payload: search = ' UNION SELECT id,username,password_plain,ssn,secret_note,role,balance,null,null,null,null,null,null,null,null,null,null FROM users --
      let sql = `
        SELECT id, username, full_name, avatar_url, bio, role, balance, created_at,
               ssn, secret_note, password_plain, email, phone, address,
               is_active, is_locked, failed_logins, last_login
        FROM users
      `;
      if (search) sql += ` WHERE username LIKE '%${search}%' OR full_name LIKE '%${search}%' OR email LIKE '%${search}%'`;
      sql += ` ORDER BY id LIMIT ${limit} OFFSET ${offset}`;
      rows = await pool.query(sql).then((r) => r.rows);
    } else {
      // [FIX] Parameterized, only public fields
      const params: unknown[] = [];
      let sql = "SELECT id, username, full_name, avatar_url, bio, role, created_at FROM users";
      if (search) {
        params.push(`%${search}%`);
        sql += ` WHERE username ILIKE $1 OR full_name ILIKE $1`;
      }
      sql += ` ORDER BY id LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
      params.push(parseInt(limit, 10), parseInt(offset, 10));
      rows = await pool.query(sql, params).then((r) => r.rows);
    }

    res.json(rows);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Failed";
    res.status(500).json({ error: mode === "vulnerable" ? msg : "Internal server error" });
  }
});

// ─── GET USER ────────────────────────────────────────────────
router.get("/:id", optionalAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { id } = req.params;

  try {
    let rows: unknown[];

    if (mode === "vulnerable") {
      // [VULN-A01] IDOR — any user can access any user's full data by ID
      // [VULN] No auth required, full sensitive data exposed
      rows = await pool
        .query(
          `SELECT id, username, email, full_name, avatar_url, bio, phone, address,
                  role, balance, ssn, secret_note, password_plain, is_active,
                  is_locked, failed_logins, last_login, created_at,
                  (SELECT COUNT(*) FROM follows WHERE followed_id = u.id) AS followers_count,
                  (SELECT COUNT(*) FROM follows WHERE follower_id = u.id) AS following_count
           FROM users u
           WHERE u.id = ${id}` // [VULN] Direct interpolation
        )
        .then((r) => r.rows);
    } else {
      // [FIX] Parameterized, only public fields, requires auth to see private fields
      rows = await pool
        .query(
          `SELECT id, username, full_name, avatar_url, bio, role, created_at,
                  (SELECT COUNT(*) FROM follows WHERE followed_id = u.id) AS followers_count,
                  (SELECT COUNT(*) FROM follows WHERE follower_id = u.id) AS following_count
           FROM users u WHERE u.id = $1`,
          [id]
        )
        .then((r) => r.rows);
    }

    if (!rows.length) {
      res.status(404).json({ error: "User not found" });
      return;
    }
    res.json(rows[0]);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Failed";
    res.status(500).json({ error: mode === "vulnerable" ? msg : "Internal server error" });
  }
});

// ─── UPDATE USER ─────────────────────────────────────────────
router.put("/:id", requireAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { id } = req.params;
  const { full_name, bio, phone, address, avatar_url, role } = req.body ?? {};

  try {
    if (mode === "vulnerable") {
      // [VULN-A01] IDOR — any user can update any user's profile
      // [VULN-A08] Mass Assignment — role can be escalated via the body
      const sets: string[] = [];
      const vals: unknown[] = [];
      if (full_name !== undefined) { sets.push(`full_name='${full_name}'`); }
      if (bio !== undefined) { sets.push(`bio='${bio}'`); }
      if (phone !== undefined) { sets.push(`phone='${phone}'`); }
      if (address !== undefined) { sets.push(`address='${address}'`); }
      if (avatar_url !== undefined) { sets.push(`avatar_url='${avatar_url}'`); }
      if (role !== undefined) { sets.push(`role='${role}'`); } // [VULN] privilege escalation

      if (!sets.length) {
        res.status(400).json({ error: "Nothing to update" });
        return;
      }
      const sql = `UPDATE users SET ${sets.join(",")} WHERE id=${id} RETURNING *`;
      const rows = await pool.query(sql).then((r) => r.rows);
      res.json(rows[0]);
    } else {
      // [FIX] Only own profile, only safe fields, parameterized
      if (parseInt(id, 10) !== req.user!.id && !["admin", "sudo"].includes(req.user!.role)) {
        res.status(403).json({ error: "Cannot edit other user's profile" });
        return;
      }
      const rows = await pool
        .query(
          `UPDATE users SET full_name=$1, bio=$2, phone=$3, address=$4, avatar_url=$5, updated_at=NOW()
           WHERE id=$6
           RETURNING id, username, email, full_name, avatar_url, bio, phone, address, role, balance, created_at`,
          [full_name ?? null, bio ?? null, phone ?? null, address ?? null, avatar_url ?? null, id]
        )
        .then((r) => r.rows);
      res.json(rows[0]);
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Failed";
    res.status(500).json({ error: mode === "vulnerable" ? msg : "Internal server error" });
  }
});

// ─── FOLLOW / UNFOLLOW ────────────────────────────────────────
router.post("/:id/follow", requireAuth, async (req, res) => {
  const followedId = parseInt(req.params.id, 10);
  const followerId = req.user!.id;
  if (followedId === followerId) {
    res.status(400).json({ error: "Cannot follow yourself" });
    return;
  }
  await pool
    .query("INSERT INTO follows (follower_id, followed_id) VALUES ($1,$2) ON CONFLICT DO NOTHING", [followerId, followedId])
    .catch(() => {});
  res.json({ ok: true });
});

router.delete("/:id/follow", requireAuth, async (req, res) => {
  const followedId = parseInt(req.params.id, 10);
  const followerId = req.user!.id;
  await pool
    .query("DELETE FROM follows WHERE follower_id=$1 AND followed_id=$2", [followerId, followedId])
    .catch(() => {});
  res.json({ ok: true });
});

export default router;
