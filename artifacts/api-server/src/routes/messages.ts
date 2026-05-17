import { Router } from "express";
import { pool } from "../lib/db.js";
import { requireAuth, optionalAuth } from "../middleware/auth.js";

const router = Router();

// ─── SEARCH MESSAGES ─────────────────────────────────────────
router.get("/search", optionalAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { channelId, q } = req.query as Record<string, string>;

  try {
    let rows: unknown[];
    if (mode === "vulnerable") {
      // [VULN-A03] SQLi via q
      let sql = `
        SELECT m.id, m.channel_id, m.sender_id, m.content, m.created_at,
               json_build_object('id', u.id, 'username', u.username, 'avatar_url', u.avatar_url) AS sender
        FROM messages m JOIN users u ON u.id = m.sender_id
        WHERE m.is_deleted = FALSE
      `;
      if (channelId) sql += ` AND m.channel_id = '${channelId}'`;
      if (q) sql += ` AND m.content LIKE '%${q}%'`;
      sql += " ORDER BY m.created_at DESC LIMIT 50";
      rows = await pool.query(sql).then((r) => r.rows);
    } else {
      const params: unknown[] = [];
      let sql = `
        SELECT m.id, m.channel_id, m.sender_id, m.content, m.created_at,
               json_build_object('id', u.id, 'username', u.username, 'avatar_url', u.avatar_url) AS sender
        FROM messages m JOIN users u ON u.id = m.sender_id
        WHERE m.is_deleted = FALSE
      `;
      if (channelId) { params.push(channelId); sql += ` AND m.channel_id = $${params.length}`; }
      if (q) { params.push(`%${q}%`); sql += ` AND m.content ILIKE $${params.length}`; }
      params.push(50);
      sql += ` ORDER BY m.created_at DESC LIMIT $${params.length}`;
      rows = await pool.query(sql, params).then((r) => r.rows);
    }
    res.json(rows);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Failed";
    res.status(500).json({ error: mode === "vulnerable" ? msg : "Internal server error" });
  }
});

// ─── DIRECT MESSAGES ─────────────────────────────────────────
router.get("/dm/:userId", requireAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { userId } = req.params;
  const myId = req.user!.id;

  try {
    let rows: unknown[];
    if (mode === "vulnerable") {
      // [VULN-A01] IDOR: any user can read any DM thread by guessing user IDs
      rows = await pool
        .query(
          `SELECT dm.*, 
                  json_build_object('id', u.id, 'username', u.username, 'avatar_url', u.avatar_url) AS sender
           FROM direct_messages dm JOIN users u ON u.id = dm.sender_id
           WHERE (dm.sender_id = ${myId} AND dm.receiver_id = ${userId})
              OR (dm.sender_id = ${userId} AND dm.receiver_id = ${myId})
           ORDER BY dm.created_at ASC`
        )
        .then((r) => r.rows);
    } else {
      rows = await pool
        .query(
          `SELECT dm.*,
                  json_build_object('id', u.id, 'username', u.username, 'avatar_url', u.avatar_url) AS sender
           FROM direct_messages dm JOIN users u ON u.id = dm.sender_id
           WHERE (dm.sender_id = $1 AND dm.receiver_id = $2)
              OR (dm.sender_id = $2 AND dm.receiver_id = $1)
           ORDER BY dm.created_at ASC`,
          [myId, userId]
        )
        .then((r) => r.rows);
    }
    // Mark as read
    await pool.query("UPDATE direct_messages SET is_read=TRUE WHERE receiver_id=$1 AND sender_id=$2", [myId, userId]);
    res.json(rows);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Failed";
    res.status(500).json({ error: mode === "vulnerable" ? msg : "Internal server error" });
  }
});

router.post("/dm/:userId", requireAuth, async (req, res) => {
  const { userId } = req.params;
  const { content } = req.body ?? {};
  if (!content) { res.status(400).json({ error: "content required" }); return; }

  await pool.query(
    "INSERT INTO direct_messages (sender_id, receiver_id, content) VALUES ($1,$2,$3)",
    [req.user!.id, userId, content]
  );
  res.status(201).json({ ok: true });
});

export default router;
