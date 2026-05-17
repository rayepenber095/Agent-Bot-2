import { Router } from "express";
import { pool } from "../lib/db.js";
import { requireAuth, optionalAuth } from "../middleware/auth.js";

const router = Router();

const CHANNEL_SELECT = `
  c.id, c.name, c.slug, c.description, c.is_private, c.created_by, c.created_at,
  json_build_object('id', u.id, 'username', u.username, 'avatar_url', u.avatar_url) AS creator,
  (SELECT COUNT(*) FROM channel_members cm WHERE cm.channel_id = c.id)::int AS member_count,
  (SELECT COUNT(*) FROM messages m WHERE m.channel_id = c.id AND m.is_deleted = FALSE)::int AS message_count
`;

// ─── LIST CHANNELS ────────────────────────────────────────────
router.get("/", optionalAuth, async (req, res) => {
  const mode = req.securityMode!;
  try {
    let rows: unknown[];
    if (mode === "vulnerable") {
      // [VULN-A01] Shows private channels to everyone
      rows = await pool
        .query(`SELECT ${CHANNEL_SELECT} FROM channels c LEFT JOIN users u ON u.id = c.created_by ORDER BY c.id`)
        .then((r) => r.rows);
    } else {
      // [FIX] Private channels only visible to members
      const userId = req.user?.id;
      rows = await pool
        .query(
          `SELECT ${CHANNEL_SELECT} FROM channels c LEFT JOIN users u ON u.id = c.created_by
           WHERE c.is_private = FALSE OR c.id IN (
             SELECT channel_id FROM channel_members WHERE user_id = $1
           )
           ORDER BY c.id`,
          [userId ?? -1]
        )
        .then((r) => r.rows);
    }
    res.json(rows);
  } catch (err: unknown) {
    res.status(500).json({ error: "Failed to list channels" });
  }
});

// ─── GET CHANNEL ──────────────────────────────────────────────
router.get("/:id", optionalAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const rows = await pool
      .query(`SELECT ${CHANNEL_SELECT} FROM channels c LEFT JOIN users u ON u.id = c.created_by WHERE c.id = $1 OR c.slug = $1`, [id])
      .then((r) => r.rows);
    if (!rows.length) { res.status(404).json({ error: "Channel not found" }); return; }
    res.json(rows[0]);
  } catch {
    res.status(500).json({ error: "Failed" });
  }
});

// ─── CREATE CHANNEL ───────────────────────────────────────────
router.post("/", requireAuth, async (req, res) => {
  const { name, description, isPrivate } = req.body ?? {};
  if (!name) { res.status(400).json({ error: "name required" }); return; }
  const slug = (name as string).toLowerCase().replace(/[^a-z0-9]/g, "-").replace(/-+/g, "-");
  try {
    const rows = await pool
      .query(
        `INSERT INTO channels (name, slug, description, is_private, created_by)
         VALUES ($1,$2,$3,$4,$5) RETURNING *`,
        [name, slug, description ?? null, isPrivate ?? false, req.user!.id]
      )
      .then((r) => r.rows);
    // Auto-join creator
    await pool.query("INSERT INTO channel_members (channel_id, user_id, role) VALUES ($1,$2,'owner') ON CONFLICT DO NOTHING", [rows[0].id, req.user!.id]);
    res.status(201).json(rows[0]);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Failed";
    res.status(500).json({ error: msg });
  }
});

// ─── JOIN CHANNEL ─────────────────────────────────────────────
router.post("/:id/join", requireAuth, async (req, res) => {
  const channelId = req.params.id;
  await pool.query("INSERT INTO channel_members (channel_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING", [channelId, req.user!.id]);
  res.json({ ok: true });
});

// ─── LEAVE CHANNEL ────────────────────────────────────────────
router.post("/:id/leave", requireAuth, async (req, res) => {
  const channelId = req.params.id;
  await pool.query("DELETE FROM channel_members WHERE channel_id=$1 AND user_id=$2", [channelId, req.user!.id]);
  res.json({ ok: true });
});

// ─── GET MESSAGES ─────────────────────────────────────────────
router.get("/:id/messages", optionalAuth, async (req, res) => {
  const mode = req.securityMode!;
  const channelId = req.params.id;
  const { limit = "50", offset = "0" } = req.query as Record<string, string>;

  try {
    let rows: unknown[];
    const limitNum = Math.min(parseInt(limit, 10) || 50, 200);
    const offsetNum = parseInt(offset, 10) || 0;

    if (mode === "vulnerable") {
      // [VULN-A07] XSS — content is stored and returned without sanitization
      // [VULN-A01] No channel membership check
      rows = await pool
        .query(
          `SELECT m.id, m.channel_id, m.sender_id, m.content, m.file_url, m.file_name,
                  m.is_deleted, m.is_pinned, m.created_at,
                  json_build_object('id', u.id, 'username', u.username, 'avatar_url', u.avatar_url, 'role', u.role) AS sender
           FROM messages m JOIN users u ON u.id = m.sender_id
           WHERE m.channel_id = ${channelId} AND m.is_deleted = FALSE
           ORDER BY m.created_at DESC LIMIT ${limitNum} OFFSET ${offsetNum}`
        )
        .then((r) => r.rows.reverse());
    } else {
      rows = await pool
        .query(
          `SELECT m.id, m.channel_id, m.sender_id, m.content, m.file_url, m.file_name,
                  m.is_deleted, m.is_pinned, m.created_at,
                  json_build_object('id', u.id, 'username', u.username, 'avatar_url', u.avatar_url, 'role', u.role) AS sender
           FROM messages m JOIN users u ON u.id = m.sender_id
           WHERE m.channel_id = $1 AND m.is_deleted = FALSE
           ORDER BY m.created_at DESC LIMIT $2 OFFSET $3`,
          [channelId, limitNum, offsetNum]
        )
        .then((r) => r.rows.reverse());
    }
    res.json(rows);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Failed";
    res.status(500).json({ error: mode === "vulnerable" ? msg : "Internal server error" });
  }
});

// ─── SEND MESSAGE ─────────────────────────────────────────────
router.post("/:id/messages", requireAuth, async (req, res) => {
  const mode = req.securityMode!;
  const channelId = req.params.id;
  const { content, fileUrl } = req.body ?? {};

  if (!content) { res.status(400).json({ error: "content required" }); return; }

  try {
    let messageContent = content as string;

    if (mode === "hardened") {
      // [FIX-A07] Sanitize XSS — strip script tags and dangerous attributes
      messageContent = messageContent
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "[REMOVED]")
        .replace(/javascript:/gi, "[REMOVED]")
        .replace(/on\w+\s*=/gi, "[REMOVED]");
    }
    // In vulnerable mode: stored XSS — content saved as-is

    const rows = await pool
      .query(
        `INSERT INTO messages (channel_id, sender_id, content, file_url)
         VALUES ($1,$2,$3,$4)
         RETURNING id, channel_id, sender_id, content, file_url, file_name, is_deleted, is_pinned, created_at`,
        [channelId, req.user!.id, messageContent, fileUrl ?? null]
      )
      .then((r) => r.rows);

    const msg = rows[0] as Record<string, unknown>;
    msg.sender = { id: req.user!.id, username: req.user!.username, role: req.user!.role };
    res.status(201).json(msg);
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : "Failed";
    res.status(500).json({ error: mode === "vulnerable" ? errMsg : "Internal server error" });
  }
});

export default router;
