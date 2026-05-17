import { Router } from "express";
import { pool } from "../lib/db.js";
import { requireAuth, optionalAuth } from "../middleware/auth.js";

const router = Router();

const POST_SELECT = (userId: number | null) => `
  p.id, p.author_id, p.content, p.image_url, p.created_at,
  json_build_object('id', u.id, 'username', u.username, 'avatar_url', u.avatar_url, 'full_name', u.full_name) AS author,
  (SELECT COUNT(*) FROM post_likes pl WHERE pl.post_id = p.id)::int AS like_count,
  (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id)::int AS comment_count,
  ${userId ? `(SELECT COUNT(*) > 0 FROM post_likes pl WHERE pl.post_id = p.id AND pl.user_id = ${userId})` : "FALSE"} AS liked_by_me
`;

// ─── FEED ────────────────────────────────────────────────────
router.get("/feed", optionalAuth, async (req, res) => {
  const { limit = "20", offset = "0" } = req.query as Record<string, string>;
  const userId = req.user?.id ?? null;
  const mode = req.securityMode!;

  try {
    let rows: unknown[];
    const limitNum = Math.min(parseInt(limit, 10) || 20, 100);
    const offsetNum = parseInt(offset, 10) || 0;

    if (mode === "vulnerable") {
      rows = await pool
        .query(
          `SELECT ${POST_SELECT(userId)} FROM posts p JOIN users u ON u.id = p.author_id
           ORDER BY p.created_at DESC LIMIT ${limitNum} OFFSET ${offsetNum}`
        )
        .then((r) => r.rows);
    } else {
      rows = await pool
        .query(
          `SELECT p.id, p.author_id, p.content, p.image_url, p.created_at,
                  json_build_object('id', u.id, 'username', u.username, 'avatar_url', u.avatar_url, 'full_name', u.full_name) AS author,
                  (SELECT COUNT(*) FROM post_likes pl WHERE pl.post_id = p.id)::int AS like_count,
                  (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id)::int AS comment_count,
                  ${userId ? `(SELECT COUNT(*) > 0 FROM post_likes pl WHERE pl.post_id = p.id AND pl.user_id = $3)` : "FALSE"} AS liked_by_me
           FROM posts p JOIN users u ON u.id = p.author_id
           ORDER BY p.created_at DESC LIMIT $1 OFFSET $2`,
          userId ? [limitNum, offsetNum, userId] : [limitNum, offsetNum]
        )
        .then((r) => r.rows);
    }
    res.json(rows);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Failed";
    res.status(500).json({ error: mode === "vulnerable" ? msg : "Internal server error" });
  }
});

// ─── CREATE POST ─────────────────────────────────────────────
router.post("/posts", requireAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { content, imageUrl } = req.body ?? {};
  if (!content) { res.status(400).json({ error: "content required" }); return; }

  let postContent = content as string;
  if (mode === "hardened") {
    postContent = postContent
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "[REMOVED]")
      .replace(/javascript:/gi, "[REMOVED]")
      .replace(/on\w+\s*=/gi, "[REMOVED]");
  }

  const rows = await pool
    .query(
      `INSERT INTO posts (author_id, content, image_url) VALUES ($1,$2,$3)
       RETURNING id, author_id, content, image_url, created_at`,
      [req.user!.id, postContent, imageUrl ?? null]
    )
    .then((r) => r.rows);

  const post = rows[0] as Record<string, unknown>;
  post.author = { id: req.user!.id, username: req.user!.username };
  post.like_count = 0;
  post.comment_count = 0;
  post.liked_by_me = false;
  res.status(201).json(post);
});

// ─── GET POST ─────────────────────────────────────────────────
router.get("/posts/:id", optionalAuth, async (req, res) => {
  const userId = req.user?.id ?? null;
  const rows = await pool
    .query(
      `SELECT p.id, p.author_id, p.content, p.image_url, p.created_at,
              json_build_object('id', u.id, 'username', u.username, 'avatar_url', u.avatar_url) AS author,
              (SELECT COUNT(*) FROM post_likes pl WHERE pl.post_id = p.id)::int AS like_count,
              (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id)::int AS comment_count,
              ${userId ? `(SELECT COUNT(*) > 0 FROM post_likes pl WHERE pl.post_id = p.id AND pl.user_id = $2)` : "FALSE"} AS liked_by_me
       FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id = $1`,
      userId ? [req.params.id, userId] : [req.params.id]
    )
    .then((r) => r.rows);
  if (!rows.length) { res.status(404).json({ error: "Post not found" }); return; }
  res.json(rows[0]);
});

// ─── DELETE POST ─────────────────────────────────────────────
router.delete("/posts/:id", requireAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { id } = req.params;

  if (mode === "vulnerable") {
    // [VULN-A01] IDOR — anyone can delete anyone's post
    await pool.query(`DELETE FROM posts WHERE id=${id}`);
  } else {
    const rows = await pool.query("SELECT author_id FROM posts WHERE id=$1", [id]).then((r) => r.rows);
    if (!rows.length) { res.status(404).json({ error: "Not found" }); return; }
    if (rows[0].author_id !== req.user!.id && !["admin", "sudo", "moderator"].includes(req.user!.role)) {
      res.status(403).json({ error: "Not authorized" }); return;
    }
    await pool.query("DELETE FROM posts WHERE id=$1", [id]);
  }
  res.json({ ok: true });
});

// ─── LIKE POST ───────────────────────────────────────────────
router.post("/posts/:id/like", requireAuth, async (req, res) => {
  const postId = parseInt(req.params.id, 10);
  const userId = req.user!.id;
  const existing = await pool.query("SELECT 1 FROM post_likes WHERE post_id=$1 AND user_id=$2", [postId, userId]).then((r) => r.rows);
  if (existing.length) {
    await pool.query("DELETE FROM post_likes WHERE post_id=$1 AND user_id=$2", [postId, userId]);
    res.json({ ok: true, liked: false });
  } else {
    await pool.query("INSERT INTO post_likes (post_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING", [postId, userId]);
    res.json({ ok: true, liked: true });
  }
});

// ─── GET COMMENTS ─────────────────────────────────────────────
router.get("/posts/:id/comments", optionalAuth, async (req, res) => {
  const rows = await pool
    .query(
      `SELECT c.id, c.post_id, c.author_id, c.content, c.created_at,
              json_build_object('id', u.id, 'username', u.username, 'avatar_url', u.avatar_url) AS author
       FROM comments c JOIN users u ON u.id = c.author_id
       WHERE c.post_id = $1 ORDER BY c.created_at ASC`,
      [req.params.id]
    )
    .then((r) => r.rows);
  res.json(rows);
});

// ─── ADD COMMENT ─────────────────────────────────────────────
router.post("/posts/:id/comments", requireAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { content } = req.body ?? {};
  if (!content) { res.status(400).json({ error: "content required" }); return; }

  let commentContent = content as string;
  if (mode === "hardened") {
    commentContent = commentContent.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "[REMOVED]");
  }

  const rows = await pool
    .query(
      `INSERT INTO comments (post_id, author_id, content) VALUES ($1,$2,$3)
       RETURNING id, post_id, author_id, content, created_at`,
      [req.params.id, req.user!.id, commentContent]
    )
    .then((r) => r.rows);

  const comment = rows[0] as Record<string, unknown>;
  comment.author = { id: req.user!.id, username: req.user!.username };
  res.status(201).json(comment);
});

export default router;
