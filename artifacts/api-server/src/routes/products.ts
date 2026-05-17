import { Router } from "express";
import { pool } from "../lib/db.js";
import { requireAuth, optionalAuth } from "../middleware/auth.js";
import axios from "axios";

const router = Router();

const PRODUCT_SELECT = `
  p.id, p.name, p.description, p.price, p.original_price, p.stock,
  p.category, p.brand, p.sku, p.image_url, p.seller_id, p.is_active,
  p.rating, p.created_at,
  json_build_object('id', u.id, 'username', u.username, 'avatar_url', u.avatar_url) AS seller
`;

// ─── SSRF: Fetch product image ────────────────────────────────
// [VULN-A10] SSRF — imageUrl is fetched server-side without validation
// Payload: {"imageUrl":"http://169.254.169.254/latest/meta-data/"}
// Payload: {"imageUrl":"file:///etc/passwd"}
// Payload: {"imageUrl":"http://localhost:5000/api/admin/users"}
router.post("/fetch-image", requireAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { imageUrl } = req.body ?? {};
  if (!imageUrl) {
    res.status(400).json({ error: "imageUrl required" });
    return;
  }

  if (mode === "vulnerable") {
    try {
      const response = await axios.get(imageUrl as string, {
        responseType: "text",
        timeout: 5000,
        maxRedirects: 5,
      });
      res.json({ url: imageUrl, saved: true, content: String(response.data).slice(0, 2000) });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Fetch failed";
      res.status(400).json({ error: msg });
    }
  } else {
    // [FIX] Only allow http/https, block internal IPs
    try {
      const url = new URL(imageUrl as string);
      if (!["http:", "https:"].includes(url.protocol)) {
        res.status(400).json({ error: "Only http/https URLs are allowed" });
        return;
      }
      const blocklist = ["localhost", "127.0.0.1", "0.0.0.0", "169.254.", "10.", "192.168.", "172.16."];
      if (blocklist.some((b) => url.hostname.startsWith(b) || url.hostname === b.replace(".", ""))) {
        res.status(400).json({ error: "Internal URLs are not allowed" });
        return;
      }
      res.json({ url: imageUrl, saved: true });
    } catch {
      res.status(400).json({ error: "Invalid URL" });
    }
  }
});

// ─── LIST PRODUCTS ────────────────────────────────────────────
router.get("/", optionalAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { search, category, limit = "20", offset = "0" } = req.query as Record<string, string>;

  try {
    let rows: unknown[];
    if (mode === "vulnerable") {
      // [VULN-A03] SQLi via search
      let sql = `SELECT ${PRODUCT_SELECT} FROM products p LEFT JOIN users u ON u.id = p.seller_id WHERE p.is_active = TRUE`;
      if (search) sql += ` AND (p.name LIKE '%${search}%' OR p.description LIKE '%${search}%' OR p.brand LIKE '%${search}%' OR p.category LIKE '%${search}%')`;
      if (category) sql += ` AND p.category = '${category}'`;
      sql += ` ORDER BY p.created_at DESC LIMIT ${limit} OFFSET ${offset}`;
      rows = await pool.query(sql).then((r) => r.rows);
    } else {
      const params: unknown[] = [];
      let sql = `SELECT ${PRODUCT_SELECT} FROM products p LEFT JOIN users u ON u.id = p.seller_id WHERE p.is_active = TRUE`;
      if (search) {
        params.push(`%${search}%`);
        sql += ` AND (p.name ILIKE $${params.length} OR p.description ILIKE $${params.length} OR p.brand ILIKE $${params.length})`;
      }
      if (category) {
        params.push(category);
        sql += ` AND p.category = $${params.length}`;
      }
      params.push(parseInt(limit, 10), parseInt(offset, 10));
      sql += ` ORDER BY p.created_at DESC LIMIT $${params.length - 1} OFFSET $${params.length}`;
      rows = await pool.query(sql, params).then((r) => r.rows);
    }
    res.json(rows);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Failed";
    res.status(500).json({ error: mode === "vulnerable" ? msg : "Internal server error" });
  }
});

// ─── GET PRODUCT ──────────────────────────────────────────────
router.get("/:id", optionalAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { id } = req.params;

  try {
    let rows: unknown[];
    if (mode === "vulnerable") {
      rows = await pool
        .query(`SELECT ${PRODUCT_SELECT} FROM products p LEFT JOIN users u ON u.id = p.seller_id WHERE p.id = ${id}`)
        .then((r) => r.rows);
    } else {
      rows = await pool
        .query(`SELECT ${PRODUCT_SELECT} FROM products p LEFT JOIN users u ON u.id = p.seller_id WHERE p.id = $1`, [id])
        .then((r) => r.rows);
    }
    if (!rows.length) { res.status(404).json({ error: "Product not found" }); return; }
    res.json(rows[0]);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Failed";
    res.status(500).json({ error: mode === "vulnerable" ? msg : "Internal server error" });
  }
});

// ─── CREATE PRODUCT ───────────────────────────────────────────
router.post("/", requireAuth, async (req, res) => {
  const { name, description, price, original_price, stock, category, brand, image_url } = req.body ?? {};
  if (!name || price === undefined || stock === undefined) {
    res.status(400).json({ error: "name, price, and stock are required" });
    return;
  }
  const mode = req.securityMode!;
  const sku = `USR-${req.user!.id}-${Date.now()}`;
  try {
    const rows = await pool
      .query(
        `INSERT INTO products (name, description, price, original_price, stock, category, brand, sku, image_url, seller_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         RETURNING *`,
        [name, description ?? null, price, original_price ?? null, stock, category ?? null, brand ?? null, sku, image_url ?? null, req.user!.id]
      )
      .then((r) => r.rows);
    res.status(201).json(rows[0]);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Failed";
    res.status(500).json({ error: mode === "vulnerable" ? msg : "Internal server error" });
  }
});

// ─── UPDATE PRODUCT ───────────────────────────────────────────
router.put("/:id", requireAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { id } = req.params;
  const { name, description, price, original_price, stock, category, brand, image_url } = req.body ?? {};

  try {
    if (mode === "vulnerable") {
      // [VULN-A01] IDOR — no seller check, anyone can update any product
      const rows = await pool
        .query(
          `UPDATE products SET name=$1, description=$2, price=$3, original_price=$4, stock=$5,
           category=$6, brand=$7, image_url=$8 WHERE id=${id} RETURNING *`,
          [name, description ?? null, price, original_price ?? null, stock, category ?? null, brand ?? null, image_url ?? null]
        )
        .then((r) => r.rows);
      res.json(rows[0]);
    } else {
      // [FIX] Only seller or admin can update
      const check = await pool.query("SELECT seller_id FROM products WHERE id=$1", [id]).then((r) => r.rows);
      if (!check.length) { res.status(404).json({ error: "Product not found" }); return; }
      if (check[0].seller_id !== req.user!.id && !["admin", "sudo"].includes(req.user!.role)) {
        res.status(403).json({ error: "Not authorized to edit this product" });
        return;
      }
      const rows = await pool
        .query(
          `UPDATE products SET name=$1, description=$2, price=$3, original_price=$4, stock=$5,
           category=$6, brand=$7, image_url=$8 WHERE id=$9 RETURNING *`,
          [name, description ?? null, price, original_price ?? null, stock, category ?? null, brand ?? null, image_url ?? null, id]
        )
        .then((r) => r.rows);
      res.json(rows[0]);
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Failed";
    res.status(500).json({ error: mode === "vulnerable" ? msg : "Internal server error" });
  }
});

// ─── DELETE PRODUCT ───────────────────────────────────────────
router.delete("/:id", requireAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { id } = req.params;
  try {
    if (mode === "vulnerable") {
      // [VULN-A01] IDOR — anyone can delete
      await pool.query(`DELETE FROM products WHERE id=${id}`);
    } else {
      const check = await pool.query("SELECT seller_id FROM products WHERE id=$1", [id]).then((r) => r.rows);
      if (!check.length) { res.status(404).json({ error: "Not found" }); return; }
      if (check[0].seller_id !== req.user!.id && !["admin", "sudo"].includes(req.user!.role)) {
        res.status(403).json({ error: "Not authorized" });
        return;
      }
      await pool.query("DELETE FROM products WHERE id=$1", [id]);
    }
    res.json({ ok: true });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Failed";
    res.status(500).json({ error: mode === "vulnerable" ? msg : "Internal server error" });
  }
});

export default router;
