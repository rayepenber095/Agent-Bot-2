import { Router } from "express";
import { pool, withTransaction } from "../lib/db.js";
import { requireAuth } from "../middleware/auth.js";

const router = Router();

// ─── GET CART ─────────────────────────────────────────────────
router.get("/", requireAuth, async (req, res) => {
  const userId = req.user!.id;
  const rows = await pool
    .query(
      `SELECT ci.id, ci.product_id, ci.quantity, ci.added_at,
              json_build_object(
                'id', p.id, 'name', p.name, 'price', p.price, 'original_price', p.original_price,
                'image_url', p.image_url, 'stock', p.stock, 'category', p.category, 'brand', p.brand
              ) AS product
       FROM cart_items ci JOIN products p ON p.id = ci.product_id
       WHERE ci.user_id = $1`,
      [userId]
    )
    .then((r) => r.rows);
  res.json(rows);
});

// ─── ADD TO CART ─────────────────────────────────────────────
router.post("/", requireAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { productId, quantity = 1 } = req.body ?? {};
  if (!productId) { res.status(400).json({ error: "productId required" }); return; }

  const qty = parseInt(String(quantity), 10);

  if (mode === "hardened" && (qty < 1 || qty > 100)) {
    res.status(400).json({ error: "Quantity must be 1-100" });
    return;
  }

  // [VULN-A04] In vulnerable mode: no stock check, can set negative quantity
  await pool.query(
    `INSERT INTO cart_items (user_id, product_id, quantity)
     VALUES ($1,$2,$3)
     ON CONFLICT (user_id, product_id) DO UPDATE SET quantity = cart_items.quantity + $3`,
    [req.user!.id, productId, qty]
  );
  res.json({ ok: true });
});

// ─── REMOVE FROM CART ─────────────────────────────────────────
router.delete("/:productId", requireAuth, async (req, res) => {
  await pool.query("DELETE FROM cart_items WHERE user_id=$1 AND product_id=$2", [req.user!.id, req.params.productId]);
  res.json({ ok: true });
});

// ─── ORDERS ───────────────────────────────────────────────────
router.get("/orders", requireAuth, async (req, res) => {
  const mode = req.securityMode!;
  const userId = req.user!.id;

  let rows: unknown[];
  if (mode === "vulnerable") {
    // [VULN-A01] Override userId via query param
    const uid = (req.query.userId as string) ?? userId;
    rows = await pool
      .query(
        `SELECT o.*, json_agg(json_build_object(
           'id', oi.id, 'product_id', oi.product_id, 'quantity', oi.quantity,
           'price_at_purchase', oi.price_at_purchase,
           'product', json_build_object('name', p.name, 'image_url', p.image_url)
         )) AS items
         FROM orders o JOIN order_items oi ON oi.order_id = o.id LEFT JOIN products p ON p.id = oi.product_id
         WHERE o.buyer_id = ${uid} GROUP BY o.id ORDER BY o.created_at DESC`
      )
      .then((r) => r.rows);
  } else {
    rows = await pool
      .query(
        `SELECT o.*, json_agg(json_build_object(
           'id', oi.id, 'product_id', oi.product_id, 'quantity', oi.quantity,
           'price_at_purchase', oi.price_at_purchase,
           'product', json_build_object('name', p.name, 'image_url', p.image_url)
         )) AS items
         FROM orders o JOIN order_items oi ON oi.order_id = o.id LEFT JOIN products p ON p.id = oi.product_id
         WHERE o.buyer_id = $1 GROUP BY o.id ORDER BY o.created_at DESC`,
        [userId]
      )
      .then((r) => r.rows);
  }
  res.json(rows);
});

router.get("/orders/:id", requireAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { id } = req.params;

  const rows = await pool
    .query(
      `SELECT o.*, json_agg(json_build_object(
         'id', oi.id, 'product_id', oi.product_id, 'quantity', oi.quantity,
         'price_at_purchase', oi.price_at_purchase
       )) AS items
       FROM orders o JOIN order_items oi ON oi.order_id = o.id
       WHERE o.id = $1 GROUP BY o.id`,
      [id]
    )
    .then((r) => r.rows);

  if (!rows.length) { res.status(404).json({ error: "Not found" }); return; }

  const order = rows[0] as Record<string, unknown>;
  if (mode === "hardened" && order.buyer_id !== req.user!.id) {
    res.status(403).json({ error: "Access denied" }); return;
  }
  res.json(order);
});

// ─── CHECKOUT ─────────────────────────────────────────────────
router.post("/orders", requireAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { shippingAddress } = req.body ?? {};
  const userId = req.user!.id;

  try {
    const result = await withTransaction(async (client) => {
      const cartItems = await client
        .query(
          `SELECT ci.*, p.price, p.stock, p.name FROM cart_items ci JOIN products p ON p.id = ci.product_id WHERE ci.user_id = $1`,
          [userId]
        )
        .then((r) => r.rows);

      if (!cartItems.length) throw new Error("Cart is empty");

      let total = 0;
      for (const item of cartItems) {
        if (mode === "hardened" && item.stock < item.quantity) {
          throw new Error(`${item.name} is out of stock`);
        }
        total += parseFloat(item.price) * item.quantity;
      }

      // Deduct from user balance
      const user = await client.query("SELECT balance FROM users WHERE id=$1 FOR UPDATE", [userId]).then((r) => r.rows[0]);
      if (mode === "hardened" && parseFloat(user.balance) < total) {
        throw new Error("Insufficient balance");
      }

      await client.query("UPDATE users SET balance = balance - $1 WHERE id=$2", [total, userId]);

      // Create order
      const order = await client
        .query("INSERT INTO orders (buyer_id, total, status, shipping_address) VALUES ($1,$2,'confirmed',$3) RETURNING *", [userId, total, shippingAddress ?? null])
        .then((r) => r.rows[0]);

      // Create order items & deduct stock
      for (const item of cartItems) {
        await client.query(
          "INSERT INTO order_items (order_id, product_id, quantity, price_at_purchase) VALUES ($1,$2,$3,$4)",
          [order.id, item.product_id, item.quantity, item.price]
        );
        if (mode === "hardened") {
          await client.query("UPDATE products SET stock = stock - $1 WHERE id=$2", [item.quantity, item.product_id]);
        }
      }

      // Create transaction record
      const ref = `ORDER-${order.id}-${Date.now()}`;
      await client.query(
        "INSERT INTO transactions (sender_id, amount, type, status, note, reference) VALUES ($1,$2,'purchase','completed',$3,$4)",
        [userId, total, `Order #${order.id}`, ref]
      );

      // Clear cart
      await client.query("DELETE FROM cart_items WHERE user_id=$1", [userId]);

      return order;
    });

    res.status(201).json(result);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Checkout failed";
    res.status(400).json({ error: msg });
  }
});

export default router;
