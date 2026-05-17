import { Router } from "express";
import { pool, withTransaction } from "../lib/db.js";
import { requireAuth } from "../middleware/auth.js";
import { logSecurityEvent } from "../middleware/requestLogger.js";

const router = Router();

const TX_SELECT = `
  t.id, t.sender_id, t.receiver_id, t.amount, t.type, t.status, t.note, t.reference, t.created_at,
  json_build_object('id', s.id, 'username', s.username, 'avatar_url', s.avatar_url) AS sender,
  json_build_object('id', r.id, 'username', r.username, 'avatar_url', r.avatar_url) AS receiver
`;

// ─── LIST TRANSACTIONS ────────────────────────────────────────
router.get("/", requireAuth, async (req, res) => {
  const mode = req.securityMode!;
  const userId = req.user!.id;

  try {
    let rows: unknown[];
    if (mode === "vulnerable") {
      // [VULN-A01] IDOR — user_id param overrideable from query string
      const uid = (req.query.userId as string) ?? userId;
      rows = await pool
        .query(
          `SELECT ${TX_SELECT} FROM transactions t
           LEFT JOIN users s ON s.id = t.sender_id
           LEFT JOIN users r ON r.id = t.receiver_id
           WHERE t.sender_id = ${uid} OR t.receiver_id = ${uid}
           ORDER BY t.created_at DESC LIMIT 50`
        )
        .then((r) => r.rows);
    } else {
      rows = await pool
        .query(
          `SELECT ${TX_SELECT} FROM transactions t
           LEFT JOIN users s ON s.id = t.sender_id
           LEFT JOIN users r ON r.id = t.receiver_id
           WHERE t.sender_id = $1 OR t.receiver_id = $1
           ORDER BY t.created_at DESC LIMIT 50`,
          [userId]
        )
        .then((r) => r.rows);
    }
    res.json(rows);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Failed";
    res.status(500).json({ error: mode === "vulnerable" ? msg : "Internal server error" });
  }
});

// ─── GET TRANSACTION ──────────────────────────────────────────
router.get("/:id", requireAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { id } = req.params;
  const userId = req.user!.id;

  try {
    const rows = await pool
      .query(
        `SELECT ${TX_SELECT} FROM transactions t
         LEFT JOIN users s ON s.id = t.sender_id
         LEFT JOIN users r ON r.id = t.receiver_id
         WHERE t.id = $1`,
        [id]
      )
      .then((r) => r.rows);

    if (!rows.length) { res.status(404).json({ error: "Not found" }); return; }

    const tx = rows[0] as Record<string, unknown>;
    if (mode === "hardened") {
      // [FIX] Only parties to the transaction can view it
      if (tx.sender_id !== userId && tx.receiver_id !== userId) {
        res.status(403).json({ error: "Access denied" });
        return;
      }
    }
    res.json(tx);
  } catch (err: unknown) {
    res.status(500).json({ error: "Failed" });
  }
});

// ─── TRANSFER ─────────────────────────────────────────────────
router.post("/transfer", requireAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { toUsername, amount, note } = req.body ?? {};
  const senderId = req.user!.id;

  if (!toUsername || amount === undefined) {
    res.status(400).json({ error: "toUsername and amount are required" });
    return;
  }

  const amountNum = parseFloat(String(amount));

  try {
    if (mode === "vulnerable") {
      // [VULN-A04] Business Logic Flaws:
      // 1. Negative amount → steal money from recipient
      // 2. No balance check → go negative
      // 3. No rate limit → concurrent transfers (race condition)
      // 4. Can transfer to yourself
      const receiver = await pool
        .query(`SELECT id, username, balance FROM users WHERE username = '${toUsername}'`)
        .then((r) => r.rows[0]);

      if (!receiver) { res.status(404).json({ error: "Recipient not found" }); return; }

      // [VULN] No balance validation, no amount sign check
      await pool.query("UPDATE users SET balance = balance - $1 WHERE id = $2", [amountNum, senderId]);
      await pool.query("UPDATE users SET balance = balance + $1 WHERE id = $2", [amountNum, receiver.id]);

      const ref = `TXN-${Date.now()}`;
      const txRows = await pool
        .query(
          "INSERT INTO transactions (sender_id, receiver_id, amount, type, note, reference) VALUES ($1,$2,$3,'transfer',$4,$5) RETURNING *",
          [senderId, receiver.id, amountNum, note ?? null, ref]
        )
        .then((r) => r.rows);

      if (amountNum < 0) {
        await logSecurityEvent("negative_transfer", `User ${req.user!.username} sent negative transfer of $${amountNum} to ${toUsername}`, senderId, req.user!.username, "high");
      }

      res.json(txRows[0]);
    } else {
      // [FIX] Proper validation with database transaction to prevent race conditions
      if (amountNum <= 0) {
        res.status(400).json({ error: "Amount must be positive" });
        return;
      }
      if (amountNum > 10000) {
        res.status(400).json({ error: "Transfer limit is $10,000" });
        return;
      }

      const result = await withTransaction(async (client) => {
        // [FIX] SELECT FOR UPDATE prevents race condition
        const sender = await client
          .query("SELECT id, balance FROM users WHERE id = $1 FOR UPDATE", [senderId])
          .then((r) => r.rows[0]);

        if (!sender) throw new Error("Sender not found");
        if (parseFloat(sender.balance) < amountNum) throw new Error("Insufficient funds");

        const receiver = await client
          .query("SELECT id FROM users WHERE username = $1 FOR UPDATE", [toUsername])
          .then((r) => r.rows[0]);

        if (!receiver) throw new Error("Recipient not found");
        if (receiver.id === senderId) throw new Error("Cannot transfer to yourself");

        await client.query("UPDATE users SET balance = balance - $1 WHERE id = $2", [amountNum, senderId]);
        await client.query("UPDATE users SET balance = balance + $1 WHERE id = $2", [amountNum, receiver.id]);

        const ref = `TXN-${Date.now()}`;
        const txRows = await client
          .query(
            "INSERT INTO transactions (sender_id, receiver_id, amount, type, note, reference) VALUES ($1,$2,$3,'transfer',$4,$5) RETURNING *",
            [senderId, receiver.id, amountNum, note ?? null, ref]
          )
          .then((r) => r.rows);
        return txRows[0];
      });

      res.json(result);
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Transfer failed";
    res.status(400).json({ error: msg });
  }
});

export default router;
