import { Router } from "express";
import bcrypt from "bcrypt";
import { query, pool } from "../lib/db.js";
import { signToken } from "../lib/jwt.js";
import { requireAuth } from "../middleware/auth.js";
import { logSecurityEvent } from "../middleware/requestLogger.js";

const router = Router();

// ─── REGISTER ────────────────────────────────────────────────
router.post("/register", async (req, res) => {
  const mode = req.securityMode!;
  const { username, email, password } = req.body ?? {};

  if (!username || !email || !password) {
    res.status(400).json({ error: "username, email, and password are required" });
    return;
  }

  try {
    // [FIX-A03] Hardened: parameterized, bcrypt hash, no plaintext storage
    // [VULN-A03] Vulnerable: no input validation, plaintext stored, no rate limit
    let hash: string;
    let rows: unknown[];

    if (mode === "vulnerable") {
      // [VULN] No password strength check, stores plaintext, no uniqueness check before insert
      hash = await bcrypt.hash(password, 8); // low rounds on purpose
      rows = await pool
        .query(
          // [VULN-A03] Error-based SQLi possible on username if not escaped properly
          // (driver still parameterizes, but we simulate the insecure comment for learning)
          `INSERT INTO users (username, email, password, password_plain, role, balance)
           VALUES ($1, $2, $3, $4, 'user', 1000)
           RETURNING id, username, email, role, balance, created_at`,
          [username, email, hash, password]
        )
        .then((r) => r.rows);
    } else {
      // [FIX] Validate input, hash securely, no plaintext
      if (password.length < 8) {
        res.status(400).json({ error: "Password must be at least 8 characters" });
        return;
      }
      if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) {
        res.status(400).json({ error: "Username must be 3-30 alphanumeric characters" });
        return;
      }
      hash = await bcrypt.hash(password, 12);
      rows = await pool
        .query(
          `INSERT INTO users (username, email, password, password_plain, role, balance)
           VALUES ($1, $2, $3, '', 'user', 1000)
           RETURNING id, username, email, role, balance, created_at`,
          [username, email, hash]
        )
        .then((r) => r.rows);
    }

    const user = (rows as { id: number; username: string; role: string }[])[0];
    const token = signToken({ id: user.id, username: user.username, role: user.role }, mode);
    res.json({ token, user, expiresIn: mode === "hardened" ? 3600 : null });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Registration failed";
    if (msg.includes("unique") || msg.includes("duplicate")) {
      res.status(409).json({ error: "Username or email already exists" });
    } else {
      res.status(500).json({ error: msg });
    }
  }
});

// ─── LOGIN ────────────────────────────────────────────────────
router.post("/login", async (req, res) => {
  const mode = req.securityMode!;
  const { username, password } = req.body ?? {};

  if (!username || !password) {
    res.status(400).json({ error: "username and password required" });
    return;
  }

  try {
    let user: Record<string, unknown> | undefined;

    if (mode === "vulnerable") {
      // [VULN-A03] SQL Injection: string concatenation — classic auth bypass
      // Payload: username = admin' OR '1'='1' --
      // Payload: username = ' OR 1=1 LIMIT 1 --
      const sqlInjectable = `
        SELECT id, username, email, password, password_plain, role, balance,
               ssn, secret_note, is_active, is_locked, failed_logins, avatar_url
        FROM users
        WHERE username = '${username}' AND is_active = TRUE
        LIMIT 1
      `;
      const rows = await pool.query(sqlInjectable).then((r) => r.rows);
      user = rows[0];

      if (user) {
        // [VULN] No lockout for brute force
        const valid = await bcrypt.compare(password as string, user.password as string);
        if (!valid) {
          await logSecurityEvent("failed_login", `Failed login for ${username}`, undefined, username as string, "medium");
          res.status(401).json({ error: "Invalid credentials" });
          return;
        }
        // Reset failed logins (no lockout enforcement)
        await pool.query("UPDATE users SET last_login=NOW(), last_ip=$1 WHERE id=$2", [req.ip, user.id]);
      }
    } else {
      // [FIX-A03] Parameterized query
      const rows = await pool
        .query(
          `SELECT id, username, email, password, role, balance, is_active, is_locked,
                  failed_logins, avatar_url
           FROM users
           WHERE username = $1`,
          [username]
        )
        .then((r) => r.rows);
      user = rows[0];

      if (!user) {
        // [FIX] Generic error — don't reveal whether username exists
        res.status(401).json({ error: "Invalid credentials" });
        return;
      }

      // [FIX] Account lockout after 5 failed attempts
      if (user.is_locked) {
        res.status(403).json({ error: "Account locked due to too many failed attempts" });
        return;
      }

      if (!user.is_active) {
        res.status(403).json({ error: "Account disabled" });
        return;
      }

      const valid = await bcrypt.compare(password as string, user.password as string);
      if (!valid) {
        const newFailed = (user.failed_logins as number) + 1;
        const lockNow = newFailed >= 5;
        await pool.query(
          "UPDATE users SET failed_logins=$1, is_locked=$2 WHERE id=$3",
          [newFailed, lockNow, user.id]
        );
        await logSecurityEvent("failed_login", `Failed login attempt ${newFailed}/5 for ${username}`, undefined, username as string, lockNow ? "high" : "medium");
        res.status(401).json({ error: "Invalid credentials" });
        return;
      }

      await pool.query("UPDATE users SET last_login=NOW(), failed_logins=0, last_ip=$1 WHERE id=$2", [req.ip, user.id]);
    }

    if (!user) {
      await logSecurityEvent("failed_login", `User not found: ${username}`, undefined, username as string, "medium");
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }

    const token = signToken({ id: user.id, username: user.username, role: user.role }, mode);

    // [VULN-A02] In vulnerable mode, return sensitive fields
    const responseUser = mode === "vulnerable"
      ? user
      : { id: user.id, username: user.username, email: user.email, role: user.role, balance: user.balance, avatar_url: user.avatar_url, is_active: user.is_active, is_locked: user.is_locked, failed_logins: user.failed_logins, created_at: user.created_at };

    res.json({ token, user: responseUser, expiresIn: mode === "hardened" ? 3600 : null });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Login failed";
    // [VULN] In vulnerable mode, expose DB errors to reveal schema
    if (mode === "vulnerable") {
      res.status(500).json({ error: msg });
    } else {
      res.status(500).json({ error: "Internal server error" });
    }
  }
});

// ─── LOGOUT ──────────────────────────────────────────────────
router.post("/logout", (req, res) => {
  // Stateless JWT — just tell client to discard
  res.json({ ok: true, message: "Logged out" });
});

// ─── ME ──────────────────────────────────────────────────────
router.get("/me", requireAuth, async (req, res) => {
  const mode = req.securityMode!;
  const userId = req.user!.id;

  try {
    let fields = "id, username, email, full_name, avatar_url, bio, phone, address, role, balance, is_active, is_locked, failed_logins, last_login, created_at";
    if (mode === "vulnerable") {
      // [VULN-A01] Expose sensitive fields to any authenticated user
      fields += ", ssn, secret_note, password_plain";
    }

    const rows = await query(`SELECT ${fields} FROM users WHERE id = $1`, [userId]);
    if (!rows[0]) {
      res.status(404).json({ error: "User not found" });
      return;
    }
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch user" });
  }
});

export default router;
