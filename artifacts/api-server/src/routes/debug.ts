import { Router } from "express";
import { execSync } from "child_process";
import { readFileSync, existsSync } from "fs";
import { join } from "path";
import axios from "axios";
import { optionalAuth } from "../middleware/auth.js";
import { logSecurityEvent } from "../middleware/requestLogger.js";

const router = Router();

// ─── PING (Command Injection) ──────────────────────────────────
// [VULN-A03] Command injection via host parameter
// Payload: host=127.0.0.1;cat /etc/passwd
// Payload: host=127.0.0.1 && id
// Payload: host=127.0.0.1 | ls -la /
router.get("/ping", optionalAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { host } = req.query as Record<string, string>;
  if (!host) { res.status(400).json({ output: "", error: "host param required" }); return; }

  if (mode === "vulnerable") {
    try {
      await logSecurityEvent("command_injection_attempt", `Ping executed: ${host}`, req.user?.id, req.user?.username, "high");
      const output = execSync(`ping -c 2 ${host} 2>&1`, { timeout: 8000 }).toString();
      res.json({ output });
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : "Command failed";
      const stdout = (err as { stdout?: Buffer }).stdout?.toString() ?? "";
      res.json({ output: stdout, error: errMsg });
    }
  } else {
    // [FIX] Validate host is a valid hostname/IP, no shell metacharacters
    const safe = /^[a-zA-Z0-9.\-]{1,253}$/.test(host);
    if (!safe) {
      res.status(400).json({ output: "", error: "Invalid host. Only alphanumeric, dots, and hyphens allowed." });
      return;
    }
    try {
      const output = execSync(`ping -c 2 ${host} 2>&1`, { timeout: 8000 }).toString();
      res.json({ output });
    } catch {
      res.json({ output: "", error: "Ping failed or host unreachable" });
    }
  }
});

// ─── EVAL (Remote Code Execution) ─────────────────────────────
// [VULN-A08] Remote code execution via eval
// Payload: {"code": "require('child_process').execSync('id').toString()"}
// Payload: {"code": "process.env"}
// Payload: {"code": "require('fs').readdirSync('/')"}
router.post("/eval", optionalAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { code } = req.body ?? {};

  if (mode === "vulnerable") {
    await logSecurityEvent("rce_attempt", `Eval executed: ${String(code).slice(0, 200)}`, req.user?.id, req.user?.username, "critical" as string);
    try {
      // eslint-disable-next-line no-eval
      const result = eval(String(code));
      res.json({ output: String(result) });
    } catch (err: unknown) {
      res.json({ output: "", error: err instanceof Error ? err.message : "Eval error" });
    }
  } else {
    // [FIX] Endpoint disabled in hardened mode
    res.status(403).json({ output: "", error: "This endpoint is disabled in hardened mode." });
  }
});

// ─── ENV (Sensitive Data Exposure) ────────────────────────────
// [VULN-A05] Exposes all environment variables — DATABASE_URL, secrets, keys
router.get("/env", optionalAuth, async (req, res) => {
  const mode = req.securityMode!;

  if (mode === "vulnerable") {
    await logSecurityEvent("sensitive_data_exposure", "Environment variables accessed", req.user?.id, req.user?.username, "high");
    res.json({ output: JSON.stringify(process.env, null, 2) });
  } else {
    // [FIX] Only non-sensitive env vars
    const safe = {
      NODE_ENV: process.env.NODE_ENV,
      PORT: process.env.PORT,
      BASE_PATH: process.env.BASE_PATH,
    };
    res.json({ output: JSON.stringify(safe, null, 2) });
  }
});

// ─── VERSION (Package Disclosure) ─────────────────────────────
// [VULN-A05] Exposes package.json — versions can be used to find CVEs
router.get("/version", optionalAuth, async (req, res) => {
  const mode = req.securityMode!;
  if (mode === "vulnerable") {
    try {
      const pkgPath = join(process.cwd(), "package.json");
      const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
      res.json({ output: JSON.stringify({ name: pkg.name, version: pkg.version, dependencies: pkg.dependencies, devDependencies: pkg.devDependencies }, null, 2) });
    } catch {
      res.json({ output: "Could not read package.json" });
    }
  } else {
    res.json({ output: `VulnLab Pro API v1.0.0 (hardened mode)` });
  }
});

// ─── WEBHOOK (SSRF) ───────────────────────────────────────────
// [VULN-A10] SSRF via user-controlled webhook URL
// Payload: {"url":"http://localhost:5000/api/admin/users","payload":{}}
router.post("/webhooks/test", optionalAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { url, payload } = req.body ?? {};

  if (!url) { res.status(400).json({ error: "url required", ok: false }); return; }

  if (mode === "vulnerable") {
    await logSecurityEvent("ssrf_attempt", `Webhook fired to: ${url}`, req.user?.id, req.user?.username, "high");
    try {
      const response = await axios.post(url as string, payload ?? {}, { timeout: 5000 });
      res.json({ ok: true, message: `Webhook sent. Status: ${response.status}` });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Webhook failed";
      res.json({ ok: false, message: msg });
    }
  } else {
    try {
      const u = new URL(url as string);
      const blocked = ["localhost", "127.0.0.1", "0.0.0.0", "169.254.", "10.", "192.168.", "172."];
      if (!["http:", "https:"].includes(u.protocol) || blocked.some((b) => u.hostname.startsWith(b))) {
        res.status(400).json({ ok: false, message: "Internal URLs not allowed" });
        return;
      }
      const response = await axios.post(url as string, payload ?? {}, { timeout: 5000 });
      res.json({ ok: true, message: `Webhook sent. Status: ${response.status}` });
    } catch {
      res.json({ ok: false, message: "Webhook failed" });
    }
  }
});

// ─── OPEN REDIRECT ────────────────────────────────────────────
// [VULN-A01] Open redirect — no validation on redirect URL
// Payload: /api/redirect?url=https://evil.com
router.get("/redirect", (req, res) => {
  const mode = req.securityMode!;
  const { url } = req.query as Record<string, string>;
  if (!url) { res.status(400).send("url required"); return; }

  if (mode === "vulnerable") {
    res.redirect(url);
  } else {
    // [FIX] Only allow relative or same-origin redirects
    if (url.startsWith("/") && !url.startsWith("//")) {
      res.redirect(url);
    } else {
      res.status(400).json({ error: "Only relative redirects are allowed" });
    }
  }
});

// ─── PATH TRAVERSAL ───────────────────────────────────────────
// [VULN-A01] Path traversal via filename — allows reading arbitrary files
// Payload: /api/files/download?name=../../etc/passwd
// Payload: /api/files/download?name=../../.env
router.get("/files/download", optionalAuth, async (req, res) => {
  const mode = req.securityMode!;
  const { name } = req.query as Record<string, string>;
  if (!name) { res.status(400).json({ error: "name required" }); return; }

  if (mode === "vulnerable") {
    await logSecurityEvent("path_traversal_attempt", `File access: ${name}`, req.user?.id, req.user?.username, "high");
    try {
      // [VULN] No path normalization — arbitrary file read
      const filePath = join(process.cwd(), "uploads", name);
      if (!existsSync(filePath)) {
        // Still try the raw path for educational purposes
        const rawPath = join("/", name.replace(/\.\.\//g, "../"));
        const content = readFileSync(rawPath, "utf8").slice(0, 10000);
        res.json({ content });
        return;
      }
      const content = readFileSync(filePath, "utf8");
      res.json({ content });
    } catch (err) {
      res.status(404).json({ error: "File not found" });
    }
  } else {
    // [FIX] Only allow files within uploads directory
    const uploadsDir = join(process.cwd(), "uploads");
    const safePath = join(uploadsDir, name);
    if (!safePath.startsWith(uploadsDir)) {
      res.status(400).json({ error: "Path traversal detected" });
      return;
    }
    if (!existsSync(safePath)) { res.status(404).json({ error: "File not found" }); return; }
    const content = readFileSync(safePath, "utf8");
    res.json({ content });
  }
});

export default router;
