import type { Request, Response, NextFunction } from "express";
import { pool } from "../lib/db.js";

const SUSPICIOUS_PATTERNS = [
  /union\s+select/i,
  /'\s*or\s+'1'\s*=\s*'1/i,
  /<script/i,
  /javascript:/i,
  /\.\.\/\.\.\/\.\./i,
  /\beval\s*\(/i,
  /\bexec\s*\(/i,
  /\bpasswd\b/i,
  /\bshadow\b/i,
  /169\.254\./,
  /localhost/i,
  /127\.0\.0\.1/,
];

function isSuspicious(req: Request): boolean {
  const parts = [
    JSON.stringify(req.query),
    JSON.stringify(req.body),
    req.url,
  ].join(" ");
  return SUSPICIOUS_PATTERNS.some((p) => p.test(parts));
}

function getSeverity(statusCode: number, suspicious: boolean): string {
  if (suspicious) return "high";
  if (statusCode >= 500) return "high";
  if (statusCode >= 400) return "medium";
  return "low";
}

export function requestLogger(req: Request, res: Response, next: NextFunction) {
  const start = Date.now();
  const suspicious = isSuspicious(req);

  res.on("finish", () => {
    const duration = Date.now() - start;
    const severity = getSeverity(res.statusCode, suspicious);

    // Fire-and-forget log insertion
    pool
      .query(
        `INSERT INTO request_logs
          (event_type, method, path, query_string, user_id, username, ip_address,
           user_agent, status_code, duration_ms, security_mode, is_suspicious, severity, details)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
        [
          "http_request",
          req.method,
          req.path,
          JSON.stringify(req.query),
          req.user?.id ?? null,
          req.user?.username ?? null,
          req.ip ?? null,
          req.headers["user-agent"] ?? null,
          res.statusCode,
          duration,
          req.securityMode ?? "vulnerable",
          suspicious,
          severity,
          suspicious ? `Suspicious pattern detected in: ${req.url}` : null,
        ]
      )
      .catch(() => { /* silent — don't break the app */ });
  });

  next();
}

export async function logSecurityEvent(
  eventType: string,
  details: string,
  userId?: number,
  username?: string,
  severity: string = "medium"
) {
  await pool
    .query(
      `INSERT INTO request_logs (event_type, user_id, username, is_suspicious, severity, details)
       VALUES ($1,$2,$3,TRUE,$4,$5)`,
      [eventType, userId ?? null, username ?? null, severity, details]
    )
    .catch(() => {});
}
