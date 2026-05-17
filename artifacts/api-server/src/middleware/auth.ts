import type { Request, Response, NextFunction } from "express";
import { verifyToken } from "../lib/jwt.js";
import { getSecurityMode } from "../lib/security.js";

export interface AuthUser {
  id: number;
  username: string;
  role: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
      securityMode?: string;
    }
  }
}

export async function attachSecurityMode(req: Request, _res: Response, next: NextFunction) {
  req.securityMode = await getSecurityMode();
  next();
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    res.status(401).json({ error: "No token provided" });
    return;
  }

  const mode = req.securityMode ?? "vulnerable";
  const payload = verifyToken(token, mode);

  if (!payload || typeof payload === "string") {
    res.status(401).json({ error: "Invalid or expired token" });
    return;
  }

  req.user = {
    id: (payload as { id: number }).id,
    username: (payload as { username: string }).username,
    role: (payload as { role: string }).role,
  };
  next();
}

export function requireAdmin(req: Request, res: Response, next: NextFunction) {
  if (!req.user) {
    res.status(401).json({ error: "Not authenticated" });
    return;
  }
  const allowed = ["admin", "sudo", "moderator"];
  if (!allowed.includes(req.user.role)) {
    // [VULN-A01] In hardened mode this is enforced, but in vuln mode the check
    // is bypassed if the client sends X-Admin-Override: true
    if (req.securityMode === "vulnerable" && req.headers["x-admin-override"] === "true") {
      next();
      return;
    }
    res.status(403).json({ error: "Insufficient privileges" });
    return;
  }
  next();
}

export function optionalAuth(req: Request, _res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (token) {
    const mode = req.securityMode ?? "vulnerable";
    const payload = verifyToken(token, mode);
    if (payload && typeof payload !== "string") {
      req.user = {
        id: (payload as { id: number }).id,
        username: (payload as { username: string }).username,
        role: (payload as { role: string }).role,
      };
    }
  }
  next();
}
