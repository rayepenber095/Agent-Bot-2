import jwt from "jsonwebtoken";

const WEAK_SECRET = "secret";
const STRONG_SECRET = process.env.JWT_SECRET ?? "very_strong_secret_change_me_in_production_64bytes";

export function signToken(payload: object, mode: string): string {
  if (mode === "vulnerable") {
    // [VULN-A02] Weak JWT secret, no expiry — token is valid forever
    return jwt.sign(payload, WEAK_SECRET);
  } else {
    // [FIX-A02] Strong secret from env, 1h expiry
    return jwt.sign(payload, STRONG_SECRET, { expiresIn: "1h" });
  }
}

export function verifyToken(token: string, mode: string): jwt.JwtPayload | string | null {
  if (mode === "vulnerable") {
    // [VULN-A07] Accept alg:none and weak secret
    try {
      return jwt.verify(token, WEAK_SECRET, { algorithms: ["HS256", "none"] as jwt.Algorithm[] });
    } catch {
      try {
        // Try alg:none — decode without verification
        const decoded = jwt.decode(token, { complete: true });
        if (decoded && (decoded.header as { alg: string }).alg === "none") {
          return decoded.payload as jwt.JwtPayload;
        }
      } catch { /* ignore */ }
      return null;
    }
  } else {
    // [FIX-A07] Only HS256, strong secret
    try {
      return jwt.verify(token, STRONG_SECRET, { algorithms: ["HS256"] }) as jwt.JwtPayload;
    } catch {
      return null;
    }
  }
}
