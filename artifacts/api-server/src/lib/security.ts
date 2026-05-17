import { query } from "./db.js";

let _cachedMode: string = "vulnerable";
let _cacheTime: number = 0;
const CACHE_TTL_MS = 10_000; // 10 seconds

export async function getSecurityMode(): Promise<string> {
  const now = Date.now();
  if (now - _cacheTime < CACHE_TTL_MS) return _cachedMode;
  try {
    const rows = await query("SELECT security_mode FROM app_settings WHERE id = 1");
    _cachedMode = rows[0]?.security_mode ?? "vulnerable";
    _cacheTime = now;
  } catch {
    // default to vulnerable if DB fails
  }
  return _cachedMode;
}

export function invalidateSecurityModeCache() {
  _cacheTime = 0;
}

export async function getAppSettings() {
  const rows = await query("SELECT * FROM app_settings WHERE id = 1");
  return rows[0] ?? { security_mode: "vulnerable", app_name: "VulnLab Pro", allow_register: true };
}
