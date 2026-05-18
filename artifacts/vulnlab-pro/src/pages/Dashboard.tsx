import { useAuth } from "@/contexts/AuthContext";
import { useSecurity } from "@/contexts/SecurityContext";
import { useGetSecurityMode, useGetMe } from "@workspace/api-client-react";
import { ShieldAlert, ShieldCheck, Bug, Database, Code, Lock, Unlock, TrendingUp, Users, Hash, ShoppingBag, CreditCard } from "lucide-react";
import { Link } from "wouter";
import { cn } from "@/lib/utils";

const VULNS = [
  { id: "A01", name: "Broken Access Control", desc: "IDOR on /api/users/:id — view any user's SSN, plaintext password, secret note", severity: "critical", endpoint: "GET /api/users/1" },
  { id: "A02", name: "Cryptographic Failures", desc: "JWT signed with 'secret', plaintext passwords stored in DB, no HTTPS enforced", severity: "critical", endpoint: "token alg:none bypass" },
  { id: "A03", name: "Injection (SQLi + Cmdi)", desc: "Auth bypass via ' OR '1'='1' -- | Cmd injection on ping endpoint", severity: "critical", endpoint: "POST /api/auth/login" },
  { id: "A04", name: "Insecure Design", desc: "Negative transfer amounts steal money | Race condition on balance deduct", severity: "high", endpoint: "POST /api/transactions/transfer" },
  { id: "A05", name: "Security Misconfiguration", desc: "/api/debug/env exposes all env vars including DATABASE_URL and secrets", severity: "high", endpoint: "GET /api/debug/env" },
  { id: "A06", name: "Vulnerable Components", desc: "/api/debug/version exposes full package.json with CVE-identifiable versions", severity: "medium", endpoint: "GET /api/debug/version" },
  { id: "A07", name: "Auth & Session Failures", desc: "JWT alg:none accepted | Weak 'secret' key | No token expiry | No brute force lockout", severity: "critical", endpoint: "JWT manipulation" },
  { id: "A08", name: "Integrity Failures", desc: "Mass assignment: PUT /api/users/:id with role=admin escalates privileges. RCE via /api/debug/eval", severity: "critical", endpoint: "PUT /api/users/2 {role:admin}" },
  { id: "A09", name: "Logging Failures", desc: "Stack traces returned to client in errors | Sensitive data in logs accessible via /api/admin/logs", severity: "medium", endpoint: "Server errors" },
  { id: "A10", name: "SSRF", desc: "POST /api/products/fetch-image accepts internal URLs including cloud metadata endpoint", severity: "high", endpoint: "POST /api/products/fetch-image" },
];

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400 border-red-800/50 bg-red-950/30",
  high: "text-orange-400 border-orange-800/50 bg-orange-950/30",
  medium: "text-yellow-400 border-yellow-800/50 bg-yellow-950/30",
  low: "text-blue-400 border-blue-800/50 bg-blue-950/30",
};

const QUICK_LINKS = [
  { href: "/channels", label: "Chat Channels", icon: Hash, desc: "Stored XSS playground" },
  { href: "/marketplace", label: "Marketplace", icon: ShoppingBag, desc: "SQLi product search" },
  { href: "/wallet", label: "Wallet", icon: CreditCard, desc: "Race condition lab" },
  { href: "/feed", label: "Social Feed", icon: TrendingUp, desc: "XSS + IDOR posts" },
  { href: "/users", label: "Users", icon: Users, desc: "IDOR user enumeration" },
  { href: "/debug", label: "Debug Lab", icon: Bug, desc: "RCE, path traversal, SSRF" },
];

export default function Dashboard() {
  const { user } = useAuth();
  const { mode } = useSecurity();
  const isVuln = mode === "vulnerable";

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">
            Welcome back, <span className="text-blue-400">{user?.username}</span>
          </h1>
          <p className="text-gray-500 text-sm mt-1">
            Role: <span className="text-purple-400 font-mono">{user?.role}</span>
            {" · "}Balance: <span className="text-green-400 font-mono">${parseFloat(String(user?.balance ?? 0)).toFixed(2)}</span>
          </p>
        </div>
        <div
          className={cn(
            "flex items-center gap-2 px-4 py-2 rounded-full border text-sm font-semibold",
            isVuln
              ? "bg-red-950/40 border-red-800/60 text-red-400"
              : "bg-green-950/40 border-green-800/60 text-green-400"
          )}
          data-testid="text-dashboard-mode"
        >
          {isVuln ? <Unlock className="w-4 h-4" /> : <Lock className="w-4 h-4" />}
          {isVuln ? "Vulnerable Mode" : "Hardened Mode"}
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: "Balance", value: `$${parseFloat(String(user?.balance ?? 0)).toFixed(2)}`, color: "text-green-400" },
          { label: "Active Vulns", value: isVuln ? "10/10" : "0/10", color: isVuln ? "text-red-400" : "text-green-400" },
          { label: "OWASP Coverage", value: "100%", color: "text-blue-400" },
          { label: "Lab Mode", value: isVuln ? "VULN" : "SAFE", color: isVuln ? "text-red-400" : "text-green-400" },
        ].map((s) => (
          <div key={s.label} className="bg-[#161b22] border border-[#30363d] rounded-xl p-4" data-testid={`card-stat-${s.label.toLowerCase()}`}>
            <p className="text-xs text-gray-500 mb-1">{s.label}</p>
            <p className={cn("text-xl font-bold font-mono", s.color)}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Quick Navigation */}
      <div>
        <h2 className="text-sm font-semibold text-gray-400 mb-3 uppercase tracking-wider">Quick Access</h2>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
          {QUICK_LINKS.map((link) => {
            const Icon = link.icon;
            return (
              <Link
                key={link.href}
                href={link.href}
                className="bg-[#161b22] border border-[#30363d] hover:border-blue-700/60 rounded-xl p-4 transition-colors group"
                data-testid={`link-quick-${link.label.toLowerCase().replace(/\s+/g, "-")}`}
              >
                <Icon className="w-5 h-5 text-blue-400 mb-2 group-hover:scale-110 transition-transform" />
                <p className="text-sm font-medium text-white">{link.label}</p>
                <p className="text-xs text-gray-500 mt-0.5">{link.desc}</p>
              </Link>
            );
          })}
        </div>
      </div>

      {/* OWASP Top 10 */}
      <div>
        <h2 className="text-sm font-semibold text-gray-400 mb-3 uppercase tracking-wider">
          OWASP Top 10 — {isVuln ? "All Active" : "All Protected"}
        </h2>
        <div className="space-y-2">
          {VULNS.map((v) => (
            <div
              key={v.id}
              className="bg-[#161b22] border border-[#30363d] rounded-lg p-3 flex items-start gap-3"
              data-testid={`card-vuln-${v.id}`}
            >
              <div className="flex items-center gap-2 flex-shrink-0 w-10">
                {isVuln
                  ? <Bug className="w-3.5 h-3.5 text-red-500" />
                  : <ShieldCheck className="w-3.5 h-3.5 text-green-500" />
                }
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs font-mono text-gray-500">{v.id}</span>
                  <span className="text-sm font-medium text-white">{v.name}</span>
                  <span className={cn("text-xs px-1.5 py-0.5 rounded border font-mono", SEVERITY_COLORS[v.severity])}>
                    {v.severity}
                  </span>
                </div>
                <p className="text-xs text-gray-500 mt-0.5">{v.desc}</p>
                <code className="text-xs text-blue-400/70 font-mono mt-0.5 block">{v.endpoint}</code>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
