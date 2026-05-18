import { useState } from "react";
import { Link, useLocation } from "wouter";
import { useAuth } from "@/contexts/AuthContext";
import { useSecurity } from "@/contexts/SecurityContext";
import api from "@/lib/axios";
import { useToast } from "@/hooks/use-toast";
import {
  Shield, ShieldAlert, ShieldCheck, Hash, MessageSquare, ShoppingBag,
  TrendingUp, CreditCard, Users, Bug, Settings, LogOut, Menu, X,
  Terminal, ChevronRight, Bell
} from "lucide-react";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { href: "/", label: "Dashboard", icon: TrendingUp, roles: null },
  { href: "/feed", label: "Feed", icon: TrendingUp, roles: null },
  { href: "/channels", label: "Channels", icon: Hash, roles: null },
  { href: "/marketplace", label: "Marketplace", icon: ShoppingBag, roles: null },
  { href: "/wallet", label: "Wallet", icon: CreditCard, roles: null },
  { href: "/users", label: "Users", icon: Users, roles: null },
  { href: "/debug", label: "Debug Lab", icon: Terminal, roles: null },
  { href: "/admin", label: "Admin", icon: Settings, roles: ["admin", "sudo", "moderator"] },
];

export default function Layout({ children }: { children: React.ReactNode }) {
  const { user, logout } = useAuth();
  const { mode, setMode, refetch } = useSecurity();
  const [location] = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const { toast } = useToast();

  const isVuln = mode === "vulnerable";

  const handleToggleMode = async () => {
    const newMode = isVuln ? "hardened" : "vulnerable";
    try {
      await api.post("/admin/security-mode", { mode: newMode });
      setMode(newMode);
      refetch();
      toast({
        title: `Mode switched to ${newMode.toUpperCase()}`,
        description: isVuln
          ? "🔒 All protections enabled. Attacks will be blocked."
          : "⚠️ All protections disabled. All 10 OWASP vulns active.",
        variant: isVuln ? "default" : "destructive",
      });
    } catch {
      toast({ title: "Failed to change mode", variant: "destructive" });
    }
  };

  const filteredNav = NAV_ITEMS.filter(
    (item) => !item.roles || (user && item.roles.includes(user.role))
  );

  return (
    <div className="flex h-screen bg-[#0d1117] text-gray-100 overflow-hidden">
      {/* SIDEBAR */}
      <aside
        className={cn(
          "flex flex-col bg-[#161b22] border-r border-[#30363d] transition-all duration-200 z-20",
          sidebarOpen ? "w-56" : "w-14"
        )}
      >
        {/* Logo */}
        <div className="flex items-center gap-2 px-3 py-4 border-b border-[#30363d]">
          <ShieldAlert className={cn("w-6 h-6 flex-shrink-0", isVuln ? "text-red-500" : "text-green-500")} />
          {sidebarOpen && (
            <span className="font-bold text-sm truncate text-white">VulnLab Pro</span>
          )}
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="ml-auto text-gray-400 hover:text-white"
            data-testid="button-toggle-sidebar"
          >
            {sidebarOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
          </button>
        </div>

        {/* Security Mode Toggle */}
        <div className="px-2 py-3 border-b border-[#30363d]">
          <button
            onClick={handleToggleMode}
            className={cn(
              "w-full flex items-center gap-2 rounded-md px-2 py-2 text-xs font-semibold transition-colors",
              isVuln
                ? "bg-red-900/40 text-red-400 hover:bg-red-900/60 border border-red-800/50"
                : "bg-green-900/40 text-green-400 hover:bg-green-900/60 border border-green-800/50"
            )}
            data-testid="button-security-mode-toggle"
          >
            {isVuln ? <ShieldAlert className="w-4 h-4 flex-shrink-0" /> : <ShieldCheck className="w-4 h-4 flex-shrink-0" />}
            {sidebarOpen && (
              <span className="truncate">{isVuln ? "VULNERABLE" : "HARDENED"}</span>
            )}
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto py-2">
          {filteredNav.map((item) => {
            const active = location === item.href || (item.href !== "/" && location.startsWith(item.href));
            const Icon = item.icon;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "flex items-center gap-3 px-3 py-2 mx-1 rounded-md text-sm transition-colors",
                  active
                    ? "bg-[#21262d] text-white font-medium"
                    : "text-gray-400 hover:text-white hover:bg-[#21262d]"
                )}
                data-testid={`link-nav-${item.label.toLowerCase().replace(/\s+/g, "-")}`}
              >
                <Icon className="w-4 h-4 flex-shrink-0" />
                {sidebarOpen && <span className="truncate">{item.label}</span>}
              </Link>
            );
          })}
        </nav>

        {/* User footer */}
        {user && (
          <div className="border-t border-[#30363d] p-2">
            <Link
              href={`/profile/${user.id}`}
              className="flex items-center gap-2 px-2 py-2 rounded-md hover:bg-[#21262d] transition-colors mb-1"
            >
              <div className="w-7 h-7 rounded-full bg-gradient-to-br from-purple-500 to-blue-500 flex items-center justify-center text-xs font-bold flex-shrink-0">
                {user.username[0].toUpperCase()}
              </div>
              {sidebarOpen && (
                <div className="min-w-0">
                  <p className="text-xs font-medium text-white truncate">{user.username}</p>
                  <p className="text-xs text-gray-500 truncate">{user.role}</p>
                </div>
              )}
            </Link>
            <button
              onClick={logout}
              className="w-full flex items-center gap-2 px-2 py-2 rounded-md text-gray-400 hover:text-red-400 hover:bg-[#21262d] transition-colors text-sm"
              data-testid="button-logout"
            >
              <LogOut className="w-4 h-4 flex-shrink-0" />
              {sidebarOpen && <span>Logout</span>}
            </button>
          </div>
        )}
      </aside>

      {/* MAIN */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top bar */}
        <header className="h-12 bg-[#161b22] border-b border-[#30363d] flex items-center px-4 gap-3 flex-shrink-0">
          <span className="text-sm text-gray-500 font-mono">
            {location === "/" ? "~/dashboard" : `~${location}`}
          </span>
          <div className="ml-auto flex items-center gap-3">
            <span
              className={cn(
                "text-xs font-mono px-2 py-0.5 rounded border",
                isVuln
                  ? "text-red-400 border-red-800/60 bg-red-900/20"
                  : "text-green-400 border-green-800/60 bg-green-900/20"
              )}
              data-testid="text-security-mode-badge"
            >
              {isVuln ? "⚠ VULNERABLE" : "✓ HARDENED"}
            </span>
            {user && (
              <div className="text-xs text-gray-400">
                ${parseFloat(String(user.balance ?? 0)).toFixed(2)}
              </div>
            )}
          </div>
        </header>

        {/* Vulnerability warning banner */}
        {isVuln && (
          <div className="bg-red-950/60 border-b border-red-800/40 px-4 py-1.5 flex items-center gap-2 text-xs text-red-400 flex-shrink-0">
            <ShieldAlert className="w-3.5 h-3.5 flex-shrink-0" />
            <span className="font-mono">
              INTENTIONALLY VULNERABLE MODE — Educational use only. All OWASP Top 10 vulnerabilities are active.
            </span>
          </div>
        )}

        {/* Page content */}
        <main className="flex-1 overflow-y-auto">{children}</main>
      </div>
    </div>
  );
}
