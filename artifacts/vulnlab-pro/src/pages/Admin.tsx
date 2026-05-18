import { useState } from "react";
import { useAdminListUsers, useGetRequestLogs, useGetSecurityEvents, useAdminDeleteUser, useAdminLockUser, useAdminUnlockUser, useAdminUpdateRole, useAdminUpdateBalance, useSetSecurityMode, getAdminListUsersQueryKey, getGetRequestLogsQueryKey, getGetSecurityModeQueryKey } from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { useSecurity } from "@/contexts/SecurityContext";
import { useAuth } from "@/contexts/AuthContext";
import { Shield, Users, Activity, AlertTriangle, Lock, Unlock, Trash2, ChevronRight, ToggleLeft, ToggleRight } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

export default function Admin() {
  const { mode, setMode, refetch } = useSecurity();
  const { user: me } = useAuth();
  const isVuln = mode === "vulnerable";
  const [tab, setTab] = useState<"users" | "logs" | "events" | "settings">("users");
  const qc = useQueryClient();
  const { toast } = useToast();
  const [balanceDelta, setBalanceDelta] = useState<Record<number, string>>({});
  const [roleUpdate, setRoleUpdate] = useState<Record<number, string>>({});

  const { data: allUsers = [] } = useAdminListUsers();
  const { data: logs = [] } = useGetRequestLogs(
    { limit: 100 },
    { query: { enabled: tab === "logs" } }
  );
  const { data: events = [] } = useGetSecurityEvents(
    { limit: 100 },
    { query: { enabled: tab === "events" } }
  );

  const deleteUser = useAdminDeleteUser();
  const lockUser = useAdminLockUser();
  const unlockUser = useAdminUnlockUser();
  const updateRole = useAdminUpdateRole();
  const updateBalance = useAdminUpdateBalance();
  const setSecurityMode = useSetSecurityMode();

  const handleToggleMode = async () => {
    const newMode = isVuln ? "hardened" : "vulnerable";
    try {
      await setSecurityMode.mutateAsync({ data: { mode: newMode } });
      setMode(newMode as "vulnerable" | "hardened");
      refetch();
      qc.invalidateQueries({ queryKey: getGetSecurityModeQueryKey() });
      toast({ title: `Mode: ${newMode.toUpperCase()}`, description: isVuln ? "Protections enabled" : "All vulns active" });
    } catch {
      toast({ title: "Failed", variant: "destructive" });
    }
  };

  const SEVERITY_COLORS: Record<string, string> = {
    critical: "text-red-400",
    high: "text-orange-400",
    medium: "text-yellow-400",
    low: "text-gray-400",
  };

  const TABS = [
    { id: "users", label: "Users", icon: Users },
    { id: "logs", label: "Request Logs", icon: Activity },
    { id: "events", label: "Security Events", icon: AlertTriangle },
    { id: "settings", label: "Settings", icon: Shield },
  ] as const;

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-white">Admin Panel</h1>
        <p className="text-gray-500 text-sm">Logged in as <span className="text-purple-400">{me?.username}</span> ({me?.role})</p>
      </div>

      {/* Tab Nav */}
      <div className="flex gap-2 border-b border-[#30363d] pb-px">
        {TABS.map((t) => {
          const Icon = t.icon;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={cn(
                "flex items-center gap-1.5 px-3 py-2 text-sm font-medium border-b-2 transition-colors -mb-px",
                tab === t.id
                  ? "border-blue-500 text-white"
                  : "border-transparent text-gray-500 hover:text-white"
              )}
              data-testid={`button-admin-tab-${t.id}`}
            >
              <Icon className="w-4 h-4" />
              {t.label}
            </button>
          );
        })}
      </div>

      {/* USERS TAB */}
      {tab === "users" && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-500 uppercase border-b border-[#30363d]">
                <th className="pb-2 text-left">ID</th>
                <th className="pb-2 text-left">Username</th>
                <th className="pb-2 text-left">Role</th>
                <th className="pb-2 text-left">Balance</th>
                <th className="pb-2 text-left">SSN</th>
                <th className="pb-2 text-left">Password</th>
                <th className="pb-2 text-left">Status</th>
                <th className="pb-2 text-left">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#30363d]">
              {allUsers.map((u) => (
                <tr key={u.id} className="text-xs" data-testid={`row-admin-user-${u.id}`}>
                  <td className="py-2 text-gray-500 font-mono">{u.id}</td>
                  <td className="py-2 text-white font-semibold">{u.username}</td>
                  <td className="py-2">
                    <div className="flex items-center gap-1">
                      <select
                        value={roleUpdate[u.id] ?? u.role}
                        onChange={(e) => setRoleUpdate((prev) => ({ ...prev, [u.id]: e.target.value }))}
                        className="bg-[#21262d] border border-[#30363d] rounded px-1 py-0.5 text-xs text-white"
                        data-testid={`select-role-${u.id}`}
                      >
                        {["user", "seller", "moderator", "admin", "sudo"].map((r) => (
                          <option key={r} value={r}>{r}</option>
                        ))}
                      </select>
                      {roleUpdate[u.id] && roleUpdate[u.id] !== u.role && (
                        <button
                          onClick={async () => {
                            await updateRole.mutateAsync({ id: u.id.toString(), data: { role: roleUpdate[u.id] } });
                            qc.invalidateQueries({ queryKey: getAdminListUsersQueryKey() });
                            toast({ title: "Role updated" });
                          }}
                          className="text-green-400 hover:text-green-300"
                          data-testid={`button-apply-role-${u.id}`}
                        >
                          <ChevronRight className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  </td>
                  <td className="py-2">
                    <div className="flex items-center gap-1">
                      <span className="text-green-400 font-mono">${parseFloat(String(u.balance ?? 0)).toFixed(2)}</span>
                      <input
                        type="number"
                        step="0.01"
                        placeholder="±amt"
                        value={balanceDelta[u.id] ?? ""}
                        onChange={(e) => setBalanceDelta((prev) => ({ ...prev, [u.id]: e.target.value }))}
                        className="w-16 bg-[#21262d] border border-[#30363d] rounded px-1 py-0.5 text-xs text-white"
                        data-testid={`input-balance-delta-${u.id}`}
                      />
                      {balanceDelta[u.id] && (
                        <button
                          onClick={async () => {
                            await updateBalance.mutateAsync({ id: u.id.toString(), data: { delta: parseFloat(balanceDelta[u.id]) } });
                            qc.invalidateQueries({ queryKey: getAdminListUsersQueryKey() });
                            setBalanceDelta((prev) => { const n = { ...prev }; delete n[u.id]; return n; });
                            toast({ title: "Balance updated" });
                          }}
                          className="text-green-400 hover:text-green-300"
                          data-testid={`button-apply-balance-${u.id}`}
                        >
                          <ChevronRight className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  </td>
                  <td className="py-2 text-red-400 font-mono">{u.ssn ?? "—"}</td>
                  <td className="py-2 text-red-400 font-mono">{(u as { password_plain?: string }).password_plain ?? "—"}</td>
                  <td className="py-2">
                    <span className={cn("px-1.5 py-0.5 rounded text-xs font-mono", u.is_locked ? "text-red-400 bg-red-950/30" : "text-green-400 bg-green-950/30")}>
                      {u.is_locked ? "locked" : "active"}
                    </span>
                  </td>
                  <td className="py-2">
                    <div className="flex items-center gap-1">
                      {u.is_locked ? (
                        <button onClick={async () => { await unlockUser.mutateAsync({ id: u.id.toString() }); qc.invalidateQueries({ queryKey: getAdminListUsersQueryKey() }); }}
                          className="text-green-400 hover:text-green-300" title="Unlock" data-testid={`button-unlock-${u.id}`}>
                          <Unlock className="w-3.5 h-3.5" />
                        </button>
                      ) : (
                        <button onClick={async () => { await lockUser.mutateAsync({ id: u.id.toString() }); qc.invalidateQueries({ queryKey: getAdminListUsersQueryKey() }); }}
                          className="text-yellow-400 hover:text-yellow-300" title="Lock" data-testid={`button-lock-${u.id}`}>
                          <Lock className="w-3.5 h-3.5" />
                        </button>
                      )}
                      {u.id !== me?.id && (
                        <button onClick={async () => { await deleteUser.mutateAsync({ id: u.id.toString() }); qc.invalidateQueries({ queryKey: getAdminListUsersQueryKey() }); toast({ title: "User deleted", variant: "destructive" }); }}
                          className="text-red-400 hover:text-red-300" title="Delete" data-testid={`button-delete-user-${u.id}`}>
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* LOGS TAB */}
      {tab === "logs" && (
        <div className="space-y-2">
          {logs.map((log) => (
            <div key={log.id} className={cn("bg-[#161b22] border rounded-lg p-3 text-xs font-mono", log.is_suspicious ? "border-red-800/50" : "border-[#30363d]")} data-testid={`row-log-${log.id}`}>
              <div className="flex items-center gap-3 flex-wrap">
                <span className="text-gray-600">{new Date(log.timestamp).toLocaleTimeString()}</span>
                <span className={cn("font-semibold", SEVERITY_COLORS[log.severity ?? "low"])}>[{(log.severity ?? "low").toUpperCase()}]</span>
                <span className="text-blue-400">{log.method} {log.path}</span>
                {log.username && <span className="text-purple-400">{log.username}</span>}
                {log.status_code && <span className={cn(log.status_code >= 400 ? "text-red-400" : "text-green-400")}>{log.status_code}</span>}
                {log.is_suspicious && <span className="text-red-400">⚠ SUSPICIOUS</span>}
              </div>
              {log.details && <p className="text-yellow-400 mt-1">{log.details}</p>}
            </div>
          ))}
        </div>
      )}

      {/* EVENTS TAB */}
      {tab === "events" && (
        <div className="space-y-2">
          {events.map((ev) => (
            <div key={ev.id} className="bg-[#161b22] border border-red-800/30 rounded-lg p-3 text-xs font-mono" data-testid={`row-event-${ev.id}`}>
              <div className="flex items-center gap-3">
                <AlertTriangle className="w-3 h-3 text-red-400 flex-shrink-0" />
                <span className="text-gray-600">{new Date(ev.timestamp).toLocaleTimeString()}</span>
                <span className="text-red-400 font-semibold">{ev.event_type}</span>
                {ev.username && <span className="text-white">{ev.username}</span>}
                <span className={cn(SEVERITY_COLORS[ev.severity])}>{ev.severity}</span>
              </div>
              {ev.details && <p className="text-gray-400 mt-1 break-all">{ev.details}</p>}
            </div>
          ))}
          {events.length === 0 && <p className="text-gray-600 text-center py-8">No security events recorded yet</p>}
        </div>
      )}

      {/* SETTINGS TAB */}
      {tab === "settings" && (
        <div className="space-y-4 max-w-md">
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5">
            <h3 className="font-semibold text-white mb-1">Security Mode</h3>
            <p className="text-xs text-gray-500 mb-4">
              Toggle between vulnerable (all OWASP Top 10 active) and hardened (all protections enabled) mode.
            </p>
            <button
              onClick={handleToggleMode}
              className={cn(
                "w-full flex items-center justify-between px-4 py-3 rounded-lg border font-medium transition-colors",
                isVuln
                  ? "bg-red-950/40 border-red-800/60 text-red-400 hover:bg-red-950/60"
                  : "bg-green-950/40 border-green-800/60 text-green-400 hover:bg-green-950/60"
              )}
              data-testid="button-admin-toggle-mode"
            >
              <span>Currently: <strong>{mode.toUpperCase()}</strong></span>
              {isVuln ? <ToggleLeft className="w-5 h-5" /> : <ToggleRight className="w-5 h-5" />}
            </button>
            <p className="text-xs text-gray-600 mt-3">
              {isVuln
                ? "Switch to HARDENED to enable: parameterized queries, bcrypt, rate limiting, CSRF tokens, strict CSP, account lockout"
                : "Switch to VULNERABLE to enable: SQLi, XSS, IDOR, RCE, SSRF, weak JWT, no rate limiting, plaintext passwords"
              }
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
