import { useState } from "react";
import { useListUsers, useGetUser, useFollowUser, useUnfollowUser } from "@workspace/api-client-react";
import { useSecurity } from "@/contexts/SecurityContext";
import { useAuth } from "@/contexts/AuthContext";
import { useQueryClient } from "@tanstack/react-query";
import { getListUsersQueryKey } from "@workspace/api-client-react";
import { Search, User, ShieldAlert, Eye, UserPlus, UserMinus, DollarSign } from "lucide-react";
import { cn } from "@/lib/utils";
import type { User as ApiUser } from "@workspace/api-client-react";

export default function Users() {
  const { mode } = useSecurity();
  const { user: me } = useAuth();
  const isVuln = mode === "vulnerable";
  const [search, setSearch] = useState("");
  const [selectedUser, setSelectedUser] = useState<ApiUser | null>(null);
  const [targetId, setTargetId] = useState("");
  const [idorResult, setIdorResult] = useState<ApiUser | null>(null);
  const qc = useQueryClient();

  const { data: users = [], isLoading } = useListUsers({ search: search || undefined });
  const followUser = useFollowUser();
  const unfollowUser = useUnfollowUser();

  const handleIdorFetch = async () => {
    if (!targetId) return;
    try {
      const res = await fetch(`${import.meta.env.BASE_URL?.replace(/\/$/, "")}/api/users/${targetId}`, {
        headers: { Authorization: `Bearer ${localStorage.getItem("token")}` }
      });
      const data = await res.json();
      setIdorResult(data);
    } catch {
      setIdorResult(null);
    }
  };

  const ROLE_COLORS: Record<string, string> = {
    sudo: "text-red-400 bg-red-950/30 border-red-800/40",
    admin: "text-orange-400 bg-orange-950/30 border-orange-800/40",
    moderator: "text-yellow-400 bg-yellow-950/30 border-yellow-800/40",
    seller: "text-blue-400 bg-blue-950/30 border-blue-800/40",
    user: "text-gray-400 bg-gray-900/30 border-gray-700/40",
  };

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Users</h1>
          <p className="text-gray-500 text-sm">{users.length} users found</p>
        </div>
        {isVuln && (
          <div className="flex items-center gap-1.5 text-xs text-red-400 bg-red-950/30 border border-red-800/40 px-3 py-1.5 rounded-full">
            <ShieldAlert className="w-3.5 h-3.5" />
            IDOR + SQLi active
          </div>
        )}
      </div>

      {/* IDOR Demo Panel */}
      {isVuln && (
        <div className="bg-[#161b22] border border-red-800/40 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <Eye className="w-4 h-4 text-red-400" />
            <h3 className="text-sm font-semibold text-white">IDOR Demo — Access Any User Profile</h3>
            <span className="text-xs text-red-400 bg-red-950/40 px-2 py-0.5 rounded font-mono">A01</span>
          </div>
          <p className="text-xs text-gray-500 font-mono mb-3">
            GET /api/users/:id — No auth required. Exposes SSN, plaintext password, secret notes.
          </p>
          <div className="flex gap-2">
            <input
              value={targetId}
              onChange={(e) => setTargetId(e.target.value)}
              placeholder="Enter user ID (1-10)"
              type="number"
              min="1"
              className="flex-1 bg-[#0d1117] border border-red-800/40 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-red-500"
              data-testid="input-idor-target-id"
            />
            <button
              onClick={handleIdorFetch}
              className="bg-red-600 hover:bg-red-500 text-white text-sm px-4 py-2 rounded-lg transition-colors"
              data-testid="button-idor-fetch"
            >
              Fetch
            </button>
          </div>
          {idorResult && (
            <div className="mt-3 bg-[#0d1117] rounded-lg p-3 text-xs font-mono space-y-1">
              <p><span className="text-gray-500">Username:</span> <span className="text-white">{idorResult.username}</span></p>
              <p><span className="text-gray-500">Email:</span> <span className="text-blue-400">{idorResult.email}</span></p>
              <p><span className="text-gray-500">SSN:</span> <span className="text-red-400">{idorResult.ssn ?? "N/A"}</span></p>
              <p><span className="text-gray-500">Balance:</span> <span className="text-green-400">${idorResult.balance}</span></p>
              <p><span className="text-gray-500">Password (plain):</span> <span className="text-red-400">{idorResult.password_plain ?? "N/A"}</span></p>
              <p className="break-all"><span className="text-gray-500">Secret:</span> <span className="text-yellow-400">{idorResult.secret_note ?? "N/A"}</span></p>
            </div>
          )}
        </div>
      )}

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder={isVuln ? "Search... (SQLi here)" : "Search users..."}
          className="w-full bg-[#161b22] border border-[#30363d] rounded-lg pl-10 pr-4 py-2.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500"
          data-testid="input-user-search"
        />
      </div>

      {/* SQLi hint */}
      {isVuln && (
        <div className="text-xs text-yellow-400 font-mono bg-[#161b22] border border-yellow-800/30 rounded p-2">
          [A03] Try: <span className="text-red-300">' UNION SELECT id,username,password_plain,ssn,secret_note,role,balance::text,email,phone,address,null,null,null,null,null,null,null,null FROM users --</span>
        </div>
      )}

      {/* Users Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4">
        {users.map((u) => (
          <div
            key={u.id}
            className="bg-[#161b22] border border-[#30363d] hover:border-blue-700/50 rounded-xl p-4 transition-colors cursor-pointer"
            onClick={() => setSelectedUser(u)}
            data-testid={`card-user-${u.id}`}
          >
            <div className="flex flex-col items-center text-center">
              <div className="w-12 h-12 rounded-full bg-gradient-to-br from-purple-500 to-blue-500 flex items-center justify-center text-lg font-bold mb-2">
                {u.username[0].toUpperCase()}
              </div>
              <p className="text-sm font-semibold text-white truncate w-full">{u.username}</p>
              <p className="text-xs text-gray-500 truncate w-full">{u.full_name ?? "—"}</p>
              <span className={cn("text-xs px-2 py-0.5 rounded border mt-2 font-mono", ROLE_COLORS[u.role] ?? ROLE_COLORS.user)}>
                {u.role}
              </span>
              {isVuln && u.ssn && (
                <p className="text-xs text-red-400 font-mono mt-1 truncate w-full" data-testid={`text-ssn-${u.id}`}>
                  SSN: {u.ssn}
                </p>
              )}
              {isVuln && u.balance !== undefined && (
                <div className="flex items-center gap-1 text-xs text-green-400 mt-1">
                  <DollarSign className="w-3 h-3" />
                  {parseFloat(String(u.balance)).toFixed(2)}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* User Detail Modal */}
      {selectedUser && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={() => setSelectedUser(null)}>
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-6 w-full max-w-md" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center gap-3 mb-4">
              <div className="w-14 h-14 rounded-full bg-gradient-to-br from-purple-500 to-blue-500 flex items-center justify-center text-xl font-bold">
                {selectedUser.username[0].toUpperCase()}
              </div>
              <div>
                <h3 className="text-white font-semibold">{selectedUser.username}</h3>
                <p className="text-gray-500 text-sm">{selectedUser.email}</p>
                <span className={cn("text-xs px-2 py-0.5 rounded border font-mono", ROLE_COLORS[selectedUser.role] ?? ROLE_COLORS.user)}>
                  {selectedUser.role}
                </span>
              </div>
            </div>
            {selectedUser.bio && <p className="text-sm text-gray-400 mb-4">{selectedUser.bio}</p>}
            <div className="grid grid-cols-2 gap-2 text-xs font-mono">
              <div className="bg-[#0d1117] rounded p-2">
                <span className="text-gray-500">Balance:</span> <span className="text-green-400">${selectedUser.balance}</span>
              </div>
              {isVuln && selectedUser.ssn && (
                <div className="bg-[#0d1117] rounded p-2">
                  <span className="text-gray-500">SSN:</span> <span className="text-red-400">{selectedUser.ssn}</span>
                </div>
              )}
              {isVuln && selectedUser.password_plain && (
                <div className="bg-[#0d1117] rounded p-2 col-span-2">
                  <span className="text-gray-500">Pass:</span> <span className="text-red-400">{selectedUser.password_plain}</span>
                </div>
              )}
              {isVuln && selectedUser.secret_note && (
                <div className="bg-[#0d1117] rounded p-2 col-span-2 break-all">
                  <span className="text-gray-500">Secret:</span> <span className="text-yellow-400">{selectedUser.secret_note}</span>
                </div>
              )}
            </div>
            <div className="flex gap-2 mt-4">
              {selectedUser.id !== me?.id && (
                <button
                  onClick={async () => {
                    await followUser.mutateAsync({ id: selectedUser.id.toString() });
                    setSelectedUser(null);
                  }}
                  className="flex-1 bg-blue-600 hover:bg-blue-500 text-white py-2 rounded-lg text-sm flex items-center justify-center gap-2"
                  data-testid="button-follow-user"
                >
                  <UserPlus className="w-3.5 h-3.5" /> Follow
                </button>
              )}
              <button onClick={() => setSelectedUser(null)} className="flex-1 border border-[#30363d] text-gray-400 py-2 rounded-lg text-sm hover:bg-[#21262d]">
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
