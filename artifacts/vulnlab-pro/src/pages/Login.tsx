import { useState } from "react";
import { useLocation } from "wouter";
import { useAuth } from "@/contexts/AuthContext";
import { ShieldAlert, Eye, EyeOff, Lock, User } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

export default function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const { login } = useAuth();
  const [, setLocation] = useLocation();
  const { toast } = useToast();

  const handle = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      await login(username, password);
      setLocation("/");
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error ?? "Login failed";
      toast({ title: "Login failed", description: msg, variant: "destructive" });
    } finally {
      setIsLoading(false);
    }
  };

  const DEMO_USERS = [
    { username: "admin", password: "Admin@123", role: "sudo" },
    { username: "john", password: "john123", role: "user" },
    { username: "alice", password: "password", role: "user" },
    { username: "diana", password: "diana123", role: "seller" },
  ];

  return (
    <div className="min-h-screen bg-[#0d1117] flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-red-900/30 border border-red-800/50 mb-4">
            <ShieldAlert className="w-8 h-8 text-red-500" />
          </div>
          <h1 className="text-2xl font-bold text-white">VulnLab Pro</h1>
          <p className="text-gray-500 text-sm mt-1">Cybersecurity Training Platform</p>
        </div>

        {/* Warning */}
        <div className="bg-yellow-950/40 border border-yellow-800/50 rounded-lg p-3 mb-6 text-xs text-yellow-400 font-mono">
          ⚠ EDUCATIONAL USE ONLY — This app is intentionally vulnerable.
          Do not use real credentials or sensitive information.
        </div>

        {/* Form */}
        <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-6">
          <form onSubmit={handle} className="space-y-4">
            <div>
              <label className="text-sm text-gray-400 block mb-1.5">Username</label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="admin"
                  className="w-full bg-[#0d1117] border border-[#30363d] rounded-lg pl-10 pr-4 py-2.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500 transition-colors"
                  data-testid="input-username"
                  autoComplete="username"
                />
              </div>
            </div>

            <div>
              <label className="text-sm text-gray-400 block mb-1.5">Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                <input
                  type={showPass ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full bg-[#0d1117] border border-[#30363d] rounded-lg pl-10 pr-10 py-2.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500 transition-colors"
                  data-testid="input-password"
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPass(!showPass)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                  data-testid="button-toggle-password"
                >
                  {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-medium py-2.5 rounded-lg transition-colors text-sm"
              data-testid="button-submit-login"
            >
              {isLoading ? "Signing in..." : "Sign in"}
            </button>
          </form>

          <p className="text-center text-sm text-gray-500 mt-4">
            No account?{" "}
            <a href="/register" className="text-blue-400 hover:text-blue-300" data-testid="link-register">
              Register
            </a>
          </p>
        </div>

        {/* Demo users */}
        <div className="mt-6 bg-[#161b22] border border-[#30363d] rounded-xl p-4">
          <p className="text-xs text-gray-500 mb-3 font-mono">// Demo accounts (click to fill)</p>
          <div className="grid grid-cols-2 gap-2">
            {DEMO_USERS.map((u) => (
              <button
                key={u.username}
                onClick={() => { setUsername(u.username); setPassword(u.password); }}
                className="text-left bg-[#21262d] hover:bg-[#2d333b] border border-[#30363d] rounded-lg px-3 py-2 transition-colors"
                data-testid={`button-demo-${u.username}`}
              >
                <p className="text-xs font-mono text-white">{u.username}</p>
                <p className="text-xs text-gray-500">{u.role}</p>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
