import { useState } from "react";
import { useDebugPing, useDebugEnv, useDebugVersion, useDebugEval, useTestWebhook, useFetchProductImage } from "@workspace/api-client-react";
import { useSecurity } from "@/contexts/SecurityContext";
import { Terminal, AlertTriangle, ShieldAlert, ShieldCheck, Zap } from "lucide-react";
import { cn } from "@/lib/utils";

interface VulnLab {
  id: string;
  name: string;
  vuln: string;
  description: string;
  payload: string;
  endpoint: string;
}

const LABS: VulnLab[] = [
  { id: "cmdi", name: "Command Injection", vuln: "A03", description: "Ping endpoint concatenates host into shell command without escaping.", payload: "127.0.0.1;id", endpoint: "GET /api/debug/ping?host=" },
  { id: "rce", name: "Remote Code Execution", vuln: "A08", description: "Eval endpoint executes arbitrary Node.js code server-side.", payload: "require('child_process').execSync('id').toString()", endpoint: "POST /api/debug/eval" },
  { id: "env", name: "Env Variable Exposure", vuln: "A05", description: "Returns all process.env including DATABASE_URL and SESSION_SECRET.", payload: "(no input needed)", endpoint: "GET /api/debug/env" },
  { id: "ssrf", name: "Server-Side Request Forgery", vuln: "A10", description: "Server fetches imageUrl without validating if it's internal.", payload: "http://169.254.169.254/latest/meta-data/", endpoint: "POST /api/products/fetch-image" },
  { id: "path", name: "Path Traversal", vuln: "A01", description: "File download resolves names relative to server root without sanitization.", payload: "../../etc/passwd", endpoint: "GET /api/files/download?name=" },
  { id: "redirect", name: "Open Redirect", vuln: "A01", description: "Redirect endpoint forwards to any URL without validation.", payload: "https://evil.example.com", endpoint: "GET /api/redirect?url=" },
];

export default function Debug() {
  const { mode } = useSecurity();
  const isVuln = mode === "vulnerable";
  const [pingHost, setPingHost] = useState("127.0.0.1");
  const [evalCode, setEvalCode] = useState("require('os').hostname()");
  const [webhookUrl, setWebhookUrl] = useState("http://localhost:5000/api/admin/users");
  const [ssrfUrl, setSsrfUrl] = useState("http://169.254.169.254/latest/meta-data/");
  const [output, setOutput] = useState<Record<string, string>>({});

  const debugPing = useDebugPing({ host: pingHost }, { query: { enabled: false } });
  const debugEnv = useDebugEnv({ query: { enabled: false } });
  const debugVersion = useDebugVersion({ query: { enabled: false } });
  const debugEval = useDebugEval();
  const testWebhook = useTestWebhook();
  const fetchImage = useFetchProductImage();

  const setOut = (key: string, val: string) => setOutput((prev) => ({ ...prev, [key]: val }));

  const run = async (key: string, fn: () => Promise<{ output?: string; content?: string; url?: string; saved?: boolean; message?: string } | string>) => {
    try {
      setOut(key, "Running...");
      const res = await fn();
      if (typeof res === "string") { setOut(key, res); return; }
      setOut(key, res.output ?? res.content ?? res.url ?? res.message ?? JSON.stringify(res));
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error ?? String(err);
      setOut(key, `Error: ${msg}`);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Terminal className="w-6 h-6 text-green-400" />
            Debug Lab
          </h1>
          <p className="text-gray-500 text-sm mt-0.5">
            {isVuln ? "All vulnerabilities active — exploit freely" : "Endpoints sandboxed — attacks blocked"}
          </p>
        </div>
        <div className={cn(
          "flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-xs font-semibold",
          isVuln ? "text-red-400 border-red-800/60 bg-red-950/30" : "text-green-400 border-green-800/60 bg-green-950/30"
        )}>
          {isVuln ? <ShieldAlert className="w-3.5 h-3.5" /> : <ShieldCheck className="w-3.5 h-3.5" />}
          {isVuln ? "VULNERABLE" : "HARDENED"}
        </div>
      </div>

      {/* Vuln Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        {LABS.map((lab) => (
          <div key={lab.id} className="bg-[#161b22] border border-[#30363d] rounded-lg p-3">
            <div className="flex items-center gap-2 mb-1">
              {isVuln
                ? <AlertTriangle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
                : <ShieldCheck className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
              }
              <span className="text-xs font-mono text-gray-500">{lab.vuln}</span>
              <span className="text-xs font-medium text-white truncate">{lab.name}</span>
            </div>
            <p className="text-xs text-gray-500">{lab.description}</p>
            <code className="text-xs text-blue-400/70 block mt-1">{lab.endpoint}</code>
          </div>
        ))}
      </div>

      {/* Interactive Labs */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Command Injection */}
        <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-4">
          <h3 className="text-sm font-semibold text-white mb-1">Command Injection (A03)</h3>
          <p className="text-xs text-gray-500 mb-3">Try: <code className="text-red-300 font-mono">127.0.0.1;cat /etc/passwd</code></p>
          <div className="flex gap-2 mb-3">
            <input
              value={pingHost}
              onChange={(e) => setPingHost(e.target.value)}
              className="flex-1 bg-[#0d1117] border border-[#30363d] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-blue-500"
              data-testid="input-ping-host"
            />
            <button
              onClick={() => run("ping", async () => { const r = await debugPing.refetch(); return r.data as { output: string }; })}
              className="bg-red-600 hover:bg-red-500 text-white text-xs px-3 py-2 rounded-lg transition-colors"
              data-testid="button-run-ping"
            >
              <Zap className="w-3.5 h-3.5" />
            </button>
          </div>
          {output.ping && (
            <pre className="bg-[#0d1117] rounded p-2 text-xs text-green-400 font-mono overflow-auto max-h-32 whitespace-pre-wrap">{output.ping}</pre>
          )}
        </div>

        {/* RCE Eval */}
        <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-4">
          <h3 className="text-sm font-semibold text-white mb-1">Remote Code Execution (A08)</h3>
          <p className="text-xs text-gray-500 mb-3">Try: <code className="text-red-300 font-mono">require('fs').readdirSync('/')</code></p>
          <div className="flex gap-2 mb-3">
            <input
              value={evalCode}
              onChange={(e) => setEvalCode(e.target.value)}
              className="flex-1 bg-[#0d1117] border border-[#30363d] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-blue-500"
              data-testid="input-eval-code"
            />
            <button
              onClick={() => run("eval", async () => { const r = await debugEval.mutateAsync({ data: { code: evalCode } }); return r as { output: string }; })}
              className="bg-red-600 hover:bg-red-500 text-white text-xs px-3 py-2 rounded-lg transition-colors"
              data-testid="button-run-eval"
            >
              <Zap className="w-3.5 h-3.5" />
            </button>
          </div>
          {output.eval && (
            <pre className="bg-[#0d1117] rounded p-2 text-xs text-green-400 font-mono overflow-auto max-h-32 whitespace-pre-wrap">{output.eval}</pre>
          )}
        </div>

        {/* Env Exposure */}
        <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-4">
          <h3 className="text-sm font-semibold text-white mb-1">Env Variable Exposure (A05)</h3>
          <p className="text-xs text-gray-500 mb-3">Exposes DATABASE_URL, SESSION_SECRET, and all env vars</p>
          <button
            onClick={() => run("env", async () => { const r = await debugEnv.refetch(); return r.data as { output: string }; })}
            className="bg-orange-600 hover:bg-orange-500 text-white text-sm px-4 py-2 rounded-lg transition-colors mb-3"
            data-testid="button-run-env"
          >
            Dump Environment
          </button>
          {output.env && (
            <pre className="bg-[#0d1117] rounded p-2 text-xs text-orange-400 font-mono overflow-auto max-h-40 whitespace-pre-wrap">{output.env.slice(0, 2000)}</pre>
          )}
        </div>

        {/* SSRF */}
        <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-4">
          <h3 className="text-sm font-semibold text-white mb-1">SSRF — Fetch Image (A10)</h3>
          <p className="text-xs text-gray-500 mb-3">Try internal URLs: <code className="text-red-300">http://localhost:5000/api/admin/users</code></p>
          <div className="flex gap-2 mb-3">
            <input
              value={ssrfUrl}
              onChange={(e) => setSsrfUrl(e.target.value)}
              className="flex-1 bg-[#0d1117] border border-[#30363d] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-blue-500"
              data-testid="input-ssrf-url"
            />
            <button
              onClick={() => run("ssrf", async () => { const r = await fetchImage.mutateAsync({ data: { imageUrl: ssrfUrl } }); return r as { url: string; saved: boolean; content?: string }; })}
              className="bg-purple-600 hover:bg-purple-500 text-white text-xs px-3 py-2 rounded-lg"
              data-testid="button-run-ssrf"
            >
              <Zap className="w-3.5 h-3.5" />
            </button>
          </div>
          {output.ssrf && (
            <pre className="bg-[#0d1117] rounded p-2 text-xs text-purple-400 font-mono overflow-auto max-h-32 whitespace-pre-wrap">{output.ssrf.slice(0, 1000)}</pre>
          )}
        </div>

        {/* Package Version */}
        <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-4">
          <h3 className="text-sm font-semibold text-white mb-1">Version Disclosure (A06)</h3>
          <p className="text-xs text-gray-500 mb-3">Exposes package.json with version info for CVE lookups</p>
          <button
            onClick={() => run("version", async () => { const r = await debugVersion.refetch(); return r.data as { output: string }; })}
            className="bg-yellow-600 hover:bg-yellow-500 text-white text-sm px-4 py-2 rounded-lg transition-colors mb-3"
            data-testid="button-run-version"
          >
            Get Version Info
          </button>
          {output.version && (
            <pre className="bg-[#0d1117] rounded p-2 text-xs text-yellow-400 font-mono overflow-auto max-h-40 whitespace-pre-wrap">{output.version.slice(0, 2000)}</pre>
          )}
        </div>

        {/* Webhook / SSRF */}
        <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-4">
          <h3 className="text-sm font-semibold text-white mb-1">Webhook SSRF (A10)</h3>
          <p className="text-xs text-gray-500 mb-3">Send requests to any URL from server context</p>
          <div className="flex gap-2 mb-3">
            <input
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              className="flex-1 bg-[#0d1117] border border-[#30363d] rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-blue-500"
              data-testid="input-webhook-url"
            />
            <button
              onClick={() => run("webhook", async () => { const r = await testWebhook.mutateAsync({ data: { url: webhookUrl, payload: { test: true } } }); return r.message ?? ""; })}
              className="bg-blue-600 hover:bg-blue-500 text-white text-xs px-3 py-2 rounded-lg"
              data-testid="button-run-webhook"
            >
              <Zap className="w-3.5 h-3.5" />
            </button>
          </div>
          {output.webhook && (
            <pre className="bg-[#0d1117] rounded p-2 text-xs text-blue-400 font-mono">{output.webhook}</pre>
          )}
        </div>
      </div>
    </div>
  );
}
