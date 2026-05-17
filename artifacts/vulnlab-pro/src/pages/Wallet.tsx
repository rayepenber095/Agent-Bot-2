import { useState } from "react";
import { useListTransactions, useTransfer, getListTransactionsQueryKey } from "@workspace/api-client-react";
import { useAuth } from "@/contexts/AuthContext";
import { useSecurity } from "@/contexts/SecurityContext";
import { useQueryClient } from "@tanstack/react-query";
import { CreditCard, ArrowUpRight, ArrowDownLeft, Send, ShieldAlert, AlertTriangle } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import type { Transaction } from "@workspace/api-client-react";

export default function Wallet() {
  const { user, refreshUser } = useAuth();
  const { mode } = useSecurity();
  const isVuln = mode === "vulnerable";
  const qc = useQueryClient();
  const { toast } = useToast();

  const [toUsername, setToUsername] = useState("");
  const [amount, setAmount] = useState("");
  const [note, setNote] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const { data: transactions = [] } = useListTransactions();
  const transfer = useTransfer();

  const handleTransfer = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      await transfer.mutateAsync({ data: { toUsername, amount: parseFloat(amount), note } });
      qc.invalidateQueries({ queryKey: getListTransactionsQueryKey() });
      await refreshUser();
      toast({
        title: "Transfer successful",
        description: `Sent $${amount} to ${toUsername}`,
      });
      setToUsername("");
      setAmount("");
      setNote("");
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error ?? "Transfer failed";
      toast({ title: "Transfer failed", description: msg, variant: "destructive" });
    } finally {
      setIsLoading(false);
    }
  };

  const formatDate = (ts: string) => new Date(ts).toLocaleDateString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

  const getType = (tx: Transaction) => {
    if (tx.sender_id === user?.id) return "sent";
    return "received";
  };

  return (
    <div className="p-6 space-y-6 max-w-4xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Wallet</h1>
        <p className="text-gray-500 text-sm">Transfer money and view history</p>
      </div>

      {/* Balance Card */}
      <div className={cn(
        "rounded-xl p-6 border",
        isVuln
          ? "bg-gradient-to-br from-red-950/40 to-[#161b22] border-red-800/40"
          : "bg-gradient-to-br from-green-950/40 to-[#161b22] border-green-800/40"
      )}>
        <p className="text-sm text-gray-400 mb-1">Available Balance</p>
        <p className="text-4xl font-bold text-white font-mono" data-testid="text-balance">
          ${user?.balance?.toFixed(2) ?? "0.00"}
        </p>
        <p className="text-xs text-gray-500 mt-2">{user?.username} · ID #{user?.id}</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Transfer Form */}
        <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <Send className="w-4 h-4 text-blue-400" />
            <h2 className="font-semibold text-white">Send Money</h2>
          </div>

          {isVuln && (
            <div className="bg-yellow-950/30 border border-yellow-800/30 rounded-lg p-2.5 mb-4 text-xs text-yellow-400 font-mono">
              [VULN-A04] Try negative amounts to steal money. No balance check. Race condition possible with concurrent requests.
            </div>
          )}

          <form onSubmit={handleTransfer} className="space-y-3">
            <div>
              <label className="text-xs text-gray-400 block mb-1.5">Recipient Username</label>
              <input
                value={toUsername}
                onChange={(e) => setToUsername(e.target.value)}
                placeholder="john"
                className="w-full bg-[#0d1117] border border-[#30363d] rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500"
                data-testid="input-transfer-username"
                required
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1.5">
                Amount
                {isVuln && <span className="text-red-400 ml-1">(negative = steal)</span>}
              </label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500 text-sm">$</span>
                <input
                  type="number"
                  step="0.01"
                  value={amount}
                  onChange={(e) => setAmount(e.target.value)}
                  placeholder={isVuln ? "-100 to steal" : "100.00"}
                  className="w-full bg-[#0d1117] border border-[#30363d] rounded-lg pl-7 pr-4 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500"
                  data-testid="input-transfer-amount"
                  required
                />
              </div>
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1.5">Note (optional)</label>
              <input
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="For the OSCP course..."
                className="w-full bg-[#0d1117] border border-[#30363d] rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500"
                data-testid="input-transfer-note"
              />
            </div>
            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-medium py-2.5 rounded-lg text-sm transition-colors"
              data-testid="button-send-transfer"
            >
              {isLoading ? "Sending..." : "Send Transfer"}
            </button>
          </form>
        </div>

        {/* Sensitive Data Panel (vuln mode only) */}
        {isVuln && user && (
          <div className="bg-[#161b22] border border-red-800/40 rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              <h2 className="font-semibold text-white">Exposed Sensitive Data</h2>
              <span className="text-xs text-red-400 bg-red-950/40 px-2 py-0.5 rounded">A01 IDOR</span>
            </div>
            <div className="space-y-2 text-xs font-mono">
              <div className="bg-[#0d1117] rounded p-2">
                <span className="text-gray-500">SSN: </span>
                <span className="text-red-400" data-testid="text-ssn">{user.ssn ?? "N/A"}</span>
              </div>
              <div className="bg-[#0d1117] rounded p-2">
                <span className="text-gray-500">Password (plain): </span>
                <span className="text-red-400" data-testid="text-password-plain">{user.password_plain ?? "N/A"}</span>
              </div>
              <div className="bg-[#0d1117] rounded p-2 break-all">
                <span className="text-gray-500">Secret Note: </span>
                <span className="text-yellow-400" data-testid="text-secret-note">{user.secret_note ?? "N/A"}</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Transaction History */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden">
        <div className="p-4 border-b border-[#30363d]">
          <h2 className="font-semibold text-white">Transaction History</h2>
        </div>
        <div className="divide-y divide-[#30363d]">
          {transactions.length === 0 && (
            <div className="text-center py-8 text-gray-600 text-sm">No transactions yet</div>
          )}
          {transactions.map((tx) => {
            const isSent = tx.sender_id === user?.id;
            return (
              <div key={tx.id} className="flex items-center gap-3 p-4" data-testid={`row-transaction-${tx.id}`}>
                <div className={cn(
                  "w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0",
                  isSent ? "bg-red-900/30" : "bg-green-900/30"
                )}>
                  {isSent
                    ? <ArrowUpRight className="w-4 h-4 text-red-400" />
                    : <ArrowDownLeft className="w-4 h-4 text-green-400" />
                  }
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-white">
                    {isSent
                      ? `To ${(tx.receiver as { username?: string })?.username ?? "unknown"}`
                      : `From ${(tx.sender as { username?: string })?.username ?? "unknown"}`
                    }
                  </p>
                  <p className="text-xs text-gray-500">{tx.note ?? tx.type} · {formatDate(tx.created_at)}</p>
                </div>
                <div className={cn("text-sm font-mono font-semibold", isSent ? "text-red-400" : "text-green-400")}>
                  {isSent ? "-" : "+"}${Math.abs(parseFloat(String(tx.amount))).toFixed(2)}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
