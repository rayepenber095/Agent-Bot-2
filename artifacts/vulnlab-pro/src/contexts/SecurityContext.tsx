import { createContext, useContext, useState, useEffect, type ReactNode } from "react";
import { useAuth } from "@/contexts/AuthContext";
import api from "@/lib/axios";

interface SecurityContextValue {
  mode: "vulnerable" | "hardened";
  appName: string;
  isLoading: boolean;
  setMode: (mode: "vulnerable" | "hardened") => void;
  refetch: () => void;
}

const SecurityContext = createContext<SecurityContextValue | null>(null);

export function SecurityProvider({ children }: { children: ReactNode }) {
  const { token } = useAuth();
  const [mode, setModeState] = useState<"vulnerable" | "hardened">("vulnerable");
  const [appName, setAppName] = useState("VulnLab Pro");
  const [isLoading, setIsLoading] = useState(true);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    if (!token) {
      setIsLoading(false);
      return;
    }
    setIsLoading(true);
    api
      .get("/admin/security-mode")
      .then((res) => {
        setModeState(res.data.security_mode ?? "vulnerable");
        setAppName(res.data.app_name ?? "VulnLab Pro");
      })
      .catch(() => {})
      .finally(() => setIsLoading(false));
  }, [token, tick]);

  const setMode = (m: "vulnerable" | "hardened") => setModeState(m);
  const refetch = () => setTick((t) => t + 1);

  return (
    <SecurityContext.Provider value={{ mode, appName, isLoading, setMode, refetch }}>
      {children}
    </SecurityContext.Provider>
  );
}

export function useSecurity() {
  const ctx = useContext(SecurityContext);
  if (!ctx) throw new Error("useSecurity must be used within SecurityProvider");
  return ctx;
}
