import { Switch, Route, Router as WouterRouter, useLocation, Redirect } from "wouter";
import { useEffect } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { queryClient } from "@/lib/queryClient";
import { AuthProvider, useAuth } from "@/contexts/AuthContext";
import { SecurityProvider } from "@/contexts/SecurityContext";
import Layout from "@/components/Layout";
import Login from "@/pages/Login";
import Register from "@/pages/Register";
import Dashboard from "@/pages/Dashboard";
import Channels from "@/pages/Channels";
import Marketplace from "@/pages/Marketplace";
import Cart from "@/pages/Cart";
import Orders from "@/pages/Orders";
import Wallet from "@/pages/Wallet";
import Feed from "@/pages/Feed";
import Users from "@/pages/Users";
import Admin from "@/pages/Admin";
import Debug from "@/pages/Debug";
import NotFound from "@/pages/not-found";

const BASE = import.meta.env.BASE_URL?.replace(/\/$/, "") ?? "";

function ProtectedRoute({ component: Component }: { component: React.ComponentType }) {
  const { user, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#0d1117] flex items-center justify-center">
        <div className="text-gray-500 font-mono animate-pulse">Loading VulnLab Pro...</div>
      </div>
    );
  }

  if (!user) return <Redirect to="/login" />;

  return (
    <Layout>
      <Component />
    </Layout>
  );
}

function AppRoutes() {
  return (
    <Switch>
      <Route path="/login" component={Login} />
      <Route path="/register" component={Register} />
      <Route path="/" component={() => <ProtectedRoute component={Dashboard} />} />
      <Route path="/feed" component={() => <ProtectedRoute component={Feed} />} />
      <Route path="/channels" component={() => <ProtectedRoute component={Channels} />} />
      <Route path="/channels/:slug" component={() => <ProtectedRoute component={Channels} />} />
      <Route path="/marketplace" component={() => <ProtectedRoute component={Marketplace} />} />
      <Route path="/cart" component={() => <ProtectedRoute component={Cart} />} />
      <Route path="/orders" component={() => <ProtectedRoute component={Orders} />} />
      <Route path="/wallet" component={() => <ProtectedRoute component={Wallet} />} />
      <Route path="/users" component={() => <ProtectedRoute component={Users} />} />
      <Route path="/debug" component={() => <ProtectedRoute component={Debug} />} />
      <Route path="/admin" component={() => <ProtectedRoute component={Admin} />} />
      <Route component={NotFound} />
    </Switch>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <SecurityProvider>
          <TooltipProvider>
            <WouterRouter base={BASE}>
              <AppRoutes />
            </WouterRouter>
            <Toaster />
          </TooltipProvider>
        </SecurityProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}
