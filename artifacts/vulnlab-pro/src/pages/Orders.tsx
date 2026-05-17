import { useListOrders } from "@workspace/api-client-react";
import { Package, CheckCircle, Clock } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Order } from "@workspace/api-client-react";

export default function Orders() {
  const { data: orders = [], isLoading } = useListOrders();

  if (isLoading) return <div className="p-6 text-gray-500">Loading orders...</div>;

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-6">
      <h1 className="text-2xl font-bold text-white flex items-center gap-2">
        <Package className="w-6 h-6" /> Orders
      </h1>

      {orders.length === 0 ? (
        <div className="text-center py-20 text-gray-600">
          <Package className="w-14 h-14 mx-auto mb-3 opacity-20" />
          <p>No orders yet</p>
        </div>
      ) : (
        <div className="space-y-4">
          {orders.map((order) => (
            <div key={order.id} className="bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden" data-testid={`card-order-${order.id}`}>
              <div className="flex items-center justify-between p-4 border-b border-[#30363d]">
                <div>
                  <p className="text-sm font-semibold text-white">Order #{order.id}</p>
                  <p className="text-xs text-gray-500">{new Date(order.created_at).toLocaleDateString()}</p>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-lg font-bold text-white font-mono">${parseFloat(String(order.total)).toFixed(2)}</span>
                  <span className={cn("text-xs px-2 py-1 rounded-full border font-mono flex items-center gap-1",
                    order.status === "confirmed" ? "text-green-400 border-green-800/50 bg-green-950/30" : "text-yellow-400 border-yellow-800/50 bg-yellow-950/30"
                  )}>
                    {order.status === "confirmed" ? <CheckCircle className="w-3 h-3" /> : <Clock className="w-3 h-3" />}
                    {order.status}
                  </span>
                </div>
              </div>
              {order.shipping_address && (
                <div className="px-4 py-2 text-xs text-gray-500 border-b border-[#30363d]">
                  Ships to: {order.shipping_address}
                </div>
              )}
              <div className="p-4 space-y-2">
                {(order.items ?? []).map((item, i) => (
                  <div key={i} className="flex items-center justify-between text-sm">
                    <span className="text-gray-300">
                      {(item.product as { name?: string })?.name ?? `Product #${item.product_id}`} × {item.quantity}
                    </span>
                    <span className="text-white font-mono">${(parseFloat(String(item.price_at_purchase)) * item.quantity).toFixed(2)}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
