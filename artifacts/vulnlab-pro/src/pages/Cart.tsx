import { useGetCart, useRemoveFromCart, useCheckout, getGetCartQueryKey, getListOrdersQueryKey } from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { useAuth } from "@/contexts/AuthContext";
import { ShoppingCart, Trash2, Package, CreditCard } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useState } from "react";
import { useLocation } from "wouter";

export default function Cart() {
  const qc = useQueryClient();
  const { refreshUser } = useAuth();
  const { toast } = useToast();
  const [, setLocation] = useLocation();
  const [address, setAddress] = useState("");
  const [isChecking, setIsChecking] = useState(false);

  const { data: cartItems = [], isLoading } = useGetCart();
  const removeFromCart = useRemoveFromCart();
  const checkout = useCheckout();

  const total = cartItems.reduce((sum, item) => {
    const price = parseFloat(String((item.product as { price?: number })?.price ?? 0));
    return sum + price * item.quantity;
  }, 0);

  const handleRemove = async (productId: number) => {
    await removeFromCart.mutateAsync({ productId: productId.toString() });
    qc.invalidateQueries({ queryKey: getGetCartQueryKey() });
  };

  const handleCheckout = async () => {
    if (!cartItems.length) return;
    setIsChecking(true);
    try {
      await checkout.mutateAsync({ data: { shippingAddress: address } });
      qc.invalidateQueries({ queryKey: getGetCartQueryKey() });
      qc.invalidateQueries({ queryKey: getListOrdersQueryKey() });
      await refreshUser();
      toast({ title: "Order placed!", description: `$${total.toFixed(2)} charged to your wallet.` });
      setLocation("/orders");
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error ?? "Checkout failed";
      toast({ title: "Checkout failed", description: msg, variant: "destructive" });
    } finally {
      setIsChecking(false);
    }
  };

  if (isLoading) return <div className="p-6 text-gray-500">Loading cart...</div>;

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-6">
      <h1 className="text-2xl font-bold text-white flex items-center gap-2">
        <ShoppingCart className="w-6 h-6" /> Cart
      </h1>

      {cartItems.length === 0 ? (
        <div className="text-center py-20 text-gray-600">
          <ShoppingCart className="w-14 h-14 mx-auto mb-3 opacity-20" />
          <p>Your cart is empty</p>
          <a href="/marketplace" className="text-blue-400 text-sm mt-2 block hover:text-blue-300">Browse marketplace</a>
        </div>
      ) : (
        <>
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden">
            {cartItems.map((item) => {
              const product = item.product as { id?: number; name?: string; price?: number; image_url?: string; stock?: number };
              return (
                <div key={item.id} className="flex items-center gap-4 p-4 border-b border-[#30363d] last:border-0" data-testid={`row-cart-${item.id}`}>
                  <div className="w-14 h-14 bg-[#21262d] rounded-lg overflow-hidden flex-shrink-0">
                    {product.image_url
                      ? <img src={product.image_url} alt={product.name} className="w-full h-full object-cover" />
                      : <div className="w-full h-full flex items-center justify-center"><Package className="w-6 h-6 text-gray-600" /></div>
                    }
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-white truncate">{product.name}</p>
                    <p className="text-xs text-gray-500">Qty: {item.quantity}</p>
                  </div>
                  <div className="text-sm font-mono font-semibold text-white">
                    ${(parseFloat(String(product.price ?? 0)) * item.quantity).toFixed(2)}
                  </div>
                  <button
                    onClick={() => handleRemove(item.product_id)}
                    className="text-red-400 hover:text-red-300 transition-colors"
                    data-testid={`button-remove-cart-${item.id}`}
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              );
            })}
          </div>

          <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <span className="text-gray-400">Total</span>
              <span className="text-xl font-bold text-white font-mono">${total.toFixed(2)}</span>
            </div>
            <input
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              placeholder="Shipping address (optional)"
              className="w-full bg-[#0d1117] border border-[#30363d] rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500 mb-3"
              data-testid="input-shipping-address"
            />
            <button
              onClick={handleCheckout}
              disabled={isChecking}
              className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-medium py-3 rounded-lg transition-colors flex items-center justify-center gap-2"
              data-testid="button-checkout"
            >
              <CreditCard className="w-4 h-4" />
              {isChecking ? "Processing..." : `Pay $${total.toFixed(2)}`}
            </button>
          </div>
        </>
      )}
    </div>
  );
}
