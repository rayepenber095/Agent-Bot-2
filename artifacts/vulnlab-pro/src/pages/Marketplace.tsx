import { useState } from "react";
import { useListProducts, useAddToCart, useGetCart, getGetCartQueryKey, getListProductsQueryKey } from "@workspace/api-client-react";
import { useSecurity } from "@/contexts/SecurityContext";
import { useQueryClient } from "@tanstack/react-query";
import { Search, ShoppingCart, Star, Package, ShieldAlert, Filter } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import type { Product } from "@workspace/api-client-react";

const CATEGORIES = ["All", "Electronics", "Books", "Clothing", "Tools", "Services"];

export default function Marketplace() {
  const { mode } = useSecurity();
  const isVuln = mode === "vulnerable";
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("All");
  const [cartAnimation, setCartAnimation] = useState<number | null>(null);
  const qc = useQueryClient();
  const { toast } = useToast();

  const { data: products = [], isLoading } = useListProducts({
    search: search || undefined,
    category: category === "All" ? undefined : category,
  });

  const addToCart = useAddToCart();

  const handleAddToCart = async (product: Product) => {
    try {
      await addToCart.mutateAsync({ data: { productId: product.id, quantity: 1 } });
      setCartAnimation(product.id);
      setTimeout(() => setCartAnimation(null), 600);
      qc.invalidateQueries({ queryKey: getGetCartQueryKey() });
      toast({ title: "Added to cart", description: product.name });
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error ?? "Failed";
      toast({ title: "Failed", description: msg, variant: "destructive" });
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Marketplace</h1>
          <p className="text-gray-500 text-sm mt-0.5">{products.length} products available</p>
        </div>
        {isVuln && (
          <div className="flex items-center gap-1.5 text-xs text-red-400 bg-red-950/30 border border-red-800/40 px-3 py-1.5 rounded-full">
            <ShieldAlert className="w-3.5 h-3.5" />
            SQLi active on search
          </div>
        )}
      </div>

      {/* SQLi hint */}
      {isVuln && (
        <div className="bg-[#161b22] border border-yellow-800/30 rounded-lg p-3 text-xs text-yellow-400 font-mono">
          [VULN-A03] Try: <span className="text-red-300">{"' UNION SELECT id,username,password_plain,ssn,secret_note,role,balance::text,null,null,null FROM users --"}</span>
        </div>
      )}

      {/* Search + Filter */}
      <div className="flex gap-3 flex-wrap">
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={isVuln ? "Search... (SQLi here)" : "Search products..."}
            className="w-full bg-[#161b22] border border-[#30363d] rounded-lg pl-10 pr-4 py-2.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500"
            data-testid="input-product-search"
          />
        </div>
        <div className="flex gap-2 flex-wrap">
          {CATEGORIES.map((cat) => (
            <button
              key={cat}
              onClick={() => setCategory(cat)}
              className={cn(
                "px-3 py-2 rounded-lg text-sm transition-colors border",
                category === cat
                  ? "bg-blue-600 border-blue-500 text-white"
                  : "bg-[#161b22] border-[#30363d] text-gray-400 hover:text-white hover:border-gray-500"
              )}
              data-testid={`button-category-${cat.toLowerCase()}`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Products Grid */}
      {isLoading ? (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4">
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="bg-[#161b22] border border-[#30363d] rounded-xl h-64 animate-pulse" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4">
          {products.map((product) => (
            <div
              key={product.id}
              className="bg-[#161b22] border border-[#30363d] hover:border-blue-700/50 rounded-xl overflow-hidden transition-all group"
              data-testid={`card-product-${product.id}`}
            >
              {/* Image */}
              <div className="aspect-square bg-[#21262d] overflow-hidden">
                {product.image_url ? (
                  <img
                    src={product.image_url}
                    alt={product.name}
                    className="w-full h-full object-cover group-hover:scale-105 transition-transform"
                  />
                ) : (
                  <div className="w-full h-full flex items-center justify-center">
                    <Package className="w-12 h-12 text-gray-600" />
                  </div>
                )}
              </div>

              {/* Info */}
              <div className="p-3">
                <div className="text-xs text-gray-500 mb-0.5">{product.category} · {product.brand}</div>
                <h3 className="text-sm font-medium text-white line-clamp-2 mb-1">{product.name}</h3>

                {/* Rating */}
                {product.rating && (
                  <div className="flex items-center gap-1 mb-2">
                    <Star className="w-3 h-3 text-yellow-400 fill-yellow-400" />
                    <span className="text-xs text-gray-400">{product.rating}</span>
                  </div>
                )}

                {/* Price + Cart */}
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-sm font-bold text-white" data-testid={`text-price-${product.id}`}>${product.price}</span>
                    {product.original_price && product.original_price > product.price && (
                      <span className="text-xs text-gray-600 line-through ml-1">${product.original_price}</span>
                    )}
                  </div>
                  <button
                    onClick={() => handleAddToCart(product)}
                    disabled={product.stock === 0}
                    className={cn(
                      "p-1.5 rounded-lg transition-all",
                      cartAnimation === product.id
                        ? "bg-green-600 scale-90"
                        : "bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:cursor-not-allowed"
                    )}
                    data-testid={`button-add-cart-${product.id}`}
                  >
                    <ShoppingCart className="w-3.5 h-3.5 text-white" />
                  </button>
                </div>

                {/* Stock */}
                <div className="text-xs text-gray-600 mt-1">
                  {product.stock === 0 ? "Out of stock" : `${product.stock} in stock`}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {!isLoading && products.length === 0 && (
        <div className="text-center py-16 text-gray-600">
          <Package className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>No products found</p>
        </div>
      )}
    </div>
  );
}
