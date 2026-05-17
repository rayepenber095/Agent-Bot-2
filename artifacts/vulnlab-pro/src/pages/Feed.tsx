import { useState } from "react";
import { useGetFeed, useCreatePost, useLikePost, useGetComments, useAddComment, getGetFeedQueryKey } from "@workspace/api-client-react";
import { useAuth } from "@/contexts/AuthContext";
import { useSecurity } from "@/contexts/SecurityContext";
import { useQueryClient } from "@tanstack/react-query";
import { Heart, MessageCircle, Send, Image, ShieldAlert } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import type { Post } from "@workspace/api-client-react";

function PostCard({ post, isVuln }: { post: Post; isVuln: boolean }) {
  const { user } = useAuth();
  const qc = useQueryClient();
  const [showComments, setShowComments] = useState(false);
  const [commentText, setCommentText] = useState("");
  const likePost = useLikePost();
  const addComment = useAddComment();
  const { data: comments = [] } = useGetComments(post.id.toString(), {
    query: { enabled: showComments }
  });

  const handleLike = async () => {
    await likePost.mutateAsync({ id: post.id.toString() });
    qc.invalidateQueries({ queryKey: getGetFeedQueryKey() });
  };

  const handleComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!commentText.trim()) return;
    await addComment.mutateAsync({ id: post.id.toString(), data: { content: commentText } });
    setCommentText("");
    qc.invalidateQueries({ queryKey: ["/api/posts", post.id.toString(), "/comments"] });
  };

  const formatTime = (ts: string) => {
    const diff = Date.now() - new Date(ts).getTime();
    if (diff < 60_000) return "just now";
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
    return new Date(ts).toLocaleDateString();
  };

  const author = post.author as { username?: string; full_name?: string; avatar_url?: string };

  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden" data-testid={`card-post-${post.id}`}>
      {/* Author */}
      <div className="flex items-center gap-3 p-4 border-b border-[#30363d]">
        <div className="w-9 h-9 rounded-full bg-gradient-to-br from-purple-500 to-blue-500 flex items-center justify-center text-sm font-bold flex-shrink-0">
          {author?.username?.[0]?.toUpperCase() ?? "?"}
        </div>
        <div>
          <p className="text-sm font-semibold text-white">{author?.full_name ?? author?.username}</p>
          <p className="text-xs text-gray-500">@{author?.username} · {formatTime(post.created_at)}</p>
        </div>
      </div>

      {/* Content */}
      <div className="p-4">
        {isVuln ? (
          /* [VULN-A07] Stored XSS in feed posts */
          <div className="text-sm text-gray-300 whitespace-pre-wrap" dangerouslySetInnerHTML={{ __html: post.content }} />
        ) : (
          <p className="text-sm text-gray-300 whitespace-pre-wrap">{post.content}</p>
        )}
        {post.image_url && (
          <img
            src={post.image_url}
            alt="Post image"
            className="mt-3 rounded-lg w-full object-cover max-h-80"
            loading="lazy"
          />
        )}
      </div>

      {/* Actions */}
      <div className="flex items-center gap-4 px-4 pb-3 pt-1">
        <button
          onClick={handleLike}
          className={cn("flex items-center gap-1.5 text-sm transition-colors", post.liked_by_me ? "text-red-400" : "text-gray-500 hover:text-red-400")}
          data-testid={`button-like-${post.id}`}
        >
          <Heart className={cn("w-4 h-4", post.liked_by_me && "fill-red-400")} />
          {post.like_count}
        </button>
        <button
          onClick={() => setShowComments(!showComments)}
          className="flex items-center gap-1.5 text-sm text-gray-500 hover:text-blue-400 transition-colors"
          data-testid={`button-comments-${post.id}`}
        >
          <MessageCircle className="w-4 h-4" />
          {post.comment_count}
        </button>
      </div>

      {/* Comments */}
      {showComments && (
        <div className="border-t border-[#30363d] p-4 space-y-3">
          {comments.map((c) => (
            <div key={c.id} className="flex gap-2.5">
              <div className="w-7 h-7 rounded-full bg-gradient-to-br from-green-500 to-teal-500 flex items-center justify-center text-xs font-bold flex-shrink-0">
                {(c.author as { username?: string })?.username?.[0]?.toUpperCase() ?? "?"}
              </div>
              <div className="flex-1 bg-[#21262d] rounded-lg px-3 py-2">
                <span className="text-xs font-semibold text-white mr-2">
                  {(c.author as { username?: string })?.username}
                </span>
                {isVuln
                  ? <span className="text-xs text-gray-300" dangerouslySetInnerHTML={{ __html: c.content }} />
                  : <span className="text-xs text-gray-300">{c.content}</span>
                }
              </div>
            </div>
          ))}
          <form onSubmit={handleComment} className="flex gap-2">
            <input
              value={commentText}
              onChange={(e) => setCommentText(e.target.value)}
              placeholder="Add a comment..."
              className="flex-1 bg-[#21262d] border border-[#30363d] rounded-lg px-3 py-1.5 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-blue-500"
            />
            <button type="submit" className="text-blue-400 hover:text-blue-300">
              <Send className="w-4 h-4" />
            </button>
          </form>
        </div>
      )}
    </div>
  );
}

export default function Feed() {
  const { user } = useAuth();
  const { mode } = useSecurity();
  const isVuln = mode === "vulnerable";
  const qc = useQueryClient();
  const [postContent, setPostContent] = useState("");
  const createPost = useCreatePost();
  const { data: posts = [], isLoading } = useGetFeed();
  const { toast } = useToast();

  const handlePost = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!postContent.trim()) return;
    try {
      await createPost.mutateAsync({ data: { content: postContent } });
      setPostContent("");
      qc.invalidateQueries({ queryKey: getGetFeedQueryKey() });
    } catch {
      toast({ title: "Failed to post", variant: "destructive" });
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-2xl mx-auto">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Social Feed</h1>
        {isVuln && (
          <div className="flex items-center gap-1.5 text-xs text-red-400 bg-red-950/30 border border-red-800/40 px-3 py-1.5 rounded-full">
            <ShieldAlert className="w-3.5 h-3.5" />
            XSS active
          </div>
        )}
      </div>

      {/* Compose */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-4">
        {isVuln && (
          <div className="text-xs text-yellow-400 font-mono mb-2">
            [VULN-A07] Try: &lt;script&gt;alert(document.cookie)&lt;/script&gt; or &lt;img src=x onerror=alert(1)&gt;
          </div>
        )}
        <form onSubmit={handlePost} className="space-y-3">
          <div className="flex gap-3">
            <div className="w-9 h-9 rounded-full bg-gradient-to-br from-purple-500 to-blue-500 flex items-center justify-center text-sm font-bold flex-shrink-0">
              {user?.username?.[0]?.toUpperCase() ?? "?"}
            </div>
            <textarea
              value={postContent}
              onChange={(e) => setPostContent(e.target.value)}
              placeholder={isVuln ? "What's on your mind? (XSS here)" : "Share something..."}
              rows={3}
              className="flex-1 bg-[#0d1117] border border-[#30363d] rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500 resize-none"
              data-testid="input-post-content"
            />
          </div>
          <div className="flex justify-end">
            <button
              type="submit"
              disabled={!postContent.trim()}
              className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
              data-testid="button-submit-post"
            >
              Post
            </button>
          </div>
        </form>
      </div>

      {/* Posts */}
      {isLoading ? (
        <div className="space-y-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="bg-[#161b22] border border-[#30363d] rounded-xl h-40 animate-pulse" />
          ))}
        </div>
      ) : (
        <div className="space-y-4">
          {posts.map((post) => (
            <PostCard key={post.id} post={post} isVuln={isVuln} />
          ))}
        </div>
      )}
    </div>
  );
}
