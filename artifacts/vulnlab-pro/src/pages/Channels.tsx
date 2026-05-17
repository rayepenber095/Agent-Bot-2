import { useState, useEffect, useRef } from "react";
import { useListChannels, useListChannelMessages, useSendMessage, useCreateChannel } from "@workspace/api-client-react";
import { useAuth } from "@/contexts/AuthContext";
import { useSecurity } from "@/contexts/SecurityContext";
import { getSocket, connectSocket } from "@/lib/socket";
import { Hash, Plus, Send, Shield, ShieldAlert, Lock } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { getListChannelMessagesQueryKey, getListChannelsQueryKey } from "@workspace/api-client-react";
import { cn } from "@/lib/utils";
import type { Message, Channel } from "@workspace/api-client-react";

export default function Channels() {
  const { user, token } = useAuth();
  const { mode } = useSecurity();
  const isVuln = mode === "vulnerable";
  const qc = useQueryClient();

  const [selectedChannel, setSelectedChannel] = useState<Channel | null>(null);
  const [messageText, setMessageText] = useState("");
  const [typingUsers, setTypingUsers] = useState<string[]>([]);
  const [localMessages, setLocalMessages] = useState<Message[]>([]);
  const [showNewChannel, setShowNewChannel] = useState(false);
  const [newChannelName, setNewChannelName] = useState("");
  const [newChannelDesc, setNewChannelDesc] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const typingTimeout = useRef<ReturnType<typeof setTimeout> | null>(null);

  const { data: channels = [] } = useListChannels();
  const { data: messages = [], queryKey } = useListChannelMessages(
    selectedChannel?.id.toString() ?? "",
    { query: { enabled: !!selectedChannel, queryKey: getListChannelMessagesQueryKey(selectedChannel?.id.toString() ?? "") } }
  );

  const sendMessage = useSendMessage();
  const createChannel = useCreateChannel();

  // Socket.io realtime
  useEffect(() => {
    if (!token) return;
    const socket = connectSocket(token);

    socket.on("new_message", (msg: Message) => {
      if (selectedChannel && msg.channel_id === selectedChannel.id) {
        setLocalMessages((prev) => [...prev, msg]);
        qc.invalidateQueries({ queryKey: getListChannelMessagesQueryKey(selectedChannel.id.toString()) });
      }
    });

    socket.on("user_typing", ({ username }: { username: string }) => {
      setTypingUsers((prev) => [...new Set([...prev, username])]);
      setTimeout(() => setTypingUsers((prev) => prev.filter((u) => u !== username)), 3000);
    });

    if (selectedChannel) {
      socket.emit("join_channel", selectedChannel.id.toString());
    }

    return () => {
      socket.off("new_message");
      socket.off("user_typing");
    };
  }, [token, selectedChannel, qc]);

  // Sync API messages with local
  useEffect(() => {
    setLocalMessages(messages);
  }, [messages]);

  // Scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [localMessages]);

  const handleSend = async () => {
    if (!messageText.trim() || !selectedChannel) return;
    const content = messageText;
    setMessageText("");
    try {
      await sendMessage.mutateAsync({
        id: selectedChannel.id.toString(),
        data: { content },
      });
      qc.invalidateQueries({ queryKey: getListChannelMessagesQueryKey(selectedChannel.id.toString()) });
      // Emit via socket too
      getSocket().emit("send_message", {
        channelId: selectedChannel.id.toString(),
        content,
        senderId: user?.id,
        sender: { id: user?.id, username: user?.username, avatar_url: user?.avatar_url },
      });
    } catch {}
  };

  const handleTyping = () => {
    if (!selectedChannel) return;
    getSocket().emit("typing", { channelId: selectedChannel.id.toString(), username: user?.username });
    if (typingTimeout.current) clearTimeout(typingTimeout.current);
  };

  const handleCreateChannel = async () => {
    if (!newChannelName.trim()) return;
    await createChannel.mutateAsync({ data: { name: newChannelName, description: newChannelDesc } });
    qc.invalidateQueries({ queryKey: getListChannelsQueryKey() });
    setNewChannelName("");
    setNewChannelDesc("");
    setShowNewChannel(false);
  };

  const formatTime = (ts: string) => new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

  return (
    <div className="flex h-full">
      {/* Channel List */}
      <div className="w-52 flex-shrink-0 bg-[#161b22] border-r border-[#30363d] flex flex-col">
        <div className="p-3 border-b border-[#30363d] flex items-center justify-between">
          <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Channels</span>
          <button
            onClick={() => setShowNewChannel(true)}
            className="text-gray-400 hover:text-white"
            data-testid="button-new-channel"
          >
            <Plus className="w-4 h-4" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto py-2">
          {channels.map((ch) => (
            <button
              key={ch.id}
              onClick={() => setSelectedChannel(ch)}
              className={cn(
                "w-full flex items-center gap-2 px-3 py-2 text-sm text-left transition-colors",
                selectedChannel?.id === ch.id
                  ? "bg-[#21262d] text-white"
                  : "text-gray-400 hover:text-white hover:bg-[#1c2128]"
              )}
              data-testid={`button-channel-${ch.slug}`}
            >
              {ch.is_private ? <Lock className="w-3.5 h-3.5 flex-shrink-0" /> : <Hash className="w-3.5 h-3.5 flex-shrink-0" />}
              <span className="truncate">{ch.name}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Chat Area */}
      {selectedChannel ? (
        <div className="flex-1 flex flex-col">
          {/* Channel header */}
          <div className="h-12 border-b border-[#30363d] flex items-center px-4 gap-2 bg-[#161b22]">
            <Hash className="w-4 h-4 text-gray-400" />
            <span className="font-semibold text-white text-sm">{selectedChannel.name}</span>
            {selectedChannel.description && (
              <span className="text-gray-500 text-xs ml-2">— {selectedChannel.description}</span>
            )}
            {isVuln && (
              <div className="ml-auto flex items-center gap-1 text-xs text-red-400">
                <ShieldAlert className="w-3.5 h-3.5" />
                XSS Active
              </div>
            )}
          </div>

          {/* XSS Warning */}
          {isVuln && (
            <div className="bg-yellow-950/30 border-b border-yellow-800/30 px-4 py-1.5 text-xs text-yellow-400 font-mono">
              ⚠ [VULN-A07] Stored XSS — messages are rendered unsanitized. Try: &lt;img src=x onerror=alert(document.cookie)&gt;
            </div>
          )}

          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-4 space-y-3">
            {localMessages.map((msg) => {
              const isMe = msg.sender_id === user?.id;
              return (
                <div key={msg.id} className="flex items-start gap-3 group" data-testid={`msg-${msg.id}`}>
                  <div className="w-8 h-8 rounded-full bg-gradient-to-br from-purple-500 to-blue-500 flex items-center justify-center text-xs font-bold flex-shrink-0">
                    {(msg.sender as { username?: string })?.username?.[0]?.toUpperCase() ?? "?"}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-baseline gap-2">
                      <span className={cn("text-sm font-semibold", isMe ? "text-blue-400" : "text-white")}>
                        {(msg.sender as { username?: string })?.username ?? "unknown"}
                      </span>
                      <span className="text-xs text-gray-600">{formatTime(msg.created_at)}</span>
                    </div>
                    {isVuln ? (
                      /* [VULN-A07] dangerouslySetInnerHTML — allows stored XSS */
                      <div
                        className="text-sm text-gray-300 break-words mt-0.5"
                        dangerouslySetInnerHTML={{ __html: msg.content }}
                      />
                    ) : (
                      <p className="text-sm text-gray-300 break-words mt-0.5">{msg.content}</p>
                    )}
                  </div>
                </div>
              );
            })}
            {typingUsers.length > 0 && (
              <div className="text-xs text-gray-500 italic">
                {typingUsers.join(", ")} {typingUsers.length === 1 ? "is" : "are"} typing...
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input */}
          <div className="p-4 border-t border-[#30363d]">
            <div className="flex items-center gap-2 bg-[#21262d] rounded-lg border border-[#30363d] px-3">
              <input
                value={messageText}
                onChange={(e) => { setMessageText(e.target.value); handleTyping(); }}
                onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && (e.preventDefault(), handleSend())}
                placeholder={`Message #${selectedChannel.name}`}
                className="flex-1 bg-transparent py-3 text-sm text-white placeholder-gray-600 focus:outline-none"
                data-testid="input-message"
              />
              <button
                onClick={handleSend}
                disabled={!messageText.trim()}
                className="text-blue-400 hover:text-blue-300 disabled:text-gray-600 transition-colors"
                data-testid="button-send-message"
              >
                <Send className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="flex-1 flex items-center justify-center text-gray-600">
          <div className="text-center">
            <Hash className="w-12 h-12 mx-auto mb-3 opacity-30" />
            <p className="text-sm">Select a channel to start chatting</p>
          </div>
        </div>
      )}

      {/* New Channel Modal */}
      {showNewChannel && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-6 w-full max-w-sm">
            <h3 className="text-white font-semibold mb-4">Create Channel</h3>
            <input
              value={newChannelName}
              onChange={(e) => setNewChannelName(e.target.value)}
              placeholder="Channel name"
              className="w-full bg-[#0d1117] border border-[#30363d] rounded-lg px-3 py-2 text-sm text-white mb-3 focus:outline-none focus:border-blue-500"
              data-testid="input-channel-name"
            />
            <input
              value={newChannelDesc}
              onChange={(e) => setNewChannelDesc(e.target.value)}
              placeholder="Description (optional)"
              className="w-full bg-[#0d1117] border border-[#30363d] rounded-lg px-3 py-2 text-sm text-white mb-4 focus:outline-none focus:border-blue-500"
              data-testid="input-channel-desc"
            />
            <div className="flex gap-2">
              <button
                onClick={() => setShowNewChannel(false)}
                className="flex-1 border border-[#30363d] text-gray-400 py-2 rounded-lg text-sm hover:bg-[#21262d]"
                data-testid="button-cancel-channel"
              >Cancel</button>
              <button
                onClick={handleCreateChannel}
                className="flex-1 bg-blue-600 hover:bg-blue-500 text-white py-2 rounded-lg text-sm"
                data-testid="button-create-channel"
              >Create</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
