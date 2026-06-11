import { useState, useRef, useEffect } from 'react';
import { MessageSquare, X, Send, Bot, User, Loader2, RotateCcw } from 'lucide-react';
import { apiGet, apiPost } from '../lib/api';

export default function SpeakWidget() {
  const [isOpen, setIsOpen] = useState(false);
  const [message, setMessage] = useState('');
  const [messages, setMessages] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [sessionId, setSessionId] = useState<number | null>(null);
  const [historyLoaded, setHistoryLoaded] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Load chat history from DB on first open
  useEffect(() => {
    if (isOpen && !historyLoaded) {
      apiGet('/api/speak/history')
        .then(data => {
          if (data.session_id) {
            setSessionId(data.session_id);
            if (data.messages && data.messages.length > 0) {
              setMessages(data.messages);
            }
          }
          setHistoryLoaded(true);
        })
        .catch(() => setHistoryLoaded(true));
    }
  }, [isOpen, historyLoaded]);

  const sendMessage = async (text: string) => {
    if (!text.trim()) return;
    
    const userMessage = { role: 'user', content: text };
    setMessages(prev => [...prev, userMessage]);
    setMessage('');
    setIsLoading(true);

    try {
      const data = await apiPost('/api/speak/chat', { message: text, session_id: sessionId });
      if (data.session_id) setSessionId(data.session_id);
      setMessages(prev => [...prev, { role: 'assistant', content: data.response }]);
    } catch (e) {
      setMessages(prev => [...prev, { role: 'assistant', content: 'Sorry, I was unable to process that request. The AI service may be temporarily unavailable. Please try again.' }]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSend = () => sendMessage(message);

  return (
    <>
      <button 
        onClick={() => setIsOpen(true)}
        className="fixed bottom-6 right-6 bg-primary-500 hover:bg-primary-600 text-white p-4 rounded-full shadow-lg shadow-primary-500/30 transition-transform hover:scale-105 z-50 flex items-center gap-2 font-medium"
      >
        <MessageSquare size={24} />
        <span className="hidden md:inline pr-2">SPEAK</span>
      </button>

      {isOpen && (
        <div className="fixed bottom-6 right-6 w-[380px] h-[600px] max-h-[80vh] glass-panel rounded-2xl flex flex-col z-50 shadow-2xl animate-in slide-in-from-bottom-8 duration-300 border border-border overflow-hidden">
          <div className="p-4 border-b border-border bg-surface flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-full bg-primary-500/20 flex items-center justify-center text-primary-500">
                <Bot size={18} />
              </div>
              <div>
                <h3 className="font-bold text-sm">SPEAK Assistant</h3>
                <p className="text-[10px] text-primary-500 uppercase tracking-wider font-semibold">Tempris AI Orchestrator</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => { setMessages([]); setSessionId(null); }}
                title="New Chat"
                className="text-text-muted hover:text-primary-500 transition-colors p-1 rounded-md hover:bg-primary-500/10"
              >
                <RotateCcw size={16} />
              </button>
              <button onClick={() => setIsOpen(false)} className="text-text-muted hover:text-text-main transition-colors">
                <X size={20} />
              </button>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {messages.length === 0 && (
              <div className="text-center text-text-muted text-sm mt-6">
                <Bot size={32} className="mx-auto mb-3 opacity-50" />
                <p className="font-medium">Hello! I am your Tempris AI Assistant.</p>
                <p className="text-xs mt-1 opacity-70 mb-6">Powered by CISA KEV intelligence. Ask me anything.</p>
                
                <div className="space-y-2 text-left">
                  {[
                    "What is our ransomware exposure?",
                    "How many total vulnerabilities do we have?",
                    "What is our MAS TRM compliance status?",
                    "How do we mitigate the top threat?"
                  ].map((prompt) => (
                    <button 
                      key={prompt}
                      onClick={() => sendMessage(prompt)}
                      className="w-full text-left px-3 py-2.5 rounded-lg bg-surface border border-border text-xs hover:border-primary-500/30 hover:bg-primary-500/5 transition-colors text-text-main"
                    >
                      💬 {prompt}
                    </button>
                  ))}
                </div>
              </div>
            )}
            {messages.map((msg, i) => (
              <div key={i} className={`flex gap-3 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>
                <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 ${msg.role === 'user' ? 'bg-surface text-text-main' : 'bg-primary-500/20 text-primary-500'}`}>
                  {msg.role === 'user' ? <User size={14} /> : <Bot size={14} />}
                </div>
                <div className={`p-3 rounded-2xl text-sm ${msg.role === 'user' ? 'bg-surface text-text-main rounded-tr-sm' : 'bg-primary-500/10 border border-primary-500/20 text-text-main rounded-tl-sm'}`}>
                  {msg.content}
                </div>
              </div>
            ))}
            {isLoading && (
              <div className="flex gap-3">
                <div className="w-8 h-8 rounded-full bg-primary-500/20 flex items-center justify-center text-primary-500 shrink-0">
                  <Bot size={14} />
                </div>
                <div className="p-3 rounded-2xl bg-primary-500/10 border border-primary-500/20 rounded-tl-sm flex items-center">
                  <Loader2 size={16} className="animate-spin text-primary-500" />
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          <div className="p-4 border-t border-border bg-surface">
            <div className="relative">
              <input 
                type="text" 
                value={message}
                onChange={e => setMessage(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleSend()}
                placeholder="Ask Tempris AI..."
                className="w-full bg-background border border-border rounded-xl pl-4 pr-12 py-3 text-sm focus:outline-none focus:border-primary-500/50 transition-colors"
              />
              <button 
                onClick={handleSend}
                disabled={!message.trim() || isLoading}
                className="absolute right-2 top-1/2 -translate-y-1/2 w-8 h-8 rounded-lg bg-primary-500 text-white flex items-center justify-center hover:bg-primary-600 disabled:opacity-50 transition-colors"
              >
                <Send size={14} className="ml-[-2px]" />
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
