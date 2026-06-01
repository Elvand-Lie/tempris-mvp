import { useState } from 'react';
import { ShieldAlert, Bot } from 'lucide-react';

interface LoginPageProps {
  onLogin: (user: any) => void;
}

export default function LoginPage({ onLogin }: LoginPageProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('demo');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        throw new Error('Invalid credentials');
      }

      const data = await response.json();
      localStorage.setItem('tempris_token', data.access_token);
      onLogin(data.user);
    } catch (err: any) {
      setError(err.message || 'Failed to login');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex flex-col justify-center items-center relative overflow-hidden text-text-main">
      {/* Background glow */}
      <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] bg-primary-600/20 blur-[120px] rounded-full pointer-events-none" />
      <div className="absolute bottom-[-20%] right-[-10%] w-[40%] h-[40%] bg-blue-600/10 blur-[120px] rounded-full pointer-events-none" />
      
      <div className="w-full max-w-md glass-panel p-8 relative z-10 border border-border">
        <div className="flex flex-col items-center mb-8">
          <div className="w-16 h-16 rounded-xl bg-primary-500/10 border border-primary-500/20 flex items-center justify-center text-primary-500 mb-4">
            <ShieldAlert size={32} />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">TEMPRIS</h1>
          <p className="text-text-muted text-sm mt-1">CTEM & EDIP Foundation Platform</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {error && (
            <div className="p-3 bg-danger/10 border border-danger/20 text-danger text-sm rounded-lg text-center">
              {error}
            </div>
          )}
          
          <div>
            <label className="block text-xs font-medium text-text-muted mb-1 uppercase tracking-wider">Email Address</label>
            <input 
              type="email" 
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full bg-surface border border-border focus:border-primary-500/50 focus:ring-1 focus:ring-primary-500/50 outline-none rounded-lg px-4 py-2.5 transition-all text-sm"
              placeholder="sherie@tempris.com"
              required
            />
          </div>
          
          <div>
            <label className="block text-xs font-medium text-text-muted mb-1 uppercase tracking-wider">Password</label>
            <input 
              type="password" 
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-surface border border-border focus:border-primary-500/50 focus:ring-1 focus:ring-primary-500/50 outline-none rounded-lg px-4 py-2.5 transition-all text-sm"
              placeholder="••••••••"
              required
            />
          </div>

          <button 
            type="submit" 
            disabled={isLoading}
            className="w-full bg-primary-500 hover:bg-primary-600 text-white font-medium py-2.5 rounded-lg transition-colors flex justify-center items-center gap-2 shadow-lg shadow-primary-500/20 disabled:opacity-50 mt-2"
          >
            {isLoading ? (
               <><div className="w-4 h-4 rounded-full border-2 border-white/30 border-t-white animate-spin" /> Authenticating...</>
            ) : (
              'Secure Login'
            )}
          </button>
        </form>
        
        <div className="mt-8 pt-6 border-t border-border">
          <p className="text-xs text-text-muted font-medium mb-3">Demo Accounts Available:</p>
          <div className="space-y-2">
            <button onClick={() => { setEmail('sherie@tempris.com'); setPassword('demo'); }} className="w-full text-left text-xs p-2 rounded bg-surfaceHover border border-border hover:border-primary-500/30 transition-colors">
              <span className="font-bold text-primary-400">Superadmin</span> • sherie@tempris.com
            </button>
            <button onClick={() => { setEmail('admin@tempris.com'); setPassword('demo'); }} className="w-full text-left text-xs p-2 rounded bg-surfaceHover border border-border hover:border-primary-500/30 transition-colors">
              <span className="font-bold text-text-main">Admin</span> • admin@tempris.com
            </button>
            <button onClick={() => { setEmail('analyst@tempris.com'); setPassword('demo'); }} className="w-full text-left text-xs p-2 rounded bg-surfaceHover border border-border hover:border-primary-500/30 transition-colors">
              <span className="font-bold text-text-main">Analyst</span> • analyst@tempris.com
            </button>
            <button onClick={() => { setEmail('viewer@tempris.com'); setPassword('demo'); }} className="w-full text-left text-xs p-2 rounded bg-surfaceHover border border-border hover:border-primary-500/30 transition-colors">
              <span className="font-bold text-text-muted">Viewer</span> • viewer@tempris.com
            </button>
            <button onClick={() => { setEmail('readonly@tempris.com'); setPassword('demo'); }} className="w-full text-left text-xs p-2 rounded bg-surfaceHover border border-border hover:border-primary-500/30 transition-colors">
              <span className="font-bold text-text-muted">Read-only</span> • readonly@tempris.com
            </button>
          </div>
        </div>
      </div>
      
      <div className="absolute bottom-8 text-xs text-text-muted flex items-center gap-2">
        <Bot size={14} /> Powered by Codingo Wave 1 Architecture
      </div>
    </div>
  );
}
