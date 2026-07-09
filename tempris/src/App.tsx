import { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, NavLink } from 'react-router-dom';
import { LayoutDashboard, Activity, Target, Shield, FileText, Settings, ShieldAlert, LogOut, ClipboardCheck, Server, Bug } from 'lucide-react';
import SpeakWidget from './components/SpeakWidget';
import LoginPage from './components/LoginPage';
import { clearToken } from './lib/api';

import Synthesis from './components/Synthesis';
import Spectrum from './components/Spectrum';
import Scout from './components/Scout';
import Surge from './components/Surge';
import Strike from './components/Strike';
import Standard from './components/Standard';
import Spotlight from './components/Spotlight';
import AuditLog from './components/AuditLog';
import GrcTes from './components/GrcTes';
import Assets from './components/Assets';
import SecurityPolicy from './components/SecurityPolicy';
import ErrorBoundary from './components/ErrorBoundary';

type TemprisUser = {
  name?: string;
  role?: string;
  email?: string;
};

function Sidebar({ user, onLogout }: { user: TemprisUser; onLogout: () => void }) {
  const allNavItems = [
    { name: 'SYNTHESIS', path: '/', icon: <LayoutDashboard size={20} /> },
    { name: 'SPECTRUM', path: '/spectrum', icon: <Activity size={20} /> },
    { name: 'SCOUT', path: '/scout', icon: <Target size={20} /> },
    { name: 'SURGE', path: '/surge', icon: <Bug size={20} /> },
    { name: 'STRIKE', path: '/strike', icon: <Shield size={20} /> },
    { name: 'STANDARD', path: '/standard', icon: <FileText size={20} /> },
    { name: 'GRC', path: '/grc', icon: <ClipboardCheck size={20} /> },
    { name: 'ASSETS', path: '/assets', icon: <Server size={20} /> },
    { name: 'SPOTLIGHT', path: '/spotlight', icon: <FileText size={20} /> },
  ];
  const navItems = user.role === 'Read-only'
    ? allNavItems.filter(item => item.name === 'STANDARD')
    : allNavItems;

  return (
    <div className="w-64 bg-surface border-r border-border h-screen flex flex-col fixed left-0 top-0 z-40">
      <div className="p-6 flex items-center gap-3">
        <div className="w-8 h-8 rounded bg-primary-500 flex items-center justify-center text-white">
          <ShieldAlert size={20} />
        </div>
        <span className="font-bold text-xl tracking-wide">TEMPRIS</span>
      </div>

      <nav className="flex-1 px-4 py-4 space-y-1">
        <div className="text-xs font-semibold text-text-muted mb-4 uppercase tracking-wider px-2">Wave 1 Modules</div>
        {navItems.map((item) => (
          <NavLink
            key={item.name}
            to={item.path}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors ${
                isActive 
                  ? 'bg-primary-500/10 text-primary-400 font-medium border border-primary-500/20' 
                  : 'text-text-muted hover:bg-surfaceHover hover:text-text-main border border-transparent'
              }`
            }
          >
            {item.icon}
            <span>{item.name}</span>
          </NavLink>
        ))}
      </nav>

      <div className="p-4 border-t border-border">
        <NavLink to="/audit" className={({ isActive }) => `flex items-center gap-3 px-3 py-2 cursor-pointer transition-colors ${isActive ? 'text-primary-400 font-medium' : 'text-text-muted hover:text-text-main'}`}>
          <Settings size={20} />
          <span>Audit Log</span>
        </NavLink>
        <div 
          onClick={onLogout}
          className="flex items-center gap-3 px-3 py-2 text-text-muted hover:text-danger cursor-pointer transition-colors mt-1"
        >
          <LogOut size={20} />
          <span>Logout</span>
        </div>
      </div>
    </div>
  );
}

function Topbar({ user }: { user: TemprisUser }) {
  // Extract initials
  const initials = user?.name ? user.name.substring(0, 2).toUpperCase() : 'U';

  return (
    <div className="h-16 bg-background/80 backdrop-blur-md border-b border-border sticky top-0 z-30 flex items-center justify-between px-8">
      <div className="text-sm font-medium text-text-muted">
        Demo Environment <span className="px-2 py-0.5 ml-2 bg-primary-500/10 text-primary-400 rounded text-xs border border-primary-500/20">AI Engine Active</span>
      </div>
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-full bg-surfaceHover border border-border flex items-center justify-center font-bold text-xs text-primary-400">
            {initials}
          </div>
          <div className="text-sm">
            <div className="font-medium">{user?.role || 'User'}</div>
            <div className="text-xs text-text-muted">{user?.email || 'user@tempris.com'}</div>
          </div>
        </div>
      </div>
    </div>
  );
}

function AuthenticatedApp({ user, onLogout }: { user: TemprisUser; onLogout: () => void }) {
  const isReadOnly = user.role === 'Read-only';

  return (
    <div className="min-h-screen bg-background flex text-text-main font-sans">
      <Sidebar user={user} onLogout={onLogout} />
      <div className="flex-1 ml-64 flex flex-col relative min-h-screen">
         {/* Global background glow */}
        <div className="fixed top-[-20%] left-[20%] w-[50%] h-[50%] bg-primary-600/10 blur-[120px] rounded-full pointer-events-none z-0" />

        <Topbar user={user} />
        <main className="flex-1 relative z-10 p-6 overflow-y-auto">
          <Routes>
            <Route path="/" element={isReadOnly ? <ErrorBoundary moduleName="STANDARD"><Standard user={user} /></ErrorBoundary> : <ErrorBoundary moduleName="SYNTHESIS"><Synthesis /></ErrorBoundary>} />
            <Route path="/spectrum" element={<ErrorBoundary moduleName="SPECTRUM"><Spectrum /></ErrorBoundary>} />
            <Route path="/scout" element={<ErrorBoundary moduleName="SCOUT"><Scout /></ErrorBoundary>} />
            <Route path="/surge" element={<ErrorBoundary moduleName="SURGE"><Surge /></ErrorBoundary>} />
            <Route path="/strike" element={<ErrorBoundary moduleName="STRIKE"><Strike /></ErrorBoundary>} />
            <Route path="/standard" element={<ErrorBoundary moduleName="STANDARD"><Standard user={user} /></ErrorBoundary>} />
            <Route path="/grc" element={<ErrorBoundary moduleName="GRC"><GrcTes /></ErrorBoundary>} />
            <Route path="/assets" element={<ErrorBoundary moduleName="ASSETS"><Assets /></ErrorBoundary>} />
            <Route path="/spotlight" element={<ErrorBoundary moduleName="SPOTLIGHT"><Spotlight /></ErrorBoundary>} />
            <Route path="/audit" element={<ErrorBoundary moduleName="AUDIT"><AuditLog /></ErrorBoundary>} />
          </Routes>
        </main>
      </div>
      {!isReadOnly && <SpeakWidget />}
    </div>
  );
}

function App() {
  const [user, setUser] = useState<TemprisUser | null>(null);

  const handleLogout = () => {
    clearToken();
    setUser(null);
  };

  const handleLogin = (nextUser: TemprisUser) => {
    setUser(nextUser);
  };

  // Listen for auth expiry events from apiFetch
  useEffect(() => {
    const handleExpiry = () => {
      setUser(null);
    };
    window.addEventListener('tempris:logout', handleExpiry);
    return () => window.removeEventListener('tempris:logout', handleExpiry);
  }, []);

  return (
    <Router>
      <Routes>
        <Route path="/security" element={<SecurityPolicy />} />
        <Route path="/vdp" element={<SecurityPolicy />} />
        <Route
          path="/*"
          element={user ? <AuthenticatedApp user={user} onLogout={handleLogout} /> : <LoginPage onLogin={handleLogin} />}
        />
      </Routes>
    </Router>
  );
}

export default App;

