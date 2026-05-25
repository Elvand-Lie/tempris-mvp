import { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, NavLink } from 'react-router-dom';
import { LayoutDashboard, Activity, Target, Shield, FileText, Settings, ShieldAlert, LogOut } from 'lucide-react';
import SpeakWidget from './components/SpeakWidget';
import LoginPage from './components/LoginPage';

import Synthesis from './components/Synthesis';
import Spectrum from './components/Spectrum';
import Scout from './components/Scout';
import Strike from './components/Strike';
import Standard from './components/Standard';
import Spotlight from './components/Spotlight';
import AuditLog from './components/AuditLog';

function Sidebar({ onLogout }: { onLogout: () => void }) {
  const navItems = [
    { name: 'SYNTHESIS', path: '/', icon: <LayoutDashboard size={20} /> },
    { name: 'SPECTRUM', path: '/spectrum', icon: <Activity size={20} /> },
    { name: 'SCOUT', path: '/scout', icon: <Target size={20} /> },
    { name: 'STRIKE', path: '/strike', icon: <Shield size={20} /> },
    { name: 'STANDARD', path: '/standard', icon: <FileText size={20} /> },
    { name: 'SPOTLIGHT', path: '/spotlight', icon: <FileText size={20} /> },
  ];

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

function Topbar({ user }: { user: any }) {
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

function App() {
  const [user, setUser] = useState<any>(null);

  const handleLogout = () => {
    localStorage.removeItem('tempris_token');
    setUser(null);
  };

  if (!user) {
    return <LoginPage onLogin={setUser} />;
  }

  return (
    <Router>
      <div className="min-h-screen bg-background flex text-text-main font-sans">
        <Sidebar onLogout={handleLogout} />
        <div className="flex-1 ml-64 flex flex-col relative min-h-screen">
           {/* Global background glow */}
          <div className="fixed top-[-20%] left-[20%] w-[50%] h-[50%] bg-primary-600/10 blur-[120px] rounded-full pointer-events-none z-0" />
          
          <Topbar user={user} />
          <main className="flex-1 relative z-10 p-6 overflow-y-auto">
            <Routes>
              <Route path="/" element={<Synthesis />} />
              <Route path="/spectrum" element={<Spectrum />} />
              <Route path="/scout" element={<Scout />} />
              <Route path="/strike" element={<Strike />} />
              <Route path="/standard" element={<Standard />} />
              <Route path="/spotlight" element={<Spotlight />} />
              <Route path="/audit" element={<AuditLog />} />
            </Routes>
          </main>
        </div>
        <SpeakWidget />
      </div>
    </Router>
  );
}

export default App;
