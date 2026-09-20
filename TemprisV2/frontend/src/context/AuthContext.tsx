import React, { createContext, useContext, useEffect, useState } from 'react';
import { api, AUTH_UNAUTHORIZED_EVENT, getCurrentSession } from '../api';
import { AuthState, TenantInfo, UserProfile } from '../types';

interface AuthContextValue extends AuthState {
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  retryMetadata: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export const AuthProvider: React.FC<React.PropsWithChildren> = ({ children }) => {
  const [session, setSession] = useState(() => getCurrentSession());
  const [user, setUser] = useState<UserProfile | null>(null);
  const [activeTenant, setActiveTenant] = useState<TenantInfo | null>(null);
  const [effectiveModules, setEffectiveModules] = useState<string[]>([]);
  const [metadataLoading, setMetadataLoading] = useState(Boolean(session));
  const [metadataError, setMetadataError] = useState<string | null>(null);
  const [metadataRevision, setMetadataRevision] = useState(0);

  const reset = () => {
    setSession(null);
    setUser(null);
    setActiveTenant(null);
    setEffectiveModules([]);
    setMetadataLoading(false);
    setMetadataError(null);
  };

  useEffect(() => {
    const handleUnauthorized = () => reset();
    const handleStorage = () => {
      const current = getCurrentSession();
      setMetadataLoading(Boolean(current));
      setSession(current);
    };
    window.addEventListener(AUTH_UNAUTHORIZED_EVENT, handleUnauthorized);
    window.addEventListener('storage', handleStorage);
    return () => {
      window.removeEventListener(AUTH_UNAUTHORIZED_EVENT, handleUnauthorized);
      window.removeEventListener('storage', handleStorage);
    };
  }, []);

  useEffect(() => {
    if (!session) {
      setUser(null);
      setActiveTenant(null);
      setEffectiveModules([]);
      setMetadataLoading(false);
      setMetadataError(null);
      return;
    }

    let active = true;
    setMetadataLoading(true);
    setMetadataError(null);
    setActiveTenant(null);
    setEffectiveModules([]);
    setUser({ email: String(session.payload.email || session.payload.sub || ''), is_platform_admin: false });

    api.getTenantMetadata()
      .then((metadata) => {
        if (!active) return;
        if (
          typeof metadata.id !== 'string' || !metadata.id.trim()
          || typeof metadata.name !== 'string' || !metadata.name.trim()
          || typeof metadata.slug !== 'string' || !metadata.slug.trim()
          || !Array.isArray(metadata.effective_modules)
          || !metadata.effective_modules.every((module) => typeof module === 'string')
          || typeof metadata.is_platform_admin !== 'boolean'
        ) {
          throw new Error('Organization metadata response was incomplete.');
        }
        setActiveTenant({
          id: metadata.id,
          name: metadata.name,
          slug: metadata.slug,
          status: metadata.status,
          created_at: metadata.created_at,
        });
        setEffectiveModules(metadata.effective_modules);
        setUser({
          email: String(session.payload.email || session.payload.sub || ''),
          is_platform_admin: metadata.is_platform_admin === true,
        });
      })
      .catch((error: any) => {
        if (active && error.status !== 401) {
          setMetadataError(error.message || 'Failed to load organization metadata.');
        }
      })
      .finally(() => {
        if (active) setMetadataLoading(false);
      });

    return () => {
      active = false;
    };
  }, [session?.token, metadataRevision]);

  const login = async (email: string, password: string) => {
    await api.login({ email, password });
    const current = getCurrentSession();
    if (!current) throw new Error('Authentication response did not contain a valid session token.');
    setMetadataLoading(true);
    setMetadataError(null);
    setSession(current);
  };

  const logout = () => {
    api.logout();
    reset();
  };

  return (
    <AuthContext.Provider
      value={{
        token: session?.token || null,
        user,
        activeTenant,
        effectiveModules,
        currentRole: session?.role || 'analyst',
        metadataLoading,
        metadataError,
        isAuthenticated: Boolean(session),
        login,
        logout,
        retryMetadata: () => setMetadataRevision((value) => value + 1),
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
}
