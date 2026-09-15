import React, { createContext, useContext, useState, useEffect } from 'react';
import { api, tokenStorage } from '../services/api';

const AuthContext = createContext(null);

const STORAGE_KEY = 'threat_ai_auth_user';

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      const savedUser = localStorage.getItem(STORAGE_KEY);
      return savedUser ? JSON.parse(savedUser) : null;
    } catch (e) {
      console.error('Failed to parse saved auth from localStorage', e);
      return null;
    }
  });

  const isAuthenticated = !!user;

  // On mount, if a JWT session token exists, validate analyst clearance with live FastAPI backend
  useEffect(() => {
    let isMounted = true;

    const verifySession = async () => {
      const token = tokenStorage.get();
      if (!token) return;

      try {
        const freshUser = await api.getMe();
        if (isMounted && freshUser) {
          const userData = {
            id: freshUser.id,
            email: freshUser.email,
            name: freshUser.name,
            role: freshUser.role,
            initials: freshUser.initials || 'SO',
            department: freshUser.department,
            clearance: freshUser.clearance
          };
          setUser(userData);
          localStorage.setItem(STORAGE_KEY, JSON.stringify(userData));
        }
      } catch (err) {
        // If 401 Unauthorized, token has expired; clear invalid session
        if (err.status === 401 && isMounted) {
          tokenStorage.remove();
          localStorage.removeItem(STORAGE_KEY);
          setUser(null);
        }
        // If network error/backend offline, preserve local session
      }
    };

    verifySession();

    return () => {
      isMounted = false;
    };
  }, []);

  const login = async (email, password) => {
    const trimmedEmail = email.trim().toLowerCase();

    // 1. Attempt live authentication with FastAPI backend
    try {
      const authResponse = await api.login(trimmedEmail, password);
      if (authResponse && authResponse.user) {
        const userData = {
          id: authResponse.user.id,
          email: authResponse.user.email,
          name: authResponse.user.name,
          role: authResponse.user.role,
          initials: authResponse.user.initials || 'SO',
          department: authResponse.user.department,
          clearance: authResponse.user.clearance
        };
        setUser(userData);
        try {
          localStorage.setItem(STORAGE_KEY, JSON.stringify(userData));
        } catch (err) {
          console.error('Failed to save auth to localStorage', err);
        }
        return { success: true };
      }
    } catch (apiError) {
      // If server returned 401 or 403, credentials are invalid
      if (apiError.status === 401 || apiError.status === 403) {
        return {
          success: false,
          message: apiError.message || 'Invalid authorization credentials.'
        };
      }

      // 2. Resilient Offline Fallback (if backend is not running or network unreachable)
      const fallbackUsers = {
        'admin@threat.ai': {
          email: 'admin@threat.ai',
          name: 'System Administrator',
          role: 'Administrator',
          initials: 'SA',
          department: 'Security Operations',
          clearance: 'TOP SECRET // SCI'
        },
        'manager@threat.ai': {
          email: 'manager@threat.ai',
          name: 'Security Manager',
          role: 'Security Manager',
          initials: 'SM',
          department: 'Incident Response',
          clearance: 'TOP SECRET // SCI'
        },
        'engineer@threat.ai': {
          email: 'engineer@threat.ai',
          name: 'SOC Lead Engineer',
          role: 'SOC Engineer',
          initials: 'SE',
          department: 'SOC Engineering',
          clearance: 'SECRET'
        },
        'analyst@threat.ai': {
          email: 'analyst@threat.ai',
          name: 'Security Analyst',
          role: 'Security Analyst',
          initials: 'SO',
          department: 'Threat Triage',
          clearance: 'SECRET'
        }
      };

      if (fallbackUsers[trimmedEmail] && password === 'admin123') {
        const userData = fallbackUsers[trimmedEmail];
        setUser(userData);
        try {
          localStorage.setItem(STORAGE_KEY, JSON.stringify(userData));
        } catch (err) {
          console.error('Failed to save auth to localStorage', err);
        }
        return { success: true };
      }

      return {
        success: false,
        message: apiError.message || 'Invalid email or password.'
      };
    }

    return { success: false, message: 'Invalid email or password.' };
  };

  const logout = () => {
    setUser(null);
    tokenStorage.remove();
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch (err) {
      console.error('Failed to remove auth from localStorage', err);
    }
  };

  return (
    <AuthContext.Provider value={{ user, isAuthenticated, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

