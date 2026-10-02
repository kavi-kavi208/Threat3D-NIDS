// Threat3D NIDS Authentication & RBAC Context
import React, { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react';
import type { AuthResponse, UserRole } from '../types';
import {
  authApi,
  getStoredToken,
  getStoredUser,
  setStoredToken,
  setStoredUser,
  clearStoredAuth,
} from '../services/api';

interface AuthContextType {
  user: AuthResponse | null;
  token: string | null;
  role: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: { username: string; password: string }) => Promise<void>;
  register: (registration: {
    username: string;
    password: string;
    fullName: string;
    email: string;
    role?: string;
  }) => Promise<void>;
  logout: () => void;
  hasRole: (requiredRole: UserRole | UserRole[] | string | string[]) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<AuthResponse | null>(() => getStoredUser());
  const [token, setToken] = useState<string | null>(() => getStoredToken());
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const logout = useCallback(() => {
    authApi.logout();
    setUser(null);
    setToken(null);
  }, []);

  // Validate stored session on startup
  useEffect(() => {
    const initAuth = async () => {
      const storedToken = getStoredToken();
      if (storedToken) {
        try {
          const profile = await authApi.getProfile();
          if (profile) {
            // Re-sync user info
            const existingUser = getStoredUser();
            const updatedUser: AuthResponse = {
              token: storedToken,
              type: 'Bearer',
              username: profile.username,
              fullName: profile.fullName,
              role: profile.role,
              expiresInMs: existingUser?.expiresInMs || 86400000,
            };
            setUser(updatedUser);
            setToken(storedToken);
            setStoredUser(updatedUser);
          }
        } catch {
          // Token expired or invalid
          clearStoredAuth();
          setUser(null);
          setToken(null);
        }
      }
      setIsLoading(false);
    };

    initAuth();

    const handleUnauthorized = () => {
      logout();
    };

    window.addEventListener('threat3d:unauthorized', handleUnauthorized);
    return () => {
      window.removeEventListener('threat3d:unauthorized', handleUnauthorized);
    };
  }, [logout]);

  const login = async (credentials: { username: string; password: string }) => {
    setIsLoading(true);
    try {
      const authData = await authApi.login(credentials);
      setUser(authData);
      setToken(authData.token);
      setStoredToken(authData.token);
      setStoredUser(authData);
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (registration: {
    username: string;
    password: string;
    fullName: string;
    email: string;
    role?: string;
  }) => {
    setIsLoading(true);
    try {
      const authData = await authApi.register(registration);
      setUser(authData);
      setToken(authData.token);
      setStoredToken(authData.token);
      setStoredUser(authData);
    } finally {
      setIsLoading(false);
    }
  };

  const hasRole = useCallback(
    (requiredRole: UserRole | UserRole[] | string | string[]): boolean => {
      if (!user || !user.role) return false;
      const userRole = user.role.toUpperCase();
      const userCleanRole = userRole.replace('ROLE_', '');

      const roles = Array.isArray(requiredRole) ? requiredRole : [requiredRole];
      return roles.some((r) => {
        const checkRole = r.toUpperCase();
        const cleanCheckRole = checkRole.replace('ROLE_', '');
        return userRole === checkRole || userCleanRole === cleanCheckRole;
      });
    },
    [user]
  );

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        role: user?.role || null,
        isAuthenticated: !!token && !!user,
        isLoading,
        login,
        register,
        logout,
        hasRole,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
