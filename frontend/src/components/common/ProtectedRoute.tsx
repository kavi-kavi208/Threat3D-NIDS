import React from 'react';
import { Navigate, useLocation, Link } from 'react-router-dom';
import { ShieldAlert } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { LoadingSpinner } from './LoadingSpinner';
import type { UserRole } from '../../types';

interface ProtectedRouteProps {
  children: React.ReactNode;
  allowedRoles?: (UserRole | string)[];
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  children,
  allowedRoles,
}) => {
  const { isAuthenticated, isLoading, hasRole, user } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return <LoadingSpinner fullScreen message="Authenticating SOC session..." />;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (allowedRoles && allowedRoles.length > 0) {
    const isAuthorized = allowedRoles.some((role) => hasRole(role));
    if (!isAuthorized) {
      return (
        <div className="cyber-unauthorized-view">
          <div className="cyber-unauthorized-card">
            <div className="flex justify-center mb-3">
              <div className="w-12 h-12 rounded-xl bg-red-950/60 border border-red-500/50 flex items-center justify-center text-red-400">
                <ShieldAlert size={28} />
              </div>
            </div>
            <h2 className="text-xl font-bold text-red-400 mb-2">Access Restricted</h2>
            <p className="text-sm text-slate-300 mb-4">
              Your account ({user?.username} &mdash; <span className="font-mono text-cyan-300">{user?.role}</span>) does not have sufficient
              security clearance for this operational resource.
            </p>
            <div className="p-3 bg-slate-900/80 border border-slate-800 rounded mb-5 text-left">
              <span className="text-[10px] text-slate-500 uppercase tracking-wider font-mono block mb-1">
                RBAC Security Policy
              </span>
              <p className="text-xs text-slate-400 font-mono">
                Required Clearance: <span className="text-amber-400 font-semibold">{allowedRoles.join(' | ')}</span>
              </p>
            </div>
            <Link to="/" className="cyber-button cyber-button--primary cyber-button--sm inline-flex">
              Return to SOC Dashboard
            </Link>
          </div>
        </div>
      );
    }
  }

  return <>{children}</>;
};
