import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Network,
  AlertOctagon,
  PlayCircle,
  Activity,
  ShieldCheck,
  Info,
  Terminal,
  BookOpen,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useLanguage } from '../../context/LanguageContext';
import { Badge } from '../common/Badge';

interface SidebarProps {
  isOpen?: boolean;
  onClose?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ isOpen = false, onClose }) => {
  const { user, hasRole } = useAuth();
  const { t } = useLanguage();

  const isAdmin = hasRole('ADMIN');
  const isAnalyst = hasRole('ANALYST');
  const isStudent = hasRole('STUDENT') && !isAdmin && !isAnalyst;

  const allNavItems = [
    {
      label: t('nav.dashboard'),
      path: '/',
      icon: <LayoutDashboard size={18} />,
      badge: null,
      allowedRoles: ['ROLE_ADMIN', 'ROLE_ANALYST', 'ROLE_STUDENT'],
    },
    {
      label: t('nav.topology'),
      path: '/topology',
      icon: <Network size={18} />,
      badge: t('nav.badge3dReady'),
      allowedRoles: ['ROLE_ADMIN', 'ROLE_ANALYST', 'ROLE_STUDENT'],
    },
    {
      label: t('nav.threats'),
      path: '/threats',
      icon: <AlertOctagon size={18} />,
      badge: null,
      allowedRoles: ['ROLE_ADMIN', 'ROLE_ANALYST', 'ROLE_STUDENT'],
    },
    {
      label: t('nav.learning'),
      path: '/learning',
      icon: <BookOpen size={18} />,
      badge: isStudent ? 'LAB' : null,
      allowedRoles: ['ROLE_ADMIN', 'ROLE_ANALYST', 'ROLE_STUDENT'],
    },
    {
      label: t('nav.simulation'),
      path: '/simulation',
      icon: <PlayCircle size={18} />,
      badge: t('nav.badgeLive'),
      allowedRoles: ['ROLE_ADMIN', 'ROLE_ANALYST'],
    },
    {
      label: t('nav.traffic'),
      path: '/traffic',
      icon: <Activity size={18} />,
      badge: null,
      allowedRoles: ['ROLE_ADMIN', 'ROLE_ANALYST'],
    },
    {
      label: t('nav.rules'),
      path: '/rules',
      icon: <ShieldCheck size={18} />,
      badge: isAdmin ? 'ADMIN' : null,
      allowedRoles: ['ROLE_ADMIN', 'ROLE_ANALYST'],
    },
  ];

  // Filter items strictly based on role
  const visibleNavItems = allNavItems.filter((item) =>
    item.allowedRoles.some((role) => hasRole(role))
  );

  return (
    <>
      {isOpen && <div className="cyber-sidebar-overlay" onClick={onClose} />}
      <aside className={`cyber-sidebar ${isOpen ? 'cyber-sidebar--open' : ''}`}>
        <div className="cyber-sidebar-section">
          <div className="flex items-center justify-between px-2 pb-2">
            <span className="cyber-sidebar-heading p-0">{t('nav.coreHeading')}</span>
            <span className="text-[10px] font-mono text-slate-500">
              {isAdmin ? 'ALL' : isAnalyst ? 'OPS' : 'STUDENT'}
            </span>
          </div>
          <nav className="cyber-sidebar-nav">
            {visibleNavItems.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                end={item.path === '/'}
                className={({ isActive }) =>
                  `cyber-nav-item ${isActive ? 'cyber-nav-item--active' : ''}`
                }
                onClick={onClose}
              >
                <span className="cyber-nav-icon">{item.icon}</span>
                <span className="cyber-nav-label">{item.label}</span>
                {item.badge && <span className="cyber-nav-badge">{item.badge}</span>}
              </NavLink>
            ))}
          </nav>
        </div>

        <div className="cyber-sidebar-section mt-auto">
          <div className="cyber-sidebar-rbac-info">
            <div className="flex items-center justify-between text-xs text-slate-400 font-mono mb-1.5">
              <div className="flex items-center gap-1.5">
                <Terminal size={14} className="text-cyan-400" />
                <span>{t('nav.securityClearance')}</span>
              </div>
              <Badge
                variant={isAdmin ? 'admin' : isAnalyst ? 'analyst' : 'student'}
                size="sm"
              >
                {isAdmin ? 'ADMIN' : isAnalyst ? 'ANALYST' : 'STUDENT'}
              </Badge>
            </div>
            <div className="text-[11px] text-slate-300 font-mono">
              {user?.fullName || user?.username}
            </div>
            <div className="text-[10px] text-slate-400 mt-1">
              {isAdmin
                ? 'Level 3: Full System Control'
                : isAnalyst
                ? 'Level 2: Threat Ops & Mitigation'
                : 'Level 1: Academic Read-Only'}
            </div>
          </div>

          <div className="cyber-sidebar-academic-notice">
            <div className="flex items-start gap-1.5 text-[11px] text-slate-400 leading-tight">
              <Info size={14} className="text-amber-400 flex-shrink-0 mt-0.5" />
              <span>
                <strong>{t('nav.academicScope')}</strong> {t('nav.academicNotice')}
              </span>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
};
