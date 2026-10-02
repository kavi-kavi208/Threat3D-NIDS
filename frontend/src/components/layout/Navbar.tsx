import React from 'react';
import { Shield, LogOut, User, Menu, X, Cpu, Radio, Languages, Mic } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useLanguage } from '../../context/LanguageContext';
import { useVoice } from '../../context/VoiceContext';
import { Badge } from '../common/Badge';

interface NavbarProps {
  onToggleSidebar?: () => void;
  isSidebarOpen?: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  onToggleSidebar,
  isSidebarOpen = false,
}) => {
  const { user, logout } = useAuth();
  const { language, toggleLanguage, isTamil, t } = useLanguage();
  const { isListening, isSpeaking, toggleWidget } = useVoice();

  const getRoleBadgeVariant = (role?: string) => {
    if (!role) return 'neutral';
    const r = role.toUpperCase();
    if (r.includes('ADMIN')) return 'admin';
    if (r.includes('ANALYST')) return 'analyst';
    if (r.includes('STUDENT')) return 'student';
    return 'neutral';
  };

  return (
    <header className="cyber-navbar">
      <div className="cyber-navbar-left">
        <button
          type="button"
          className="cyber-mobile-menu-btn"
          onClick={onToggleSidebar}
          aria-label="Toggle navigation menu"
        >
          {isSidebarOpen ? <X size={20} /> : <Menu size={20} />}
        </button>

        <div className="cyber-brand">
          <div className="cyber-brand-logo">
            <Shield size={20} className="text-cyan-400" />
          </div>
          <div className="cyber-brand-text">
            <span className="cyber-brand-title">{t('app.title')}</span>
            <span className="cyber-brand-sub">{t('app.subtitle')}</span>
          </div>
        </div>

        <div className="cyber-status-pill hidden md:flex">
          <span className="cyber-pulse-dot" />
          <Radio size={13} className="text-emerald-400" />
          <span className="text-xs text-emerald-300 font-mono">{t('nav.engineOnline')}</span>
        </div>

        <div className="cyber-academic-pill hidden lg:flex items-center gap-1.5">
          {user?.role?.toUpperCase().includes('ADMIN') ? (
            <>
              <Shield size={13} className="text-pink-400" />
              <span className="text-xs text-pink-300 font-mono">CLEARANCE: LEVEL 3 &bull; ADMIN (FULL OPS)</span>
            </>
          ) : user?.role?.toUpperCase().includes('ANALYST') ? (
            <>
              <Cpu size={13} className="text-cyan-400" />
              <span className="text-xs text-cyan-300 font-mono">CLEARANCE: LEVEL 2 &bull; ANALYST (THREAT OPS)</span>
            </>
          ) : (
            <>
              <Cpu size={13} className="text-emerald-400" />
              <span className="text-xs text-emerald-300 font-mono">CLEARANCE: LEVEL 1 &bull; STUDENT (READ-ONLY LAB)</span>
            </>
          )}
        </div>
      </div>

      <div className="cyber-navbar-right">
        {/* Bilingual Language Switcher */}
        <button
          type="button"
          className="cyber-lang-btn"
          onClick={toggleLanguage}
          title={isTamil ? t('common.switchToEnglish') : t('common.switchToTamil')}
          aria-label={t('common.language')}
        >
          <Languages size={15} className="text-cyan-400" />
          <span className="cyber-lang-label font-mono text-xs">{language === 'en' ? 'தமிழ்' : 'EN'}</span>
        </button>

        {/* NOVA Tactical Voice Assistant Button */}
        <button
          type="button"
          className={`cyber-voice-nav-btn ${isListening ? 'cyber-voice-nav-btn--listening' : ''} ${isSpeaking ? 'cyber-voice-nav-btn--speaking' : ''}`}
          onClick={toggleWidget}
          title={t('voice.navBtnTitle')}
          aria-label={t('voice.navBtnTitle')}
        >
          <Mic size={15} className={isListening ? 'text-red-400 animate-pulse' : isSpeaking ? 'text-purple-400 animate-pulse' : 'text-cyan-400'} />
          <span className="font-mono text-xs hidden md:inline">NOVA</span>
        </button>

        {user ? (
          <div className="cyber-user-profile">
            <div className="cyber-user-info hidden sm:flex">
              <span className="cyber-user-name">{user.fullName || user.username}</span>
              <Badge variant={getRoleBadgeVariant(user.role)} size="sm">
                {user.role?.replace('ROLE_', '') || 'ANALYST'}
              </Badge>
            </div>

            <button
              type="button"
              className="cyber-logout-btn"
              onClick={logout}
              title="Sign out of SOC console"
              aria-label={t('common.logout')}
            >
              <LogOut size={16} />
              <span className="hidden sm:inline">{t('common.logout')}</span>
            </button>
          </div>
        ) : (
          <div className="flex items-center gap-2">
            <User size={18} className="text-slate-400" />
            <span className="text-xs text-slate-400 font-mono">{t('common.guest')}</span>
          </div>
        )}
      </div>
    </header>
  );
};
