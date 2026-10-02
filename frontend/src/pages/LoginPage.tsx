import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Shield, Lock, User, Key, UserCheck, AlertCircle, ShieldAlert, Languages } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useLanguage } from '../context/LanguageContext';
import { Button } from '../components/common/Button';

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, register, isAuthenticated } = useAuth();
  const { language, toggleLanguage, isTamil, t } = useLanguage();

  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('admin123');
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('ROLE_ANALYST');

  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const from = (location.state as { from?: { pathname: string } })?.from?.pathname || '/';

  // If already authenticated, redirect
  React.useEffect(() => {
    if (isAuthenticated) {
      navigate('/', { replace: true });
    }
  }, [isAuthenticated, navigate]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setIsLoading(true);

    try {
      if (mode === 'login') {
        await login({ username, password });
      } else {
        await register({
          username,
          password,
          fullName: fullName || username,
          email: email || `${username}@threat3d.local`,
          role,
        });
      }
      navigate(from, { replace: true });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Authentication failed. Check credentials.';
      setErrorMessage(msg);
    } finally {
      setIsLoading(false);
    }
  };

  const handleQuickFill = (userType: 'admin' | 'analyst' | 'student') => {
    setMode('login');
    setErrorMessage(null);
    if (userType === 'admin') {
      setUsername('admin');
      setPassword('Admin@12345');
    } else if (userType === 'analyst') {
      setUsername('analyst');
      setPassword('Analyst@12345');
    } else {
      setUsername('student');
      setPassword('Student@12345');
    }
  };

  return (
    <div className="cyber-auth-page">
      <div className="cyber-auth-grid-bg" />
      <div className="cyber-auth-container">
        <div className="cyber-auth-card">
          <div className="flex justify-end mb-2">
            <button
              type="button"
              className="cyber-lang-btn"
              onClick={toggleLanguage}
              title={isTamil ? t('common.switchToEnglish') : t('common.switchToTamil')}
              aria-label={t('common.language')}
            >
              <Languages size={14} className="text-cyan-400" />
              <span className="font-mono text-xs">{language === 'en' ? 'தமிழ்' : 'EN'}</span>
            </button>
          </div>

          <div className="cyber-auth-header">
            <div className="cyber-auth-logo">
              <Shield size={32} className="text-cyan-400" />
            </div>
            <h1 className="cyber-auth-title">{t('auth.loginTitle')}</h1>
            <p className="cyber-auth-subtitle">
              {t('auth.loginSub')}
            </p>
            <div className="cyber-auth-safety-pill">
              <ShieldAlert size={14} className="text-amber-400" />
              <span>{t('app.academicPill')}</span>
            </div>
          </div>

          <div className="cyber-auth-tabs">
            <button
              type="button"
              className={`cyber-auth-tab ${mode === 'login' ? 'cyber-auth-tab--active' : ''}`}
              onClick={() => {
                setMode('login');
                setErrorMessage(null);
              }}
            >
              {t('auth.tabLogin')}
            </button>
            <button
              type="button"
              className={`cyber-auth-tab ${mode === 'register' ? 'cyber-auth-tab--active' : ''}`}
              onClick={() => {
                setMode('register');
                setErrorMessage(null);
              }}
            >
              {t('auth.tabRegister')}
            </button>
          </div>

          {errorMessage && (
            <div className="cyber-auth-error">
              <AlertCircle size={16} className="flex-shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="cyber-auth-form">
            <div className="cyber-form-group">
              <label htmlFor="username" className="cyber-label">
                <User size={14} className="text-cyan-400" />
                <span>{t('auth.username')}</span>
              </label>
              <input
                id="username"
                type="text"
                required
                className="cyber-input"
                placeholder={t('auth.usernamePlaceholder')}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
              />
            </div>

            {mode === 'register' && (
              <>
                <div className="cyber-form-group">
                  <label htmlFor="fullName" className="cyber-label">
                    <UserCheck size={14} className="text-cyan-400" />
                    <span>{t('auth.fullName')}</span>
                  </label>
                  <input
                    id="fullName"
                    type="text"
                    required
                    className="cyber-input"
                    placeholder={t('auth.fullNamePlaceholder')}
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                  />
                </div>

                <div className="cyber-form-group">
                  <label htmlFor="email" className="cyber-label">
                    <span>{t('auth.email')}</span>
                  </label>
                  <input
                    id="email"
                    type="email"
                    required
                    className="cyber-input"
                    placeholder={t('auth.emailPlaceholder')}
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                </div>

                <div className="cyber-form-group">
                  <label htmlFor="role" className="cyber-label">
                    <Key size={14} className="text-cyan-400" />
                    <span>{t('auth.role')}</span>
                  </label>
                  <select
                    id="role"
                    className="cyber-input cyber-select"
                    value={role}
                    onChange={(e) => setRole(e.target.value)}
                  >
                    <option value="ROLE_ANALYST">{t('auth.roleAnalyst')}</option>
                    <option value="ROLE_STUDENT">{t('auth.roleStudent')}</option>
                    <option value="ROLE_ADMIN">{t('auth.roleAdmin')}</option>
                  </select>
                </div>
              </>
            )}

            <div className="cyber-form-group">
              <label htmlFor="password" className="cyber-label">
                <Lock size={14} className="text-cyan-400" />
                <span>{t('auth.password')}</span>
              </label>
              <input
                id="password"
                type="password"
                required
                className="cyber-input"
                placeholder={t('auth.passwordPlaceholder')}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
              />
            </div>

            <Button
              type="submit"
              variant="primary"
              size="lg"
              className="w-full mt-2"
              isLoading={isLoading}
            >
              {mode === 'login'
                ? (isLoading ? t('auth.authenticating') : t('auth.btnLogin'))
                : (isLoading ? t('auth.registering') : t('auth.btnRegister'))}
            </Button>
          </form>

          <div className="cyber-quick-auth">
            <span className="cyber-quick-auth-title">{t('auth.quickFillTitle')}</span>
            <div className="cyber-quick-buttons">
              <button
                type="button"
                className="cyber-quick-btn cyber-quick-btn--admin"
                onClick={() => handleQuickFill('admin')}
              >
                {t('auth.quickFillAdmin')}
              </button>
              <button
                type="button"
                className="cyber-quick-btn cyber-quick-btn--analyst"
                onClick={() => handleQuickFill('analyst')}
              >
                {t('auth.quickFillAnalyst')}
              </button>
              <button
                type="button"
                className="cyber-quick-btn cyber-quick-btn--student"
                onClick={() => handleQuickFill('student')}
              >
                {t('auth.quickFillStudent')}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
