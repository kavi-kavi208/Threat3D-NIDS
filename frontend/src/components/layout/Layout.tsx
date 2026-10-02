import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Navbar } from './Navbar';
import { Sidebar } from './Sidebar';
import { AlertBanner } from '../common/AlertBanner';
import { useLanguage } from '../../context/LanguageContext';
import { CyberSecurityChat } from '../chat/CyberSecurityChat';
import { VoiceAssistantWidget } from '../voice/VoiceAssistantWidget';

export const Layout: React.FC = () => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const { t } = useLanguage();

  return (
    <div className="cyber-layout">
      <Navbar
        onToggleSidebar={() => setIsSidebarOpen((prev) => !prev)}
        isSidebarOpen={isSidebarOpen}
      />

      <div className="cyber-layout-body">
        <Sidebar isOpen={isSidebarOpen} onClose={() => setIsSidebarOpen(false)} />

        <main className="cyber-main-content">
          <div className="cyber-main-container">
            <AlertBanner
              type="safety"
              className="mb-4"
              message={
                <span>
                  <strong>{t('safety.bannerBold')}</strong>{t('safety.bannerDesc')}
                </span>
              }
            />
            <Outlet />
          </div>
        </main>
      </div>

      {/* Floating Cyber Assistant Widgets */}
      <CyberSecurityChat />
      <VoiceAssistantWidget />
    </div>
  );
};
