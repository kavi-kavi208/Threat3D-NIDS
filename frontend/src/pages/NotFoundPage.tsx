import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, ArrowLeft } from 'lucide-react';
import { Button } from '../components/common/Button';
import { useLanguage } from '../context/LanguageContext';

export const NotFoundPage: React.FC = () => {
  const navigate = useNavigate();
  const { t } = useLanguage();

  return (
    <div className="cyber-not-found-view">
      <div className="cyber-not-found-card">
        <ShieldAlert size={48} className="text-cyan-400 mx-auto mb-3" />
        <h2 className="text-2xl font-bold text-slate-100 mb-1">{t('notfound.title')}</h2>
        <p className="text-xs text-slate-400 mb-6">
          {t('notfound.desc')}
        </p>
        <Button
          variant="primary"
          size="md"
          onClick={() => navigate('/')}
          leftIcon={<ArrowLeft size={16} />}
        >
          {t('notfound.btnHome')}
        </Button>
      </div>
    </div>
  );
};
