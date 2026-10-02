import React, { useState } from 'react';
import { AlertTriangle, Info, CheckCircle2, XCircle, X } from 'lucide-react';

interface AlertBannerProps {
  type?: 'info' | 'warning' | 'error' | 'success' | 'safety';
  title?: string;
  message: React.ReactNode;
  dismissible?: boolean;
  className?: string;
}

export const AlertBanner: React.FC<AlertBannerProps> = ({
  type = 'info',
  title,
  message,
  dismissible = false,
  className = '',
}) => {
  const [dismissed, setDismissed] = useState(false);

  if (dismissed) return null;

  const getIcon = () => {
    switch (type) {
      case 'warning':
      case 'safety':
        return <AlertTriangle size={18} />;
      case 'error':
        return <XCircle size={18} />;
      case 'success':
        return <CheckCircle2 size={18} />;
      default:
        return <Info size={18} />;
    }
  };

  return (
    <div className={`cyber-alert-banner cyber-alert-banner--${type} ${className}`}>
      <div className="cyber-alert-icon">{getIcon()}</div>
      <div className="cyber-alert-content">
        {title && <h5 className="cyber-alert-title">{title}</h5>}
        <div className="cyber-alert-message">{message}</div>
      </div>
      {dismissible && (
        <button
          type="button"
          className="cyber-alert-dismiss"
          onClick={() => setDismissed(true)}
          aria-label="Dismiss alert"
        >
          <X size={16} />
        </button>
      )}
    </div>
  );
};
