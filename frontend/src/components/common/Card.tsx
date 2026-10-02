import React from 'react';

interface CardProps {
  children: React.ReactNode;
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  action?: React.ReactNode;
  badge?: React.ReactNode;
  className?: string;
  glow?: boolean;
  glowColor?: 'blue' | 'red' | 'purple' | 'green' | 'amber';
}

export const Card: React.FC<CardProps> = ({
  children,
  title,
  subtitle,
  action,
  badge,
  className = '',
  glow = false,
  glowColor = 'blue',
}) => {
  return (
    <div
      className={`cyber-card ${glow ? `cyber-card--glow-${glowColor}` : ''} ${className}`}
    >
      {(title || action || badge) && (
        <div className="cyber-card-header">
          <div className="cyber-card-title-group">
            {title && <h3 className="cyber-card-title">{title}</h3>}
            {badge && <span className="cyber-card-badge">{badge}</span>}
            {subtitle && <p className="cyber-card-subtitle">{subtitle}</p>}
          </div>
          {action && <div className="cyber-card-actions">{action}</div>}
        </div>
      )}
      <div className="cyber-card-body">{children}</div>
    </div>
  );
};
