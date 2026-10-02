import React from 'react';

interface StatWidgetProps {
  label: string;
  value: string | number;
  subtext?: string;
  icon?: React.ReactNode;
  trend?: {
    text: string;
    type: 'up' | 'down' | 'neutral';
  };
  variant?: 'blue' | 'red' | 'purple' | 'green' | 'amber' | 'neutral';
  onClick?: () => void;
}

export const StatWidget: React.FC<StatWidgetProps> = ({
  label,
  value,
  subtext,
  icon,
  trend,
  variant = 'blue',
  onClick,
}) => {
  return (
    <div
      className={`cyber-stat-widget cyber-stat-widget--${variant} ${onClick ? 'cursor-pointer' : ''}`}
      onClick={onClick}
    >
      <div className="cyber-stat-header">
        <span className="cyber-stat-label">{label}</span>
        {icon && <div className="cyber-stat-icon">{icon}</div>}
      </div>
      <div className="cyber-stat-value">{value}</div>
      {(subtext || trend) && (
        <div className="cyber-stat-footer">
          {trend && (
            <span className={`cyber-stat-trend cyber-stat-trend--${trend.type}`}>
              {trend.text}
            </span>
          )}
          {subtext && <span className="cyber-stat-subtext">{subtext}</span>}
        </div>
      )}
    </div>
  );
};
