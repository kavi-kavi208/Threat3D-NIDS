import React from 'react';

export type BadgeVariant =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'healthy'
  | 'suspicious'
  | 'compromised'
  | 'isolated'
  | 'admin'
  | 'analyst'
  | 'student'
  | 'active'
  | 'mitigated'
  | 'blocked'
  | 'neutral';

interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
  size?: 'sm' | 'md' | 'lg';
  dot?: boolean;
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'neutral',
  size = 'md',
  dot = false,
  className = '',
}) => {
  const getVariantStyles = (): { bg: string; text: string; border: string; dotColor: string } => {
    switch (variant) {
      case 'critical':
      case 'compromised':
        return {
          bg: 'rgba(239, 68, 68, 0.12)',
          text: '#f87171',
          border: 'rgba(239, 68, 68, 0.35)',
          dotColor: '#ef4444',
        };
      case 'high':
      case 'suspicious':
        return {
          bg: 'rgba(249, 115, 22, 0.12)',
          text: '#fb923c',
          border: 'rgba(249, 115, 22, 0.35)',
          dotColor: '#f97316',
        };
      case 'medium':
        return {
          bg: 'rgba(234, 179, 8, 0.12)',
          text: '#facc15',
          border: 'rgba(234, 179, 8, 0.35)',
          dotColor: '#eab308',
        };
      case 'low':
      case 'healthy':
      case 'mitigated':
        return {
          bg: 'rgba(34, 197, 94, 0.12)',
          text: '#4ade80',
          border: 'rgba(34, 197, 94, 0.35)',
          dotColor: '#22c55e',
        };
      case 'isolated':
      case 'blocked':
        return {
          bg: 'rgba(168, 85, 247, 0.12)',
          text: '#c084fc',
          border: 'rgba(168, 85, 247, 0.35)',
          dotColor: '#a855f7',
        };
      case 'admin':
        return {
          bg: 'rgba(236, 72, 153, 0.12)',
          text: '#f472b6',
          border: 'rgba(236, 72, 153, 0.35)',
          dotColor: '#ec4899',
        };
      case 'analyst':
        return {
          bg: 'rgba(56, 189, 248, 0.12)',
          text: '#38bdf8',
          border: 'rgba(56, 189, 248, 0.35)',
          dotColor: '#38bdf8',
        };
      case 'student':
        return {
          bg: 'rgba(16, 185, 129, 0.12)',
          text: '#34d399',
          border: 'rgba(16, 185, 129, 0.35)',
          dotColor: '#10b981',
        };
      case 'active':
        return {
          bg: 'rgba(239, 68, 68, 0.15)',
          text: '#fca5a5',
          border: 'rgba(239, 68, 68, 0.4)',
          dotColor: '#ef4444',
        };
      default:
        return {
          bg: 'rgba(100, 116, 139, 0.12)',
          text: '#94a3b8',
          border: 'rgba(100, 116, 139, 0.25)',
          dotColor: '#64748b',
        };
    }
  };

  const styles = getVariantStyles();

  const sizeClasses = {
    sm: 'text-[10px] px-1.5 py-0.5 font-semibold tracking-wider',
    md: 'text-xs px-2.5 py-0.5 font-medium',
    lg: 'text-sm px-3 py-1 font-medium',
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border uppercase tracking-wider ${sizeClasses[size]} ${className}`}
      style={{
        backgroundColor: styles.bg,
        color: styles.text,
        borderColor: styles.border,
      }}
    >
      {dot && (
        <span
          className="inline-block w-1.5 h-1.5 rounded-full"
          style={{ backgroundColor: styles.dotColor }}
        />
      )}
      {children}
    </span>
  );
};
