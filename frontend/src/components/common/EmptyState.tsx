import React from 'react';
import { ShieldCheck } from 'lucide-react';

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon,
  title,
  description,
  action,
}) => {
  return (
    <div className="cyber-empty-state">
      <div className="cyber-empty-icon">{icon || <ShieldCheck size={36} />}</div>
      <h4 className="cyber-empty-title">{title}</h4>
      {description && <p className="cyber-empty-desc">{description}</p>}
      {action && <div className="cyber-empty-action">{action}</div>}
    </div>
  );
};
