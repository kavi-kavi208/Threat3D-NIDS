import React from 'react';

interface LoadingSpinnerProps {
  message?: string;
  size?: 'sm' | 'md' | 'lg';
  fullScreen?: boolean;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  message = 'Processing network telemetry...',
  size = 'md',
  fullScreen = false,
}) => {
  const content = (
    <div className={`cyber-loader cyber-loader--${size}`}>
      <div className="cyber-loader-radar">
        <div className="radar-sweep" />
        <div className="radar-cross-h" />
        <div className="radar-cross-v" />
      </div>
      {message && <p className="cyber-loader-text">{message}</p>}
    </div>
  );

  if (fullScreen) {
    return <div className="cyber-loader-fullscreen">{content}</div>;
  }

  return content;
};
