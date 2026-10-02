import React, { useState, useEffect, useRef } from 'react';
import { useLanguage } from '../../context/LanguageContext';
import { useVoice } from '../../context/VoiceContext';
import { LoadingSpinner } from '../common/LoadingSpinner';
import { fetchThreatExplanation } from '../../services/chatService';
import type { ChatMessage, ChatResponse } from '../../types/chatTypes';

/**
 * CyberSecurityChat — Professional cybersecurity chatbot widget.
 * Acts as both a cybersecurity tutor and a Threat3D application guide.
 * Supports English and Tamil (Thanglish) queries.
 * Uses real persisted backend alert data for Alert ID queries.
 * SIMULATION ONLY — NO REAL NETWORK CHANGES.
 */
export const CyberSecurityChat: React.FC = () => {
  const { t } = useLanguage();
  const { speak } = useVoice();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isOpen, setIsOpen] = useState(false);

  const toggleOpen = () => setIsOpen((prev) => !prev);

  const addMessage = (msg: ChatMessage) => {
    setMessages((prev) => [...prev, msg]);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;
    const userMsg: ChatMessage = { sender: 'user', text: input.trim() };
    addMessage(userMsg);
    setInput('');
    setIsLoading(true);
    setError(null);
    try {
      const response: ChatResponse = await fetchThreatExplanation(userMsg.text);
      const botMsg: ChatMessage = {
        sender: 'bot',
        text: response.answer || 'No response available.',
        severity: response.severity,
        score: response.score,
        mitre: response.mitre,
        recommendations: response.recommendations,
      };
      addMessage(botMsg);
      if (response.answer) {
        speak(response.answer);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unexpected error';
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  };

  // Auto-scroll to newest message
  const bottomRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  return (
    <div className="chat-widget-container">
      {/* Chat Panel */}
      {isOpen && (
        <div className="chat-panel">
          {/* Header */}
          <div className="chat-header">
            <div className="chat-header-left">
              <div className="chat-header-dot" />
              <span className="chat-header-title">NOVA · Cyber Assistant</span>
            </div>
            <button
              type="button"
              onClick={toggleOpen}
              className="chat-close-btn"
              title={t('chat.close')}
              aria-label={t('chat.close')}
            >
              ✕
            </button>
          </div>

          {/* Welcome hint (only when empty) */}
          {messages.length === 0 && (
            <div className="chat-welcome">
              <p className="chat-welcome-title">Ask me anything!</p>
              <div className="chat-welcome-hints">
                <span className="chat-hint-chip" onClick={() => setInput('What is NIDS?')}>What is NIDS?</span>
                <span className="chat-hint-chip" onClick={() => setInput('How does Threat3D detect threats?')}>How does Threat3D detect threats?</span>
                <span className="chat-hint-chip" onClick={() => setInput('How do I run a simulation?')}>How do I run a simulation?</span>
                <span className="chat-hint-chip" onClick={() => setInput('NIDS na enna?')}>NIDS na enna?</span>
                <span className="chat-hint-chip" onClick={() => setInput('Simulation epdi run panrathu?')}>Simulation epdi run?</span>
              </div>
            </div>
          )}

          {/* Messages */}
          <div className="chat-messages">
            {messages.map((msg, idx) => (
              <div
                key={idx}
                className={`chat-msg-row ${msg.sender === 'user' ? 'chat-msg-row--user' : 'chat-msg-row--bot'}`}
              >
                <div className={`chat-bubble ${msg.sender === 'user' ? 'chat-bubble--user' : 'chat-bubble--bot'}`}>
                  {/* Severity/Score badge for bot messages */}
                  {msg.sender === 'bot' && (msg.severity || msg.score != null) && (
                    <div className="chat-bubble-meta">
                      {msg.severity && (
                        <span className={`chat-severity-badge chat-severity-badge--${msg.severity?.toLowerCase()}`}>
                          {msg.severity}
                        </span>
                      )}
                      {msg.score != null && (
                        <span className="chat-score-badge">Score: {msg.score}/100</span>
                      )}
                    </div>
                  )}

                  {/* Message text — preserve newlines */}
                  <p className="chat-msg-text">{msg.text}</p>

                  {/* MITRE tags */}
                  {msg.sender === 'bot' && msg.mitre && msg.mitre.length > 0 && (
                    <div className="chat-mitre-row">
                      {msg.mitre.map((m, mIdx) => (
                        <span key={mIdx} className="chat-mitre-tag">{m}</span>
                      ))}
                    </div>
                  )}

                  {/* Recommendations */}
                  {msg.sender === 'bot' && msg.recommendations && msg.recommendations.length > 0 && (
                    <div className="chat-recs">
                      <span className="chat-recs-label">Mitigations:</span>
                      <ul className="chat-recs-list">
                        {msg.recommendations.map((rec, rIdx) => (
                          <li key={rIdx}>{rec}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            ))}
            <div ref={bottomRef} />
          </div>

          {/* Error Banner */}
          {error && (
            <div className="chat-error-banner">
              <span>⚠ {error}</span>
              <button type="button" onClick={() => setError(null)} className="chat-error-dismiss">×</button>
            </div>
          )}

          {/* Loading indicator */}
          {isLoading && (
            <div className="chat-loading">
              <LoadingSpinner message="NOVA is thinking..." />
            </div>
          )}

          {/* Input form */}
          <form onSubmit={handleSubmit} className="chat-input-form">
            <input
              type="text"
              className="chat-input"
              placeholder={t('chat.placeholder') || 'Ask a cybersecurity question...'}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              disabled={isLoading}
              autoComplete="off"
            />
            <button
              type="submit"
              className="chat-send-btn"
              disabled={isLoading || !input.trim()}
              aria-label={t('chat.send') || 'Send'}
            >
              {t('chat.send') || 'Send'}
            </button>
          </form>
        </div>
      )}

      {/* Toggle Button */}
      <button
        type="button"
        onClick={toggleOpen}
        className={`chat-toggle-btn ${isOpen ? 'chat-toggle-btn--open' : 'chat-toggle-btn--closed'}`}
        aria-label={isOpen ? (t('chat.close') || 'Close Chat') : (t('chat.open') || 'Open Chat')}
      >
        <span className="chat-toggle-icon">{isOpen ? '✕' : '💬'}</span>
        <span className="chat-toggle-label">{isOpen ? (t('chat.close') || 'Close Chat') : (t('chat.open') || 'Open Chat')}</span>
      </button>
    </div>
  );
};
