import React, { useState } from 'react';
import {
  Mic,
  MicOff,
  Volume2,
  VolumeX,
  Send,
  X,
  Radio,
  Sparkles,
  AlertCircle,
  Languages,
} from 'lucide-react';
import { useVoice } from '../../context/VoiceContext';
import { useLanguage } from '../../context/LanguageContext';

export const VoiceAssistantWidget: React.FC = () => {
  const {
    isListening,
    isSpeaking,
    isProcessing,
    isSupported,
    permissionState,
    transcript,
    interimTranscript,
    response,
    error,
    isWidgetOpen,
    toggleListening,
    stopSpeaking,
    executeCommand,
    toggleWidget,
    closeWidget,
    clearError,
  } = useVoice();

  const { language, isTamil, toggleLanguage, t } = useLanguage();
  const [textInput, setTextInput] = useState('');

  const handleTextSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!textInput.trim() || isProcessing) return;
    const cmd = textInput.trim();
    setTextInput('');
    await executeCommand(cmd);
  };

  const handleQuickCommand = async (cmd: string) => {
    if (isProcessing) return;
    await executeCommand(cmd);
  };

  return (
    <>
      {/* Floating Tactical Dock Trigger Button */}
      <div className="cyber-voice-dock">
        <button
          type="button"
          className={`cyber-voice-dock-btn ${
            isListening ? 'cyber-voice-dock-btn--listening' : ''
          } ${isSpeaking ? 'cyber-voice-dock-btn--speaking' : ''}`}
          onClick={toggleWidget}
          title={t('voice.navBtnTitle')}
          aria-label={t('voice.navBtnTitle')}
        >
          <div className="cyber-voice-dock-glow" />
          {isListening ? (
            <Mic className="cyber-voice-icon cyber-pulse-red" size={22} />
          ) : isSpeaking ? (
            <Volume2 className="cyber-voice-icon cyber-pulse-cyan" size={22} />
          ) : (
            <Mic className="cyber-voice-icon" size={22} />
          )}
          <span className="cyber-voice-dock-badge font-mono">NOVA</span>
        </button>
      </div>

      {/* Expanded Tactical HUD Panel */}
      {isWidgetOpen && (
        <div className="cyber-voice-hud-overlay" onClick={closeWidget}>
          <div
            className="cyber-voice-hud-panel"
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-label={t('voice.title')}
          >
            {/* Panel Header */}
            <div className="cyber-voice-hud-header">
              <div className="flex items-center gap-2.5">
                <div className="cyber-voice-hud-avatar">
                  <Sparkles size={16} className="text-cyan-400" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="cyber-voice-hud-title font-mono text-sm font-bold text-slate-100">
                      {t('voice.title')}
                    </h3>
                    <span className="cyber-voice-lang-pill font-mono text-[10px]">
                      {language === 'ta' ? 'ta-IN • தமிழ்' : 'en-US • English'}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">{t('voice.subtitle')}</p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  className="cyber-voice-lang-toggle"
                  onClick={toggleLanguage}
                  title={isTamil ? t('common.switchToEnglish') : t('common.switchToTamil')}
                >
                  <Languages size={13} />
                  <span className="font-mono text-xs">{language === 'en' ? 'தமிழ்' : 'EN'}</span>
                </button>
                <button
                  type="button"
                  className="cyber-voice-hud-close"
                  onClick={closeWidget}
                  aria-label={t('common.close')}
                >
                  <X size={18} />
                </button>
              </div>
            </div>

            {/* Visualizer & Mic Control Center */}
            <div className="cyber-voice-control-center">
              {/* Concentric Glow Wave Rings */}
              <div
                className={`cyber-voice-mic-orb ${
                  isListening
                    ? 'cyber-voice-mic-orb--listening'
                    : isSpeaking
                    ? 'cyber-voice-mic-orb--speaking'
                    : ''
                }`}
              >
                <button
                  type="button"
                  className="cyber-voice-mic-btn"
                  onClick={toggleListening}
                  disabled={!isSupported && permissionState === 'unsupported'}
                  title={isListening ? t('voice.micStop') : t('voice.micStart')}
                  aria-label={isListening ? t('voice.micStop') : t('voice.micStart')}
                >
                  {isListening ? (
                    <MicOff size={28} className="text-red-400 animate-pulse" />
                  ) : (
                    <Mic size={28} className="text-cyan-400" />
                  )}
                </button>

                {/* Pulsing Concentric Waves */}
                <div className="cyber-voice-ring cyber-voice-ring-1" />
                <div className="cyber-voice-ring cyber-voice-ring-2" />
                <div className="cyber-voice-ring cyber-voice-ring-3" />
              </div>

              {/* Dynamic Audio Visualizer Bars */}
              <div className="cyber-voice-waveform">
                <span className={`cyber-wave-bar ${isListening || isSpeaking ? 'active' : ''}`} />
                <span className={`cyber-wave-bar ${isListening || isSpeaking ? 'active' : ''}`} />
                <span className={`cyber-wave-bar ${isListening || isSpeaking ? 'active' : ''}`} />
                <span className={`cyber-wave-bar ${isListening || isSpeaking ? 'active' : ''}`} />
                <span className={`cyber-wave-bar ${isListening || isSpeaking ? 'active' : ''}`} />
                <span className={`cyber-wave-bar ${isListening || isSpeaking ? 'active' : ''}`} />
                <span className={`cyber-wave-bar ${isListening || isSpeaking ? 'active' : ''}`} />
                <span className={`cyber-wave-bar ${isListening || isSpeaking ? 'active' : ''}`} />
              </div>

              {/* Status Indicator */}
              <div className="flex items-center gap-2 mt-2">
                <Radio
                  size={14}
                  className={
                    isListening
                      ? 'text-red-400 animate-pulse'
                      : isSpeaking
                      ? 'text-purple-400 animate-pulse'
                      : 'text-cyan-400'
                  }
                />
                <span className="text-xs font-mono font-medium text-slate-300">
                  {isListening
                    ? t('voice.statusListening')
                    : isProcessing
                    ? t('voice.statusProcessing')
                    : isSpeaking
                    ? t('voice.statusSpeaking')
                    : t('voice.statusIdle')}
                </span>

                {isSpeaking && (
                  <button
                    type="button"
                    className="cyber-voice-silence-btn ml-2"
                    onClick={stopSpeaking}
                    title={t('voice.stopSpeaking')}
                  >
                    <VolumeX size={12} />
                    <span>{t('voice.stopSpeaking')}</span>
                  </button>
                )}
              </div>
            </div>

            {/* Permission or Error Alert */}
            {permissionState === 'denied' && (
              <div className="cyber-voice-alert cyber-voice-alert--warn">
                <AlertCircle size={15} />
                <span>{t('voice.permissionDenied')}</span>
              </div>
            )}

            {!isSupported && (
              <div className="cyber-voice-alert cyber-voice-alert--info">
                <AlertCircle size={15} />
                <span>{t('voice.unsupported')}</span>
              </div>
            )}

            {error && permissionState !== 'denied' && (
              <div className="cyber-voice-alert cyber-voice-alert--error">
                <AlertCircle size={15} />
                <span>{error}</span>
                <button
                  type="button"
                  className="ml-auto text-xs opacity-70 hover:opacity-100"
                  onClick={clearError}
                >
                  &times;
                </button>
              </div>
            )}

            {/* Real-time Voice Transcription & Assistant Response Log */}
            <div className="cyber-voice-dialogue-box">
              {/* Operator's Spoken Input */}
              <div className="cyber-voice-bubble cyber-voice-bubble--user">
                <span className="cyber-voice-bubble-label font-mono">
                  {t('voice.transcriptLabel')}
                </span>
                <p className="text-xs font-mono text-cyan-200">
                  {interimTranscript
                    ? `${interimTranscript} ...`
                    : transcript || t('voice.noTranscript')}
                </p>
              </div>

              {/* Assistant's Spoken Response */}
              {response && (
                <div className="cyber-voice-bubble cyber-voice-bubble--assistant">
                  <div className="flex items-center gap-1.5 mb-1">
                    <Volume2 size={13} className="text-purple-400" />
                    <span className="cyber-voice-bubble-label font-mono">
                      {t('voice.responseLabel')}
                    </span>
                  </div>
                  <p className="text-xs leading-relaxed text-slate-200">{response}</p>
                </div>
              )}
            </div>

            {/* Text Fallback Command Bar */}
            <form onSubmit={handleTextSubmit} className="cyber-voice-input-row">
              <input
                type="text"
                className="cyber-voice-text-input"
                placeholder={t('voice.textFallbackPlaceholder')}
                value={textInput}
                onChange={(e) => setTextInput(e.target.value)}
                disabled={isProcessing}
              />
              <button
                type="submit"
                className="cyber-voice-send-btn"
                disabled={!textInput.trim() || isProcessing}
                aria-label={t('voice.btnExecute')}
              >
                <Send size={15} />
                <span className="hidden sm:inline font-mono text-xs">{t('voice.btnExecute')}</span>
              </button>
            </form>

            {/* Quick Tactical Command Chips */}
            <div className="cyber-voice-chips-container">
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1">
                {t('voice.quickCommandsTitle')}
              </span>
              <div className="flex flex-wrap gap-1.5">
                <button
                  type="button"
                  className="cyber-voice-chip"
                  onClick={() => handleQuickCommand(t('voice.cmdStatus'))}
                >
                  {t('voice.cmdStatus')}
                </button>
                <button
                  type="button"
                  className="cyber-voice-chip"
                  onClick={() => handleQuickCommand(t('voice.cmdEngine'))}
                >
                  {t('voice.cmdEngine')}
                </button>
                <button
                  type="button"
                  className="cyber-voice-chip"
                  onClick={() => handleQuickCommand(t('voice.cmdThreats'))}
                >
                  {t('voice.cmdThreats')}
                </button>
                <button
                  type="button"
                  className="cyber-voice-chip"
                  onClick={() => handleQuickCommand(t('voice.cmdTopology'))}
                >
                  {t('voice.cmdTopology')}
                </button>
                <button
                  type="button"
                  className="cyber-voice-chip"
                  onClick={() => handleQuickCommand(t('voice.cmdTraffic'))}
                >
                  {t('voice.cmdTraffic')}
                </button>
                <button
                  type="button"
                  className="cyber-voice-chip"
                  onClick={() => handleQuickCommand(t('voice.cmdSimulation'))}
                >
                  {t('voice.cmdSimulation')}
                </button>
                <button
                  type="button"
                  className="cyber-voice-chip"
                  onClick={() => handleQuickCommand(t('voice.cmdRules'))}
                >
                  {t('voice.cmdRules')}
                </button>
                <button
                  type="button"
                  className="cyber-voice-chip"
                  onClick={() => handleQuickCommand(t('voice.cmdHelp'))}
                >
                  {t('voice.cmdHelp')}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
