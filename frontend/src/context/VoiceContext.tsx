// Threat3D NIDS NOVA Voice Assistant Context
// Bilingual Voice Input/Output Management & State
import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useLanguage } from './LanguageContext';
import type { Language } from '../i18n/translations';
import {
  isSpeechRecognitionSupported,
  isSpeechSynthesisSupported,
  speakUtterance,
  stopSpeech,
  processTacticalCommand,
  logAvailableVoices,
} from '../services/voiceAssistant';

export type VoicePermissionState = 'prompt' | 'granted' | 'denied' | 'unsupported';

interface VoiceContextType {
  isListening: boolean;
  isSpeaking: boolean;
  isProcessing: boolean;
  isSupported: boolean;
  permissionState: VoicePermissionState;
  transcript: string;
  interimTranscript: string;
  response: string;
  lastAction: string | null;
  error: string | null;
  isWidgetOpen: boolean;
  startListening: () => void;
  stopListening: () => void;
  toggleListening: () => void;
  speak: (text: string, lang?: Language) => void;
  stopSpeaking: () => void;
  executeCommand: (commandText: string) => Promise<void>;
  openWidget: () => void;
  closeWidget: () => void;
  toggleWidget: () => void;
  clearError: () => void;
}

const VoiceContext = createContext<VoiceContextType | undefined>(undefined);

// Web Speech API interfaces for type safety
interface IWindowRecognition extends Window {
  SpeechRecognition?: any;
  webkitSpeechRecognition?: any;
}

const isTamilText = (text: string): boolean => {
  if (!text) return false;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code >= 0x0b80 && code <= 0x0bff) {
      return true;
    }
  }
  return false;
};

export const VoiceProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const navigate = useNavigate();
  const { language, setLanguage } = useLanguage();

  const [isListening, setIsListening] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [isSupported] = useState<boolean>(() => isSpeechRecognitionSupported());
  const [permissionState, setPermissionState] = useState<VoicePermissionState>(() =>
    isSpeechRecognitionSupported() ? 'prompt' : 'unsupported'
  );

  const [transcript, setTranscript] = useState('');
  const [interimTranscript, setInterimTranscript] = useState('');
  const [response, setResponse] = useState('');
  const [lastAction, setLastAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isWidgetOpen, setIsWidgetOpen] = useState(false);

  const recognitionRef = useRef<any>(null);

  // Pre-load synthesis voices and handle voiceschanged event
  useEffect(() => {
    if (isSpeechSynthesisSupported()) {
      const handleVoicesChanged = () => {
        const voices = window.speechSynthesis.getVoices();
        if (voices && voices.length > 0) {
          logAvailableVoices();
        }
      };

      // Query immediately in case voices are already loaded
      handleVoicesChanged();

      window.speechSynthesis.onvoiceschanged = handleVoicesChanged;

      return () => {
        if (window.speechSynthesis) {
          window.speechSynthesis.onvoiceschanged = null;
        }
      };
    }
  }, []);

  // Stop speaking on unmount
  useEffect(() => {
    return () => {
      stopSpeech();
      if (recognitionRef.current) {
        try {
          recognitionRef.current.abort();
        } catch {
          // ignore
        }
      }
    };
  }, []);

  const speak = useCallback(
    (text: string, lang?: Language) => {
      const activeLang = lang || (isTamilText(text) ? 'ta' : language);
      setIsSpeaking(true);
      speakUtterance(
        text,
        activeLang,
        () => setIsSpeaking(true),
        () => setIsSpeaking(false)
      );
    },
    [language]
  );

  const stopSpeaking = useCallback(() => {
    stopSpeech();
    setIsSpeaking(false);
  }, []);

  const executeCommand = useCallback(
    async (commandText: string) => {
      if (!commandText.trim()) return;
      setError(null);
      setIsProcessing(true);
      setTranscript(commandText);
      setInterimTranscript('');

      try {
        const result = await processTacticalCommand(commandText, language);
        setResponse(result.responseMessage);
        setLastAction(result.actionExecuted || null);

        // Language change requested via voice
        if (result.languageChangedTo) {
          setLanguage(result.languageChangedTo);
        }

        // Navigation requested via voice
        if (result.navDestination) {
          navigate(result.navDestination);
        }

        // Vocalize response feedback with auto-detected Tamil or active language
        const targetLang: Language = isTamilText(result.responseMessage)
          ? 'ta'
          : (result.languageChangedTo || language);
        speak(result.responseMessage, targetLang);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : 'Execution failed';
        setError(msg);
      } finally {
        setIsProcessing(false);
      }
    },
    [language, navigate, setLanguage, speak]
  );

  const stopListening = useCallback(() => {
    if (recognitionRef.current) {
      try {
        recognitionRef.current.stop();
      } catch {
        // ignore
      }
    }
    setIsListening(false);
  }, []);

  const startListening = useCallback(() => {
    if (!isSpeechRecognitionSupported()) {
      setPermissionState('unsupported');
      setError('Speech recognition is not supported by your browser. Please use text input below.');
      return;
    }

    // Stop active speech synthesis before listening to avoid hearing ourselves
    stopSpeaking();
    setError(null);

    const win = window as unknown as IWindowRecognition;
    const SpeechRecognitionClass = win.SpeechRecognition || win.webkitSpeechRecognition;

    if (!SpeechRecognitionClass) {
      setPermissionState('unsupported');
      return;
    }

    try {
      if (recognitionRef.current) {
        try {
          recognitionRef.current.abort();
        } catch {
          // ignore
        }
      }

      const recognition = new SpeechRecognitionClass();
      recognition.continuous = false;
      recognition.interimResults = true;
      recognition.lang = language === 'ta' ? 'ta-IN' : 'en-IN';
      recognitionRef.current = recognition;

      recognition.onstart = () => {
        setIsListening(true);
        setPermissionState('granted');
        setInterimTranscript('');
      };

      recognition.onresult = (event: any) => {
        let finalStr = '';
        let interimStr = '';

        for (let i = event.resultIndex; i < event.results.length; ++i) {
          const item = event.results[i];
          const part = item && item[0] ? item[0].transcript : '';
          if (item && item.isFinal) {
            finalStr += part;
          } else {
            interimStr += part;
          }
        }

        if (interimStr) {
          setInterimTranscript(interimStr);
        }

        if (finalStr) {
          setTranscript(finalStr);
          setInterimTranscript('');
          executeCommand(finalStr);
        }
      };

      recognition.onerror = (event: any) => {
        setIsListening(false);
        if (event.error === 'not-allowed' || event.error === 'permission-denied') {
          setPermissionState('denied');
          setError('Microphone permission denied. Enable microphone access or use text command below.');
        } else if (event.error === 'no-speech') {
          // Soft timeout without user speech
          setError(null);
        } else {
          setError(`Recognition error: ${event.error}`);
        }
      };

      recognition.onend = () => {
        setIsListening(false);
        setInterimTranscript('');
      };

      recognition.start();
    } catch (err: unknown) {
      setIsListening(false);
      const msg = err instanceof Error ? err.message : 'Could not activate microphone';
      setError(msg);
    }
  }, [language, stopSpeaking, executeCommand]);

  const toggleListening = useCallback(() => {
    if (isListening) {
      stopListening();
    } else {
      startListening();
    }
  }, [isListening, startListening, stopListening]);

  const openWidget = useCallback(() => setIsWidgetOpen(true), []);
  const closeWidget = useCallback(() => setIsWidgetOpen(false), []);
  const toggleWidget = useCallback(() => setIsWidgetOpen((prev) => !prev), []);
  const clearError = useCallback(() => setError(null), []);

  return (
    <VoiceContext.Provider
      value={{
        isListening,
        isSpeaking,
        isProcessing,
        isSupported,
        permissionState,
        transcript,
        interimTranscript,
        response,
        lastAction,
        error,
        isWidgetOpen,
        startListening,
        stopListening,
        toggleListening,
        speak,
        stopSpeaking,
        executeCommand,
        openWidget,
        closeWidget,
        toggleWidget,
        clearError,
      }}
    >
      {children}
    </VoiceContext.Provider>
  );
};

export const useVoice = (): VoiceContextType => {
  const context = useContext(VoiceContext);
  if (!context) {
    throw new Error('useVoice must be used within a VoiceProvider');
  }
  return context;
};
