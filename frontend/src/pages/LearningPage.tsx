import React, { useEffect, useState } from 'react';
import { useLanguage } from '../context/LanguageContext';
import { fetchThreatExplanation } from '../services/chatService';
import { threatApi } from '../services/api';
import type { ChatResponse } from '../types/chatTypes';

interface Threat {
  id: number;
  attackType: string;
  src: string;
  dst: string;
  severity: string;
}

export const LearningPage: React.FC = () => {
  const { t } = useLanguage();
  const [threats, setThreats] = useState<Threat[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [explanation, setExplanation] = useState<ChatResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>('');

  // Load recent threats on mount
  useEffect(() => {
    threatApi.getAlerts().then((res) => {
      const alerts = res?.data || [];
      const list = alerts.map((a: any) => ({
        id: a.id,
        attackType: a.attackType,
        src: a.sourceIp || a.source || '',
        dst: a.destinationIp || a.destination || '',
        severity: a.severity,
      }));
      setThreats(list);
    }).catch(() => setThreats([]));
  }, []);

  const handleExplain = async () => {
    if (!selectedId) return;
    setLoading(true);
    setError('');
    try {
      const resp = await fetchThreatExplanation('', selectedId.toString());
      setExplanation(resp);
    } catch (e: any) {
      setError(e.message || t('common.error'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="cyber-page-header">
        <h1 className="cyber-page-title">{t('learning.title')}</h1>
        <p className="cyber-page-subtitle">{t('learning.overview')}</p>
      </div>

      <div className="cyber-card p-6">
        <h3 className="text-lg font-semibold text-cyan-300 mb-3">{t('learning.selectThreat')}</h3>
        <div className="flex flex-col md:flex-row gap-4 items-stretch md:items-center">
          <select
            id="threatSelect"
            className="flex-1 cyber-select bg-slate-900 border border-slate-700 text-slate-100 rounded-lg p-3 font-mono text-sm focus:border-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-400"
            style={{ colorScheme: 'dark', backgroundColor: '#0f172a', color: '#f1f5f9' }}
            value={selectedId ?? ''}
            onChange={(e) => setSelectedId(Number(e.target.value) || null)}
          >
            <option value="" className="bg-slate-900 text-slate-400" style={{ backgroundColor: '#0f172a', color: '#94a3b8' }}>
              -- {t('common.select')} --
            </option>
            {threats.map((th) => (
              <option key={th.id} value={th.id} className="bg-slate-900 text-slate-100" style={{ backgroundColor: '#0f172a', color: '#f1f5f9' }}>
                Alert #{th.id} — {th.attackType} [{th.severity}] ({th.src} → {th.dst})
              </option>
            ))}
          </select>
          <button
            className="px-6 py-3 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded-lg transition-colors disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            onClick={handleExplain}
            disabled={!selectedId || loading}
          >
            {loading ? (
              <span>{t('learning.loading')}</span>
            ) : (
              <span>{t('learning.explainButton')}</span>
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-red-950/40 border border-red-500/50 text-red-300 font-mono text-sm">
          {error}
        </div>
      )}

      {explanation && (
        <div className="cyber-card p-6 border-cyan-500/40 bg-slate-900/90 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h2 className="text-xl font-bold text-cyan-400 flex items-center gap-2">
              <span>🛡️</span> {t('learning.threatExplanation')}
            </h2>
            <div className="flex items-center gap-2">
              {explanation.severity && (
                <span className="px-2.5 py-1 text-xs font-bold rounded font-mono bg-red-950 text-red-400 border border-red-800">
                  {explanation.severity}
                </span>
              )}
              {explanation.score !== undefined && (
                <span className="px-2.5 py-1 text-xs font-bold rounded font-mono bg-cyan-950 text-cyan-300 border border-cyan-800">
                  Score: {explanation.score}/100
                </span>
              )}
            </div>
          </div>

          <div className="space-y-3 text-slate-200">
            <div>
              <span className="text-xs uppercase tracking-wider text-slate-400 font-mono block mb-1">
                {t('learning.answer')}
              </span>
              <p className="text-slate-100 leading-relaxed bg-slate-950/60 p-3 rounded border border-slate-800 font-sans">
                {explanation.answer}
              </p>
            </div>

            {explanation.mitre && explanation.mitre.length > 0 && (
              <div>
                <span className="text-xs uppercase tracking-wider text-slate-400 font-mono block mb-1">
                  {t('learning.mitre')}
                </span>
                <div className="flex flex-wrap gap-2">
                  {explanation.mitre.map((m, idx) => (
                    <span key={idx} className="px-2 py-0.5 text-xs font-mono rounded bg-purple-950/70 text-purple-300 border border-purple-700/60">
                      {m}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {explanation.recommendations && explanation.recommendations.length > 0 && (
              <div>
                <span className="text-xs uppercase tracking-wider text-emerald-400 font-mono block mb-1">
                  {t('learning.recommendations')}
                </span>
                <ul className="list-disc list-inside space-y-1 bg-emerald-950/20 border border-emerald-800/40 p-3 rounded text-sm text-emerald-200">
                  {explanation.recommendations.map((rec, idx) => (
                    <li key={idx}>{rec}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Foundational NIDS Concepts */}
      <div className="cyber-card p-6 border-slate-800">
        <h2 className="text-xl font-bold text-slate-100 mb-3 flex items-center gap-2">
          <span>📚</span> {t('learning.nidsConcepts')}
        </h2>
        <p className="text-slate-300 leading-relaxed text-sm">
          {t('learning.nidsConceptsText')}
        </p>
      </div>
    </div>
  );
};
