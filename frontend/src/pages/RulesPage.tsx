import React, { useState, useEffect, useCallback } from 'react';
import {
  RotateCw,
  Search,
} from 'lucide-react';
import { detectionApi } from '../services/api';
import type {
  SnortRule,
  EngineStatusResponse,
  CorrelationSummary,
  RecommendationSummary,
} from '../types';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { Button } from '../components/common/Button';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { EmptyState } from '../components/common/EmptyState';
import { useLanguage } from '../context/LanguageContext';
import { useAuth } from '../context/AuthContext';

export const RulesPage: React.FC = () => {
  const { hasRole } = useAuth();
  const { t } = useLanguage();
  const isAdmin = hasRole('ADMIN');
  const [rules, setRules] = useState<SnortRule[]>([]);
  const [engineStatus, setEngineStatus] = useState<EngineStatusResponse | null>(null);
  const [correlations, setCorrelations] = useState<CorrelationSummary[]>([]);
  const [recommendations, setRecommendations] = useState<RecommendationSummary[]>([]);

  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  const loadData = useCallback(async () => {
    setError(null);
    try {
      const [rulesRes, statusRes, corrRes, recRes] = await Promise.all([
        detectionApi.getSnortRules(false).catch(() => ({ data: [] })),
        detectionApi.getEngineStatus().catch(() => ({ data: null })),
        detectionApi.getCorrelations().catch(() => ({ data: [] })),
        detectionApi.getRecommendations().catch(() => ({ data: [] })),
      ]);

      if (rulesRes.data) setRules(rulesRes.data);
      if (statusRes.data) setEngineStatus(statusRes.data);
      if (corrRes.data) setCorrelations(corrRes.data);
      if (recRes.data) setRecommendations(recRes.data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to query detection rules';
      setError(msg);
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleRefresh = () => {
    setIsRefreshing(true);
    loadData();
  };

  const filteredRules = rules.filter((r) => {
    const q = searchQuery.toLowerCase();
    return (
      (r.name ?? '').toLowerCase().includes(q) ||
      (r.description ?? '').toLowerCase().includes(q) ||
      (r.protocol ?? '').toLowerCase().includes(q) ||
      (r.attackCategory ?? '').toLowerCase().includes(q) ||
      String(r.sid ?? '').includes(q) ||
      (r.mitreTechniqueId && r.mitreTechniqueId.toLowerCase().includes(q))
    );
  });

  if (isLoading && !isRefreshing) {
    return <LoadingSpinner message={t('rules.loadingData')} />;
  }

  return (
    <div className="cyber-page-content">
      {/* Page Header */}
      <div className="cyber-page-header">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h1 className="cyber-page-title mb-0">{t('rules.title')}</h1>
            <Badge variant={isAdmin ? 'admin' : 'analyst'} size="sm">
              {isAdmin ? 'ADMIN CONTROL' : 'ANALYST INSPECTION'}
            </Badge>
          </div>
          <p className="cyber-page-desc">
            {t('rules.desc')}
          </p>
        </div>
        <div className="cyber-page-header-actions">
          <Button
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            isLoading={isRefreshing}
            leftIcon={<RotateCw size={14} />}
          >
            {t('rules.refreshEngines')}
          </Button>
        </div>
      </div>

      {isAdmin ? (
        <div className="p-3 mb-6 bg-pink-950/20 border border-pink-800/40 rounded text-xs text-pink-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="font-bold uppercase tracking-wider font-mono">System Admin Clearance:</span>
            <span>Deterministic Snort Rule policy and statistical anomaly baseline controls active.</span>
          </div>
          <Badge variant="admin" size="sm">Admin Authority</Badge>
        </div>
      ) : (
        <div className="p-3 mb-6 bg-cyan-950/20 border border-cyan-800/40 rounded text-xs text-cyan-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="font-bold uppercase tracking-wider font-mono">Analyst Inspection Mode:</span>
            <span>Viewing configured signatures and anomaly baselines. Rule administration restricted to ROLE_ADMIN.</span>
          </div>
          <Badge variant="analyst" size="sm">Read-Only</Badge>
        </div>
      )}

      {error && (
        <div className="cyber-auth-error mb-4">
          <span>{error}</span>
        </div>
      )}

      {/* Dual Engine Architecture Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        {/* Signature Engine Card */}
        <Card
          title={t('rules.signatureCardTitle')}
          subtitle={t('rules.signatureCardSub')}
          badge={<Badge variant="high" size="sm">{t('rules.signatureBadge')}</Badge>}
        >
          <div className="flex flex-col gap-3 text-xs">
            <div className="grid grid-cols-2 gap-3 p-3 bg-slate-900/60 rounded border border-slate-800">
              <div>
                <span className="text-slate-400 font-mono block">{t('rules.activeRules')}</span>
                <span className="text-lg font-bold text-cyan-400 font-mono">
                  {engineStatus?.signatureEngine?.activeRulesCount || rules.filter((r) => r.enabled).length}
                </span>
              </div>
              <div>
                <span className="text-slate-400 font-mono block">{t('rules.totalRules')}</span>
                <span className="text-lg font-bold text-slate-200 font-mono">
                  {engineStatus?.signatureEngine?.totalRulesCount || rules.length}
                </span>
              </div>
            </div>
            <p className="text-slate-400 leading-relaxed">
              {t('rules.signatureDesc')}
            </p>
          </div>
        </Card>

        {/* Java Statistical Anomaly Detection Card */}
        <Card
          title={t('rules.anomalyCardTitle')}
          subtitle={t('rules.anomalyCardSub')}
          badge={
            <Badge
              variant={engineStatus?.anomalyEngine?.baselineReady ? 'healthy' : 'suspicious'}
              size="sm"
            >
              {engineStatus?.anomalyEngine?.baselineReady ? t('rules.baselineReady') : t('rules.calibrating')}
            </Badge>
          }
        >
          <div className="flex flex-col gap-3 text-xs">
            <div className="grid grid-cols-3 gap-2 p-3 bg-slate-900/60 rounded border border-slate-800 text-center font-mono">
              <div>
                <span className="text-slate-400 text-[10px] block">{t('rules.featureDims')}</span>
                <span className="text-sm font-bold text-purple-400">
                  {engineStatus?.anomalyEngine?.featureDimensions || 41}
                </span>
              </div>
              <div>
                <span className="text-slate-400 text-[10px] block">{t('rules.samples')}</span>
                <span className="text-sm font-bold text-cyan-400">
                  {engineStatus?.anomalyEngine?.sampleCount || 0}
                </span>
              </div>
              <div>
                <span className="text-slate-400 text-[10px] block">{t('rules.warmupTarget')}</span>
                <span className="text-sm font-bold text-emerald-400">
                  {engineStatus?.anomalyEngine?.warmupSamplesThreshold || 50}
                </span>
              </div>
            </div>
            <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800 text-slate-300">
              <span className="text-[10px] text-cyan-400 font-mono block mb-1">
                {t('rules.academicIntegrity')}
              </span>
              {t('rules.academicIntegrityDesc')}
            </div>
          </div>
        </Card>
      </div>

      {/* Snort Rules Table */}
      <Card
        className="mb-6"
        title={t('rules.rulesTableTitle')}
        subtitle={`Displaying ${filteredRules.length} registered detection rules`}
      >
        <div className="mb-4">
          <div className="cyber-search-wrapper w-full sm:w-80">
            <Search size={16} className="cyber-search-icon" />
            <input
              type="text"
              className="cyber-input cyber-search-input"
              placeholder={t('rules.searchPlaceholder')}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
        </div>

        {filteredRules.length === 0 ? (
          <EmptyState
            title={t('rules.noMatchingRules')}
            description={t('rules.noMatchingRulesDesc')}
          />
        ) : (
          <div className="cyber-table-container">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>{t('rules.colSid')}</th>
                  <th>{t('rules.colRuleName')}</th>
                  <th>{t('rules.colProtocol')}</th>
                  <th>{t('rules.colPortMapping')}</th>
                  <th>{t('rules.colSeverity')}</th>
                  <th>{t('rules.colCategory')}</th>
                  <th>{t('rules.colMitre')}</th>
                  <th>{t('rules.colStatus')}</th>
                </tr>
              </thead>
              <tbody>
                {filteredRules.map((rule) => (
                  <tr key={rule.id} className="cyber-table-row">
                    <td className="font-mono text-xs text-cyan-400 font-bold">
                      {rule.sid ? `SID-${rule.sid}` : (String(rule.id).startsWith('SID-') ? rule.id : `SID-${rule.id}`)}
                    </td>
                    <td>
                      <span className="font-semibold text-xs text-slate-200 block">
                        {rule.name}
                      </span>
                      <span className="text-[10px] text-slate-400">
                        {rule.description}
                      </span>
                    </td>
                    <td className="font-mono text-xs text-slate-300">
                      {rule.protocol || 'TCP'}
                    </td>
                    <td className="font-mono text-xs text-slate-400">
                      {rule.sourcePort || 'any'} &rarr; {rule.destPort || 'any'}
                    </td>
                    <td>
                      <Badge
                        variant={
                          rule.severity === 'CRITICAL'
                            ? 'critical'
                            : rule.severity === 'HIGH'
                            ? 'high'
                            : rule.severity === 'MEDIUM'
                            ? 'medium'
                            : 'low'
                        }
                        size="sm"
                      >
                        {rule.severity}
                      </Badge>
                    </td>
                    <td className="text-xs text-slate-300">
                      {rule.attackCategory}
                    </td>
                    <td className="font-mono text-xs text-cyan-300">
                      {rule.mitreTechniqueId || 'N/A'}
                    </td>
                    <td>
                      <Badge variant={rule.enabled ? 'healthy' : 'neutral'} size="sm" dot>
                        {rule.enabled ? t('rules.statusActive') : t('rules.statusDisabled')}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Multi-Stage Correlations & Recommendations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card
          title={t('rules.correlationsTitle')}
          subtitle={t('rules.correlationsSub')}
          badge={<Badge variant="analyst" size="sm">Sliding Window</Badge>}
        >
          {correlations.length === 0 ? (
            <EmptyState
              title={t('rules.noCorrelations')}
              description={t('rules.noCorrelationsDesc')}
            />
          ) : (
            <div className="flex flex-col gap-3">
              {correlations.map((corr) => (
                <div
                  key={corr.correlationId}
                  className="p-3 bg-slate-900/60 rounded border border-purple-900/60 flex flex-col gap-1.5 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-purple-300">
                      {corr.threatType}
                    </span>
                    <Badge variant="critical" size="sm">
                      Score: {corr.escalatedScore}/100
                    </Badge>
                  </div>
                  <span className="font-mono text-cyan-300">
                    Source: {corr.sourceIp} &bull; Stages: {corr.stageCount} ({corr.stages ? corr.stages.join(' &rarr; ') : 'N/A'})
                  </span>
                  <p className="text-slate-400">{corr.description}</p>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card
          title={t('rules.recommendationsTitle')}
          subtitle={t('rules.recommendationsSub')}
          badge={<Badge variant="student" size="sm">Simulated</Badge>}
        >
          {recommendations.length === 0 ? (
            <EmptyState
              title={t('rules.noRecommendations')}
              description={t('rules.noRecommendationsDesc')}
            />
          ) : (
            <div className="flex flex-col gap-3">
              {recommendations.map((rec) => (
                <div
                  key={rec.recommendationId}
                  className="p-3 bg-slate-900/60 rounded border border-cyan-900/60 flex flex-col gap-2 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-amber-300 font-mono">
                      [SIMULATED] {rec.action}
                    </span>
                    <Badge variant="high" size="sm">
                      Confidence: {rec.confidenceScore}%
                    </Badge>
                  </div>
                  <span className="font-mono text-cyan-300">
                    Target: {rec.targetIp} &bull; MITRE: {rec.mitreTechniqueId}
                  </span>
                  {rec.remediationSteps && rec.remediationSteps.length > 0 && (
                    <ul className="list-disc list-inside text-slate-300 pl-1">
                      {rec.remediationSteps.map((step, idx) => (
                        <li key={idx}>{step}</li>
                      ))}
                    </ul>
                  )}
                  <div className="text-[10px] text-slate-500 font-mono border-t border-slate-800 pt-1.5 mt-1">
                    {rec.safetyDisclaimer}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
};
