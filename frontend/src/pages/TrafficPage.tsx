import React, { useState, useEffect, useCallback } from 'react';
import {
  RotateCw,
  Send,
  CheckCircle2,
  AlertTriangle,
  Search,
} from 'lucide-react';
import { trafficApi } from '../services/api';
import type {
  NetworkFlow,
  TrafficStats,
  TrafficRecordRequest,
  PipelineResultResponse,
} from '../types';
import { useLanguage } from '../context/LanguageContext';
import { useAuth } from '../context/AuthContext';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { Button } from '../components/common/Button';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { EmptyState } from '../components/common/EmptyState';

export const TrafficPage: React.FC = () => {
  const { hasRole } = useAuth();
  const { t } = useLanguage();
  const isAdmin = hasRole('ADMIN');
  const [flows, setFlows] = useState<NetworkFlow[]>([]);
  const [stats, setStats] = useState<TrafficStats | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [searchQuery, setSearchQuery] = useState('');

  // Packet Analyzer State
  const [testSrcIp, setTestSrcIp] = useState('192.168.1.105');
  const [testSrcPort, setTestSrcPort] = useState('44321');
  const [testDstIp, setTestDstIp] = useState('192.168.1.10');
  const [testDstPort, setTestDstPort] = useState('80');
  const [testProtocol, setTestProtocol] = useState('TCP');
  const [testFlags, setTestFlags] = useState('SYN');
  const [testPayload, setTestPayload] = useState('GET /login.php?id=1%27%20OR%201=1-- HTTP/1.1');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<PipelineResultResponse | null>(null);
  const [analysisError, setAnalysisError] = useState<string | null>(null);

  const loadTrafficData = useCallback(async () => {
    setError(null);
    try {
      const [flowsRes, statsRes] = await Promise.all([
        trafficApi.getRecentFlows().catch(() => ({ data: [] })),
        trafficApi.getStats().catch(() => ({ data: null })),
      ]);
      if (flowsRes.data) setFlows(flowsRes.data);
      if (statsRes.data) setStats(statsRes.data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to query traffic flows';
      setError(msg);
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadTrafficData();
  }, [loadTrafficData]);

  const handleRefresh = () => {
    setIsRefreshing(true);
    loadTrafficData();
  };

  const handleAnalyzePacket = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsAnalyzing(true);
    setAnalysisError(null);
    setAnalysisResult(null);

    const record: TrafficRecordRequest = {
      sourceIp: testSrcIp.trim(),
      sourcePort: Number(testSrcPort) || 1024,
      destinationIp: testDstIp.trim(),
      destinationPort: Number(testDstPort) || 80,
      protocol: testProtocol.toUpperCase(),
      tcpFlags: testFlags.toUpperCase(),
      packetSize: 64 + (testPayload ? testPayload.length : 0),
      payloadLength: testPayload ? testPayload.length : 0,
      simulatedPayloadSnippet: testPayload,
    };

    try {
      const res = await trafficApi.analyze(record);
      if (res.data) {
        setAnalysisResult(res.data);
        loadTrafficData();
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Analysis failed';
      setAnalysisError(msg);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handlePresetFill = (type: 'sql' | 'syn' | 'normal') => {
    if (type === 'sql') {
      setTestSrcIp('192.168.1.105');
      setTestSrcPort('54321');
      setTestDstIp('192.168.1.10');
      setTestDstPort('80');
      setTestProtocol('TCP');
      setTestFlags('PSH,ACK');
      setTestPayload('SELECT * FROM users WHERE username = "admin" OR "1"="1"');
    } else if (type === 'syn') {
      setTestSrcIp('10.0.0.99');
      setTestSrcPort('61234');
      setTestDstIp('192.168.1.10');
      setTestDstPort('80');
      setTestProtocol('TCP');
      setTestFlags('SYN');
      setTestPayload('');
    } else {
      setTestSrcIp('192.168.1.45');
      setTestSrcPort('49152');
      setTestDstIp('192.168.1.10');
      setTestDstPort('443');
      setTestProtocol('TCP');
      setTestFlags('ACK');
      setTestPayload('GET /index.html HTTP/1.1');
    }
  };

  const filteredFlows = flows.filter((f) => {
    const q = searchQuery.toLowerCase();
    return (
      (f.sourceIp ?? '').toLowerCase().includes(q) ||
      (f.destinationIp ?? '').toLowerCase().includes(q) ||
      (f.protocol ?? '').toLowerCase().includes(q) ||
      String(f.sourcePort ?? '').includes(q) ||
      String(f.destinationPort ?? '').includes(q)
    );
  });

  if (isLoading && !isRefreshing) {
    return <LoadingSpinner message={t('traffic.loadingData')} />;
  }

  return (
    <div className="cyber-page-content">
      {/* Page Header */}
      <div className="cyber-page-header">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h1 className="cyber-page-title mb-0">{t('traffic.title')}</h1>
            <Badge variant={isAdmin ? 'admin' : 'analyst'} size="sm">
              {isAdmin ? 'ADMIN INSPECTION' : 'ANALYST OPERATIONS'}
            </Badge>
          </div>
          <p className="cyber-page-desc">
            {t('traffic.desc')}
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
            {isRefreshing ? t('common.refreshing') : t('traffic.refreshFlows')}
          </Button>
        </div>
      </div>

      {error && (
        <div className="cyber-auth-error mb-4">
          <span>{error}</span>
        </div>
      )}

      {/* Traffic Stats Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
        <div className="cyber-stat-widget cyber-stat-widget--blue">
          <span className="cyber-stat-label">{t('dashboard.statPackets')}</span>
          <span className="cyber-stat-value text-cyan-400">
            {stats?.totalRecordsProcessed || 0}
          </span>
          <span className="cyber-stat-subtext">{t('dashboard.statPacketsSub')}</span>
        </div>
        <div className="cyber-stat-widget cyber-stat-widget--purple">
          <span className="cyber-stat-label">{t('dashboard.statFlows')}</span>
          <span className="cyber-stat-value text-purple-400">
            {stats?.activeFlowCount || 0}
          </span>
          <span className="cyber-stat-subtext">{t('dashboard.statFlowsSub')}</span>
        </div>
        <div className="cyber-stat-widget cyber-stat-widget--green">
          <span className="cyber-stat-label">{t('simulation.packetsProcessed')}</span>
          <span className="cyber-stat-value text-emerald-400">
            {stats?.totalEventsGenerated || 0}
          </span>
          <span className="cyber-stat-subtext">Scored by Hybrid Engine</span>
        </div>
        <div className="cyber-stat-widget cyber-stat-widget--red">
          <span className="cyber-stat-label">{t('dashboard.statAlerts')}</span>
          <span className="cyber-stat-value text-red-400">
            {stats?.totalAlertsPersistedDb || 0}
          </span>
          <span className="cyber-stat-subtext">High &amp; Critical in H2</span>
        </div>
      </div>

      {/* Single Packet Pipeline Evaluator */}
      <Card
        className="mb-6"
        title={t('traffic.analyzerTitle')}
        subtitle={t('traffic.analyzerSub')}
        badge={<Badge variant={isAdmin ? 'admin' : 'analyst'} size="sm">{isAdmin ? 'Admin Live Analyzer' : 'Analyst Live Analyzer'}</Badge>}
      >
        <div className="mb-3 flex items-center gap-2">
          <span className="text-xs text-slate-400 font-mono">{t('traffic.presets')}</span>
          <button
            type="button"
            className="text-xs text-cyan-400 hover:underline font-mono"
            onClick={() => handlePresetFill('sql')}
          >
            [{t('traffic.presetSql')}]
          </button>
          <button
            type="button"
            className="text-xs text-amber-400 hover:underline font-mono"
            onClick={() => handlePresetFill('syn')}
          >
            [{t('traffic.presetSyn')}]
          </button>
          <button
            type="button"
            className="text-xs text-emerald-400 hover:underline font-mono"
            onClick={() => handlePresetFill('normal')}
          >
            [{t('traffic.presetNormal')}]
          </button>
        </div>

        <form onSubmit={handleAnalyzePacket} className="flex flex-col gap-4">
          <div className="grid grid-cols-2 sm:grid-cols-6 gap-3">
            <div>
              <label className="text-[11px] text-slate-400 font-mono block mb-1">{t('traffic.srcIp')}</label>
              <input
                type="text"
                required
                className="cyber-input text-xs"
                value={testSrcIp}
                onChange={(e) => setTestSrcIp(e.target.value)}
              />
            </div>
            <div>
              <label className="text-[11px] text-slate-400 font-mono block mb-1">{t('traffic.srcPort')}</label>
              <input
                type="number"
                required
                className="cyber-input text-xs"
                value={testSrcPort}
                onChange={(e) => setTestSrcPort(e.target.value)}
              />
            </div>
            <div>
              <label className="text-[11px] text-slate-400 font-mono block mb-1">{t('traffic.dstIp')}</label>
              <input
                type="text"
                required
                className="cyber-input text-xs"
                value={testDstIp}
                onChange={(e) => setTestDstIp(e.target.value)}
              />
            </div>
            <div>
              <label className="text-[11px] text-slate-400 font-mono block mb-1">{t('traffic.dstPort')}</label>
              <input
                type="number"
                required
                className="cyber-input text-xs"
                value={testDstPort}
                onChange={(e) => setTestDstPort(e.target.value)}
              />
            </div>
            <div>
              <label className="text-[11px] text-slate-400 font-mono block mb-1">{t('traffic.protocol')}</label>
              <select
                className="cyber-input cyber-select text-xs"
                value={testProtocol}
                onChange={(e) => setTestProtocol(e.target.value)}
              >
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
              </select>
            </div>
            <div>
              <label className="text-[11px] text-slate-400 font-mono block mb-1">{t('traffic.tcpFlags')}</label>
              <input
                type="text"
                className="cyber-input text-xs"
                value={testFlags}
                onChange={(e) => setTestFlags(e.target.value)}
              />
            </div>
          </div>

          <div>
            <label className="text-[11px] text-slate-400 font-mono block mb-1">
              {t('traffic.payload')}
            </label>
            <input
              type="text"
              className="cyber-input text-xs"
              placeholder="e.g. GET /index.php?user=admin HTTP/1.1"
              value={testPayload}
              onChange={(e) => setTestPayload(e.target.value)}
            />
          </div>

          <div className="flex items-center gap-3">
            <Button
              type="submit"
              variant="primary"
              size="sm"
              isLoading={isAnalyzing}
              leftIcon={<Send size={14} />}
            >
              {isAnalyzing ? t('traffic.analyzing') : t('traffic.btnAnalyze')}
            </Button>
          </div>
        </form>

        {analysisError && (
          <div className="cyber-auth-error mt-4">
            <AlertTriangle size={16} />
            <span>{analysisError}</span>
          </div>
        )}

        {/* Live Analysis Output */}
        {analysisResult && (
          <div className="mt-4 p-4 bg-slate-900/80 rounded border border-cyan-800/80 flex flex-col gap-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center gap-2">
                <CheckCircle2 size={16} className="text-emerald-400" />
                <span className="text-xs font-semibold text-slate-200">
                  {t('traffic.analysisResultTitle')}: {analysisResult.detectionEvent.threatType}
                </span>
              </div>
              <Badge
                variant={
                  analysisResult.detectionEvent.severity === 'CRITICAL'
                    ? 'critical'
                    : analysisResult.detectionEvent.severity === 'HIGH'
                    ? 'high'
                    : analysisResult.detectionEvent.severity === 'MEDIUM'
                    ? 'medium'
                    : 'low'
                }
                size="sm"
              >
                {analysisResult.detectionEvent.severity} &bull; {t('traffic.threatScore')}{' '}
                {analysisResult.detectionEvent.threatScore}/100
              </Badge>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
              <div>
                <span className="text-[10px] text-slate-400 font-mono block">{t('traffic.matchedRule')}</span>
                <span className="text-slate-200 font-mono">
                  {analysisResult.detectionEvent.signatureMatched
                    ? `${analysisResult.detectionEvent.matchedRuleId} (${analysisResult.detectionEvent.matchedRuleName})`
                    : 'No Signature Match'}
                </span>
              </div>
              <div>
                <span className="text-[10px] text-slate-400 font-mono block">{t('traffic.anomalyScore')}</span>
                <span className="text-slate-200 font-mono">
                  {analysisResult.detectionEvent.anomalous
                    ? `Z-Score: ${(analysisResult.detectionEvent.anomalyScore ?? 0).toFixed(2)}`
                    : 'Within Baseline'}
                </span>
              </div>
              <div>
                <span className="text-[10px] text-slate-400 font-mono block">MITRE ATT&amp;CK</span>
                <span className="text-cyan-300 font-mono">
                  {analysisResult.detectionEvent.mitreTechniqueId} &bull;{' '}
                  {analysisResult.detectionEvent.mitreTechniqueName}
                </span>
              </div>
              <div>
                <span className="text-[10px] text-slate-400 font-mono block">{t('threats.recommendationTitle')}</span>
                <span className="text-amber-400 font-mono">
                  {analysisResult.detectionEvent.recommendedAction}
                </span>
              </div>
            </div>

            <div className="text-xs text-slate-300 leading-relaxed bg-black/40 p-2.5 rounded border border-slate-800">
              <strong className="text-cyan-400 block font-mono text-[10px] mb-0.5">
                {t('threats.explainabilityTitle').toUpperCase()}
              </strong>
              {analysisResult.detectionEvent.explanation}
            </div>
          </div>
        )}
      </Card>

      {/* Recent Flows Table */}
      <Card
        title={t('traffic.recentFlowsTitle')}
        subtitle={t('traffic.recentFlowsSub')}
      >
        <div className="mb-4">
          <div className="cyber-search-wrapper w-full sm:w-80">
            <Search size={16} className="cyber-search-icon" />
            <input
              type="text"
              className="cyber-input cyber-search-input"
              placeholder="Filter flows by IP, port, protocol..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
        </div>

        {filteredFlows.length === 0 ? (
          <EmptyState
            title={t('traffic.noFlowsFound')}
            description=""
          />
        ) : (
          <div className="cyber-table-container">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>Flow Key</th>
                  <th>{t('threats.colEndpoints')}</th>
                  <th>{t('common.destination')}</th>
                  <th>{t('traffic.colPackets')} / {t('traffic.colBytes')}</th>
                  <th>{t('traffic.colDuration')}</th>
                  <th>TCP Flags (S/A/F/R)</th>
                  <th>{t('common.timestamp')}</th>
                </tr>
              </thead>
              <tbody>
                {filteredFlows.map((flow) => (
                  <tr key={flow.id} className="cyber-table-row">
                    <td className="font-mono text-[11px] text-slate-500">#{flow.id}</td>
                    <td className="font-mono text-xs text-slate-300">
                      {flow.sourceIp}:{flow.sourcePort ?? 0} ({flow.protocol || 'TCP'})
                    </td>
                    <td className="font-mono text-xs text-cyan-300">
                      {flow.destinationIp}:{flow.destinationPort ?? 0}
                    </td>
                    <td className="font-mono text-xs text-slate-300">
                      {flow.packetCount ?? 0} pkts / {(flow.byteCount ?? 0).toLocaleString()} B
                    </td>
                    <td className="font-mono text-xs text-slate-400">
                      {flow.durationMs ?? 0} ms
                    </td>
                    <td className="font-mono text-xs text-slate-400">
                      {flow.synCount ?? 0}/{flow.ackCount ?? 0}/{flow.finCount ?? 0}/{flow.rstCount ?? 0}
                    </td>
                    <td className="font-mono text-[10px] text-slate-500">
                      {flow.flowStart ? new Date(flow.flowStart).toLocaleTimeString() : '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
};
