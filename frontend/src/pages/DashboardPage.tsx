import React, { useState, useEffect, useCallback, Suspense, lazy } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  Shield,
  Layers,
  Play,
  RotateCw,
  Cpu,
  ArrowUpRight,
  Eye,
  BookOpen,
} from 'lucide-react';
import {
  trafficApi,
  threatApi,
  telemetryApi,
  simulationApi,
} from '../services/api';
import type {
  TrafficStats,
  ThreatSummaryResponse,
  ThreatAlertResponse,
  NetworkNode,
  ScenarioType,
} from '../types';
import { useWebSocket } from '../context/WebSocketContext';
import { useLanguage } from '../context/LanguageContext';
import { useAuth } from '../context/AuthContext';
import { Card } from '../components/common/Card';
import { StatWidget } from '../components/common/StatWidget';
import { Badge } from '../components/common/Badge';
import { Button } from '../components/common/Button';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { EmptyState } from '../components/common/EmptyState';
import { Modal } from '../components/common/Modal';
const NetworkTopology3D = lazy(() =>
  import('../components/topology/NetworkTopology3D').then((m) => ({ default: m.NetworkTopology3D }))
);

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const { hasRole } = useAuth();
  const { subscribeToAlerts, subscribeToTelemetry, isConnected } = useWebSocket();
  const { t } = useLanguage();

  const isAdmin = hasRole('ADMIN');
  const isAnalyst = hasRole('ANALYST');
  const canLaunchSim = isAdmin || isAnalyst;

  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [stats, setStats] = useState<TrafficStats | null>(null);
  const [threatSummary, setThreatSummary] = useState<ThreatSummaryResponse | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<ThreatAlertResponse[]>([]);
  const [nodes, setNodes] = useState<NetworkNode[]>([]);

  const [selectedAlert, setSelectedAlert] = useState<ThreatAlertResponse | null>(null);
  const [quickSimLoading, setQuickSimLoading] = useState(false);
  const [simMessage, setSimMessage] = useState<string | null>(null);

  const loadDashboardData = useCallback(async () => {
    setError(null);
    try {
      const [statsRes, threatSummaryRes, alertsRes, nodesData] = await Promise.all([
        trafficApi.getStats().catch(() => null),
        threatApi.getSummary().catch(() => null),
        threatApi.getAlerts().catch(() => null),
        telemetryApi.getNodes().catch(() => []),
      ]);

      if (statsRes?.data) setStats(statsRes.data);
      if (threatSummaryRes?.data) setThreatSummary(threatSummaryRes.data);
      if (alertsRes?.data) setRecentAlerts(alertsRes.data.slice(0, 6));
      if (nodesData) setNodes(nodesData);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to fetch SOC telemetry';
      setError(msg);
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadDashboardData();

    // Listen to real-time threat alerts over WebSocket
    const unsubAlerts = subscribeToAlerts((newAlert) => {
      setRecentAlerts((prev) => [newAlert, ...prev.slice(0, 5)]);
      setThreatSummary((prev) => {
        if (!prev) return prev;
        const sev = newAlert.severity?.toUpperCase() || 'HIGH';
        const currentCounts = prev.severityCounts || {};
        return {
          ...prev,
          totalAlerts: prev.totalAlerts + 1,
          activeAlerts: prev.activeAlerts + 1,
          severityCounts: {
            ...currentCounts,
            [sev]: (currentCounts[sev] || 0) + 1,
          },
        };
      });
    });

    // Listen to real-time telemetry metrics
    const unsubTelemetry = subscribeToTelemetry(() => {
      setStats((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          totalRecordsProcessed: prev.totalRecordsProcessed + 1,
          totalEventsGenerated: prev.totalEventsGenerated + 1,
        };
      });
    });

    return () => {
      unsubAlerts();
      unsubTelemetry();
    };
  }, [loadDashboardData, subscribeToAlerts, subscribeToTelemetry]);

  const handleRefresh = () => {
    setIsRefreshing(true);
    loadDashboardData();
  };

  const handleQuickLaunch = async (scenario: ScenarioType) => {
    setQuickSimLoading(true);
    setSimMessage(null);
    try {
      const res = await simulationApi.start(scenario, 30);
      setSimMessage(`Launched ${scenario}: ${res.message || 'Processing in memory...'}`);
      setTimeout(() => {
        loadDashboardData();
        navigate('/simulation');
      }, 1200);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Simulation launch error';
      setSimMessage(`Error: ${msg}`);
    } finally {
      setQuickSimLoading(false);
    }
  };

  const getSeverityBadgeVariant = (sev: string) => {
    const s = sev?.toUpperCase();
    if (s === 'CRITICAL') return 'critical';
    if (s === 'HIGH') return 'high';
    if (s === 'MEDIUM') return 'medium';
    if (s === 'LOW') return 'low';
    return 'neutral';
  };

  const safeNodes = Array.isArray(nodes) ? nodes : [];

  const nodeStatusCounts = {
    healthy: safeNodes.filter((n) => n.status === 'HEALTHY').length,
    suspicious: safeNodes.filter((n) => n.status === 'SUSPICIOUS').length,
    compromised: safeNodes.filter((n) => n.status === 'COMPROMISED').length,
    isolated: safeNodes.filter((n) => n.status === 'ISOLATED').length,
  };

  if (isLoading) {
    return <LoadingSpinner message={t('dashboard.loadingData')} />;
  }

  return (
    <div className="cyber-page-content">
      {/* Page Header */}
      <div className="cyber-page-header">
        <div>
          <h1 className="cyber-page-title">{t('dashboard.title')}</h1>
          <p className="cyber-page-desc">
            {t('dashboard.desc')}
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
            {isRefreshing ? t('common.refreshing') : t('common.refresh')}
          </Button>
          {canLaunchSim ? (
            <Button
              variant="primary"
              size="sm"
              onClick={() => navigate('/simulation')}
              leftIcon={<Play size={14} />}
            >
              {t('dashboard.launchSim')}
            </Button>
          ) : (
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate('/learning')}
              leftIcon={<BookOpen size={14} />}
            >
              Learning Lab
            </Button>
          )}
        </div>
      </div>

      {error && (
        <div className="cyber-auth-error mb-6">
          <AlertTriangle size={18} className="flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Telemetry Stat Widgets */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatWidget
          label={t('dashboard.statPackets')}
          value={stats?.totalRecordsProcessed?.toLocaleString() || '0'}
          subtext={t('dashboard.statPacketsSub')}
          variant="blue"
          icon={<Activity size={20} className="text-cyan-400" />}
        />
        <StatWidget
          label={t('dashboard.statFlows')}
          value={stats?.activeFlowCount || 0}
          subtext={t('dashboard.statFlowsSub')}
          variant="purple"
          icon={<Layers size={20} className="text-purple-400" />}
        />
        <StatWidget
          label={t('dashboard.statAlerts')}
          value={threatSummary?.totalAlerts || stats?.totalAlertsPersistedDb || 0}
          subtext={t('dashboard.statAlertsSub', {
            active: threatSummary?.activeAlerts || 0,
            mitigated: threatSummary?.mitigatedAlerts || 0,
          })}
          variant="red"
          icon={<AlertTriangle size={20} className="text-red-400" />}
          onClick={() => navigate('/threats')}
        />
        <StatWidget
          label={t('dashboard.statBaseline')}
          value={stats?.anomalyBaselineReady ? t('dashboard.ready') : t('dashboard.calibrating')}
          subtext={t('dashboard.statBaselineSub', { count: stats?.anomalySampleCount || 0 })}
          variant={stats?.anomalyBaselineReady ? 'green' : 'amber'}
          icon={<Cpu size={20} className={stats?.anomalyBaselineReady ? 'text-emerald-400' : 'text-amber-400'} />}
          onClick={() => navigate('/rules')}
        />
      </div>

      {/* Main Grid: 3D Topology Preview & Threat Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        {/* 3D Topology Preview Card */}
        <Card
          className="lg:col-span-2"
          title={t('dashboard.topologyCardTitle')}
          subtitle={t('dashboard.topologyCardSub', { count: nodes.length })}
          badge={
            <Badge variant={isConnected ? 'healthy' : 'neutral'} size="sm" dot>
              {isConnected ? t('dashboard.liveStream') : t('dashboard.offline')}
            </Badge>
          }
          action={
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate('/topology')}
              rightIcon={<ArrowUpRight size={14} />}
            >
              {t('dashboard.fullScreen3d')}
            </Button>
          }
        >
          {/* Topology Quick Status Badges */}
          <div className="flex flex-wrap items-center gap-2 mb-3">
            <Badge variant="healthy" dot size="sm">
              {t('common.healthy')} ({nodeStatusCounts.healthy})
            </Badge>
            <Badge variant="suspicious" dot size="sm">
              {t('common.suspicious')} ({nodeStatusCounts.suspicious})
            </Badge>
            <Badge variant="compromised" dot size="sm">
              {t('common.compromised')} ({nodeStatusCounts.compromised})
            </Badge>
            {nodeStatusCounts.isolated > 0 && (
              <Badge variant="isolated" dot size="sm">
                {t('common.isolated')} ({nodeStatusCounts.isolated})
              </Badge>
            )}
          </div>

          {/* 3D Topology WebGL Canvas */}
          <Suspense fallback={<LoadingSpinner message="Loading 3D topology engine..." />}>
            <NetworkTopology3D
              nodes={nodes}
              onSelectNode={() => navigate('/topology')}
              height={260}
            />
          </Suspense>
        </Card>

        {/* Threat Distribution & Quick Simulation Launch */}
        <div className="flex flex-col gap-6">
          <Card title={t('dashboard.threatBreakdownTitle')} subtitle={t('dashboard.threatBreakdownSub')}>
            <div className="cyber-severity-breakdown">
              <div className="cyber-sev-item cyber-sev-item--critical">
                <span className="cyber-sev-label">{t('common.critical')}</span>
                <span className="cyber-sev-count">
                  {threatSummary?.severityCounts?.CRITICAL || 0}
                </span>
              </div>
              <div className="cyber-sev-item cyber-sev-item--high">
                <span className="cyber-sev-label">{t('common.high')}</span>
                <span className="cyber-sev-count">
                  {threatSummary?.severityCounts?.HIGH || 0}
                </span>
              </div>
              <div className="cyber-sev-item cyber-sev-item--medium">
                <span className="cyber-sev-label">{t('common.medium')}</span>
                <span className="cyber-sev-count">
                  {threatSummary?.severityCounts?.MEDIUM || 0}
                </span>
              </div>
              <div className="cyber-sev-item cyber-sev-item--low">
                <span className="cyber-sev-label">{t('common.low')}</span>
                <span className="cyber-sev-count">
                  {threatSummary?.severityCounts?.LOW || 0}
                </span>
              </div>
            </div>
          </Card>

          {canLaunchSim ? (
            <Card
              title={t('dashboard.quickLaunchTitle')}
              subtitle={t('dashboard.quickLaunchSub')}
              badge={<Badge variant={isAdmin ? 'admin' : 'analyst'} size="sm">{isAdmin ? 'ADMIN CONTROL' : 'ANALYST OPS'}</Badge>}
            >
              {simMessage && (
                <div className="p-2 mb-3 bg-cyan-950/40 border border-cyan-800/60 rounded text-xs text-cyan-300">
                  {simMessage}
                </div>
              )}
              <div className="flex flex-col gap-2">
                <button
                  type="button"
                  className="cyber-quick-scenario-btn"
                  onClick={() => handleQuickLaunch('SYN_FLOOD_PATTERN')}
                  disabled={quickSimLoading}
                >
                  <div className="flex items-center gap-2">
                    <Play size={14} className="text-red-400" />
                    <span className="font-semibold text-xs text-slate-200">SYN Flood Attack</span>
                  </div>
                  <span className="text-[10px] text-slate-400">30 records</span>
                </button>

                <button
                  type="button"
                  className="cyber-quick-scenario-btn"
                  onClick={() => handleQuickLaunch('PORT_SCAN_PATTERN')}
                  disabled={quickSimLoading}
                >
                  <div className="flex items-center gap-2">
                    <Play size={14} className="text-amber-400" />
                    <span className="font-semibold text-xs text-slate-200">Port Scan Probing</span>
                  </div>
                  <span className="text-[10px] text-slate-400">30 records</span>
                </button>

                <button
                  type="button"
                  className="cyber-quick-scenario-btn"
                  onClick={() => handleQuickLaunch('NORMAL_TRAFFIC')}
                  disabled={quickSimLoading}
                >
                  <div className="flex items-center gap-2">
                    <Play size={14} className="text-emerald-400" />
                    <span className="font-semibold text-xs text-slate-200">Normal Baseline Traffic</span>
                  </div>
                  <span className="text-[10px] text-slate-400">30 records</span>
                </button>
              </div>
            </Card>
          ) : (
            <Card
              title="Academic Threat Lab"
              subtitle="Student learning & detection analysis"
              badge={<Badge variant="student" size="sm">Learning Mode</Badge>}
            >
              <div className="flex flex-col gap-3 text-xs text-slate-300">
                <p className="leading-relaxed">
                  As an academic student, your profile has read-only clearance to inspect live 3D network topology, study MITRE ATT&amp;CK mappings, and review AI threat explanations.
                </p>
                <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800 flex items-center justify-between">
                  <span className="text-slate-400 font-mono">Interactive Guide:</span>
                  <Button
                    variant="primary"
                    size="sm"
                    onClick={() => navigate('/learning')}
                    leftIcon={<BookOpen size={14} />}
                  >
                    Open Learning Lab
                  </Button>
                </div>
              </div>
            </Card>
          )}
        </div>
      </div>

      {/* Recent Alerts Table */}
      <Card
        title={t('dashboard.recentAlertsTitle')}
        subtitle={t('dashboard.recentAlertsSub')}
        action={
          <Button
            variant="ghost"
            size="sm"
            onClick={() => navigate('/threats')}
            rightIcon={<ArrowUpRight size={14} />}
          >
            {t('dashboard.viewAllAlerts')}
          </Button>
        }
      >
        {recentAlerts.length === 0 ? (
          <EmptyState
            title={t('dashboard.noAlerts')}
            description=""
            action={
              canLaunchSim ? (
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => handleQuickLaunch('MIXED_SUSPICIOUS_ACTIVITY')}
                >
                  {t('dashboard.launchSim')}
                </Button>
              ) : undefined
            }
          />
        ) : (
          <div className="cyber-table-container">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>{t('common.timestamp')}</th>
                  <th>{t('common.severity')}</th>
                  <th>{t('threats.colAttack')}</th>
                  <th>{t('threats.colEndpoints')}</th>
                  <th>{t('threats.colScore')}</th>
                  <th>{t('threats.colMitigation')}</th>
                  <th>{t('common.actions')}</th>
                </tr>
              </thead>
              <tbody>
                {recentAlerts.map((alert) => (
                  <tr key={alert.id} className="cyber-table-row">
                    <td className="font-mono text-xs text-slate-400">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </td>
                    <td>
                      <Badge variant={getSeverityBadgeVariant(alert.severity)} size="sm">
                        {alert.severity}
                      </Badge>
                    </td>
                    <td className="font-medium text-slate-200 text-xs">
                      {alert.attackType}
                    </td>
                    <td className="font-mono text-xs text-slate-300">
                      {alert.sourceIp}:{alert.sourcePort} &rarr; {alert.destinationIp}:{alert.destinationPort}
                    </td>
                    <td>
                      <span className="cyber-score-pill">
                        {alert.threatScore}/100
                      </span>
                    </td>
                    <td>
                      <Badge
                        variant={alert.mitigationStatus === 'MITIGATED' ? 'mitigated' : 'active'}
                        size="sm"
                      >
                        {alert.mitigationStatus}
                      </Badge>
                    </td>
                    <td>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setSelectedAlert(alert)}
                        leftIcon={<Eye size={14} />}
                      >
                        {t('topology.colAction')}
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Alert Details Modal */}
      <Modal
        isOpen={!!selectedAlert}
        onClose={() => setSelectedAlert(null)}
        title={
          selectedAlert && (
            <div className="flex items-center gap-2">
              <Shield size={18} className="text-red-400" />
              <span>{t('dashboard.modalTitle', { id: selectedAlert.id })}</span>
            </div>
          )
        }
        footer={
          <div className="flex items-center justify-between w-full">
            <span className="text-xs text-slate-400 font-mono">
              MITRE ATT&CK: {selectedAlert?.mitreTechniqueId || 'T1498'} ({selectedAlert?.mitreTechniqueName || 'Network Denial of Service'})
            </span>
            <Button variant="primary" size="sm" onClick={() => setSelectedAlert(null)}>
              {t('common.close')}
            </Button>
          </div>
        }
      >
        {selectedAlert && (
          <div className="flex flex-col gap-4 text-xs">
            <div className="grid grid-cols-2 gap-3 p-3 bg-slate-900/60 rounded border border-slate-800">
              <div>
                <span className="text-slate-400 font-mono block">{t('common.severity')}</span>
                <Badge variant={getSeverityBadgeVariant(selectedAlert.severity)} size="sm" className="mt-1">
                  {selectedAlert.severity} (Score: {selectedAlert.threatScore}/100)
                </Badge>
              </div>
              <div>
                <span className="text-slate-400 font-mono block">{t('rules.colCategory')}</span>
                <span className="text-slate-200 font-semibold mt-1 block">{selectedAlert.attackType}</span>
              </div>
              <div>
                <span className="text-slate-400 font-mono block">{t('common.source')}</span>
                <span className="text-slate-200 font-mono mt-1 block">
                  {selectedAlert.sourceIp}:{selectedAlert.sourcePort} ({selectedAlert.protocol})
                </span>
              </div>
              <div>
                <span className="text-slate-400 font-mono block">{t('common.destination')}</span>
                <span className="text-slate-200 font-mono mt-1 block">
                  {selectedAlert.destinationIp}:{selectedAlert.destinationPort}
                </span>
              </div>
            </div>

            <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
              <span className="text-slate-400 font-mono block mb-1">{t('threats.explainabilityTitle')}</span>
              <p className="text-slate-200 leading-relaxed">{selectedAlert.description}</p>
            </div>

            {selectedAlert.signatureRule && (
              <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
                <span className="text-slate-400 font-mono block mb-1">{t('rules.colRuleName')}</span>
                <code className="text-xs text-cyan-300 font-mono block bg-black/40 p-2 rounded">
                  {selectedAlert.signatureRule}
                </code>
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
};
