import React, { useState, useEffect, useCallback } from 'react';
import {
  AlertTriangle,
  RotateCw,
  Search,
  Eye,
  Shield,
  CheckCircle,
  Filter,
} from 'lucide-react';
import { threatApi } from '../services/api';
import type { ThreatAlertResponse, ThreatSummaryResponse, MitigationStatus } from '../types';
import { useAuth } from '../context/AuthContext';
import { useWebSocket } from '../context/WebSocketContext';
import { useLanguage } from '../context/LanguageContext';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { Button } from '../components/common/Button';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { EmptyState } from '../components/common/EmptyState';
import { Modal } from '../components/common/Modal';

export const ThreatsPage: React.FC = () => {
  const { hasRole, user } = useAuth();
  const { subscribeToAlerts } = useWebSocket();
  const { t } = useLanguage();
  const canMitigate = hasRole('ADMIN') || hasRole('ANALYST');

  const [alerts, setAlerts] = useState<ThreatAlertResponse[]>([]);
  const [summary, setSummary] = useState<ThreatSummaryResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlertResponse | null>(null);
  const [mitigatingAlertId, setMitigatingAlertId] = useState<number | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  const loadAlerts = useCallback(async (severity = selectedSeverity) => {
    setError(null);
    try {
      const [alertsRes, summaryRes] = await Promise.all([
        threatApi.getAlerts(severity),
        threatApi.getSummary(),
      ]);

      if (alertsRes.data) setAlerts(alertsRes.data);
      if (summaryRes.data) setSummary(summaryRes.data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to query threat alerts';
      setError(msg);
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, [selectedSeverity]);

  useEffect(() => {
    loadAlerts(selectedSeverity);

    // Real-time alert subscription
    const unsub = subscribeToAlerts((incomingAlert) => {
      setAlerts((prev) => [incomingAlert, ...prev]);
      setSummary((prev) => {
        if (!prev) return prev;
        const sev = incomingAlert.severity?.toUpperCase() || 'HIGH';
        return {
          ...prev,
          totalAlerts: prev.totalAlerts + 1,
          activeAlerts: prev.activeAlerts + 1,
          severityCounts: {
            ...(prev.severityCounts || {}),
            [sev]: ((prev.severityCounts && prev.severityCounts[sev]) || 0) + 1,
          },
        };
      });
    });

    return () => unsub();
  }, [loadAlerts, selectedSeverity, subscribeToAlerts]);

  const handleRefresh = () => {
    setIsRefreshing(true);
    loadAlerts(selectedSeverity);
  };

  const handleSeverityChange = (sev: string) => {
    setSelectedSeverity(sev);
    setIsLoading(true);
    loadAlerts(sev);
  };

  const handleUpdateStatus = async (alertId: number, newStatus: MitigationStatus) => {
    setMitigatingAlertId(alertId);
    setActionSuccess(null);
    try {
      await threatApi.updateMitigationStatus(alertId, newStatus);
      setActionSuccess(`Alert #${alertId} updated to ${newStatus}`);
      // Update local state
      setAlerts((prev) =>
        prev.map((a) => (a.id === alertId ? { ...a, mitigationStatus: newStatus } : a))
      );
      if (selectedAlert && selectedAlert.id === alertId) {
        setSelectedAlert({ ...selectedAlert, mitigationStatus: newStatus });
      }
      loadAlerts();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to update mitigation status';
      setError(msg);
    } finally {
      setMitigatingAlertId(null);
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

  const filteredAlerts = alerts.filter((alert) => {
    const q = searchQuery.toLowerCase();
    return (
      (alert.attackType ?? '').toLowerCase().includes(q) ||
      (alert.sourceIp ?? '').toLowerCase().includes(q) ||
      (alert.destinationIp ?? '').toLowerCase().includes(q) ||
      (alert.description ?? '').toLowerCase().includes(q) ||
      (alert.signatureRule && alert.signatureRule.toLowerCase().includes(q)) ||
      (alert.mitreTechniqueId && alert.mitreTechniqueId.toLowerCase().includes(q))
    );
  });

  if (isLoading && !isRefreshing) {
    return <LoadingSpinner message={t('threats.loadingData')} />;
  }

  return (
    <div className="cyber-page-content">
      {/* Page Header */}
      <div className="cyber-page-header">
        <div>
          <h1 className="cyber-page-title">{t('threats.title')}</h1>
          <p className="cyber-page-desc">
            {t('threats.desc')}
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
            {isRefreshing ? t('common.refreshing') : t('threats.refreshAlerts')}
          </Button>
        </div>
      </div>

      {actionSuccess && (
        <div className="p-3 mb-4 bg-emerald-950/40 border border-emerald-800/60 rounded text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircle size={16} />
          <span>{actionSuccess}</span>
        </div>
      )}

      {error && (
        <div className="cyber-auth-error mb-4">
          <AlertTriangle size={16} />
          <span>{error}</span>
        </div>
      )}

      {/* Threat Summary Widgets */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
        <div className="cyber-stat-widget cyber-stat-widget--red">
          <span className="cyber-stat-label">{t('common.critical')}</span>
          <span className="cyber-stat-value text-red-400">
            {summary?.severityCounts?.CRITICAL || 0}
          </span>
          <span className="cyber-stat-subtext">Immediate Response Recommended</span>
        </div>
        <div className="cyber-stat-widget cyber-stat-widget--amber">
          <span className="cyber-stat-label">{t('common.high')}</span>
          <span className="cyber-stat-value text-amber-400">
            {summary?.severityCounts?.HIGH || 0}
          </span>
          <span className="cyber-stat-subtext">Multi-Stage / DoS Ingested</span>
        </div>
        <div className="cyber-stat-widget cyber-stat-widget--blue">
          <span className="cyber-stat-label">{t('threats.colMitigation')}</span>
          <span className="cyber-stat-value text-cyan-400">
            {summary?.activeAlerts || 0} / {summary?.mitigatedAlerts || 0}
          </span>
          <span className="cyber-stat-subtext">
            {canMitigate ? 'RBAC: Mitigation Permitted' : 'RBAC: Read-Only (Student)'}
          </span>
        </div>
        <div className="cyber-stat-widget cyber-stat-widget--neutral">
          <span className="cyber-stat-label">{t('dashboard.statAlerts')}</span>
          <span className="cyber-stat-value text-slate-200">
            {summary?.totalAlerts || 0}
          </span>
          <span className="cyber-stat-subtext">Persisted in H2 Database</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 mb-4">
        <div className="cyber-search-wrapper w-full sm:w-80">
          <Search size={16} className="cyber-search-icon" />
          <input
            type="text"
            className="cyber-input cyber-search-input"
            placeholder={t('threats.searchPlaceholder')}
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <div className="flex items-center gap-2 overflow-x-auto w-full sm:w-auto">
          <Filter size={14} className="text-slate-500 hidden sm:block mr-1" />
          {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => {
            const label = sev === 'ALL' ? t('threats.filterAll') :
              sev === 'CRITICAL' ? t('threats.filterCritical') :
              sev === 'HIGH' ? t('threats.filterHigh') :
              sev === 'MEDIUM' ? t('threats.filterMedium') : t('threats.filterLow');
            return (
              <button
                key={sev}
                type="button"
                className={`cyber-filter-pill ${selectedSeverity === sev ? 'cyber-filter-pill--active' : ''}`}
                onClick={() => handleSeverityChange(sev)}
              >
                {label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Alerts Table */}
      <Card
        title={t('threats.title')}
        subtitle={`Showing ${filteredAlerts.length} alerts matching filter`}
      >
        {filteredAlerts.length === 0 ? (
          <EmptyState
            title={t('threats.noAlertsFound')}
            description=""
          />
        ) : (
          <div className="cyber-table-container">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>{t('threats.colId')}</th>
                  <th>{t('common.timestamp')}</th>
                  <th>{t('common.severity')}</th>
                  <th>{t('threats.colAttack')}</th>
                  <th>{t('threats.colEndpoints')}</th>
                  <th>{t('common.protocol')}</th>
                  <th>{t('threats.colScore')}</th>
                  <th>{t('threats.colMitigation')}</th>
                  <th>{t('common.actions')}</th>
                </tr>
              </thead>
              <tbody>
                {filteredAlerts.map((alert) => (
                  <tr key={alert.id} className="cyber-table-row">
                    <td className="font-mono text-xs text-slate-500">#{alert.id}</td>
                    <td className="font-mono text-xs text-slate-400">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </td>
                    <td>
                      <Badge variant={getSeverityBadgeVariant(alert.severity)} size="sm">
                        {alert.severity}
                      </Badge>
                    </td>
                    <td>
                      <span className="font-semibold text-xs text-slate-200 block">
                        {alert.attackType}
                      </span>
                      {alert.mitreTechniqueId && (
                        <span className="text-[10px] text-cyan-400 font-mono">
                          {alert.mitreTechniqueId}
                        </span>
                      )}
                    </td>
                    <td className="font-mono text-xs text-slate-300">
                      {alert.sourceIp}:{alert.sourcePort ?? 0} &rarr; {alert.destinationIp}:{alert.destinationPort ?? 0}
                    </td>
                    <td className="font-mono text-xs text-cyan-400">
                      {alert.protocol || 'TCP'}
                    </td>
                    <td>
                      <span className="cyber-score-pill">{alert.threatScore}/100</span>
                    </td>
                    <td>
                      <Badge
                        variant={
                          alert.mitigationStatus === 'MITIGATED'
                            ? 'mitigated'
                            : alert.mitigationStatus === 'BLOCKED'
                            ? 'blocked'
                            : 'active'
                        }
                        size="sm"
                      >
                        {alert.mitigationStatus}
                      </Badge>
                    </td>
                    <td>
                      <div className="flex items-center gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setSelectedAlert(alert)}
                          leftIcon={<Eye size={14} />}
                        >
                          {t('threats.colInspect')}
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Threat Investigation Drawer Modal */}
      <Modal
        isOpen={!!selectedAlert}
        onClose={() => setSelectedAlert(null)}
        title={
          selectedAlert && (
            <div className="flex items-center gap-2">
              <Shield size={18} className="text-red-400" />
              <span>
                {t('threats.modalTitle', { id: selectedAlert.id })} &mdash; {selectedAlert.attackType}
              </span>
            </div>
          )
        }
        footer={
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 w-full">
            <div className="text-xs text-slate-400 font-mono">
              Role: <span className="text-cyan-300">{user?.role?.replace('ROLE_', '')}</span> &bull; Status:{' '}
              <span className="text-slate-200">{selectedAlert?.mitigationStatus}</span>
            </div>
            <div className="flex items-center gap-2">
              {canMitigate ? (
                selectedAlert && (
                  <>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={selectedAlert.mitigationStatus === 'MITIGATED'}
                      isLoading={mitigatingAlertId === selectedAlert.id}
                      onClick={() => handleUpdateStatus(selectedAlert.id, 'MITIGATED')}
                    >
                      {t('threats.setMitigated')}
                    </Button>
                    <Button
                      variant="danger"
                      size="sm"
                      disabled={selectedAlert.mitigationStatus === 'BLOCKED'}
                      isLoading={mitigatingAlertId === selectedAlert.id}
                      onClick={() => handleUpdateStatus(selectedAlert.id, 'BLOCKED')}
                    >
                      Block Simulated IP
                    </Button>
                  </>
                )
              ) : (
                <span className="text-xs text-amber-400 font-mono px-2 py-1 bg-amber-950/30 rounded border border-amber-800/40">
                  Read-Only: Mitigation restricted to Analyst / Admin
                </span>
              )}
              <Button variant="primary" size="sm" onClick={() => setSelectedAlert(null)}>
                {t('common.close')}
              </Button>
            </div>
          </div>
        }
      >
        {selectedAlert && (
          <div className="flex flex-col gap-4 text-xs">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3 bg-slate-900/60 rounded border border-slate-800">
              <div>
                <span className="text-slate-400 font-mono block">{t('traffic.threatScore')}</span>
                <span className="text-lg font-bold text-red-400 font-mono mt-0.5 block">
                  {selectedAlert.threatScore} / 100
                </span>
              </div>
              <div>
                <span className="text-slate-400 font-mono block">{t('common.severity')}</span>
                <Badge variant={getSeverityBadgeVariant(selectedAlert.severity)} size="sm" className="mt-1">
                  {selectedAlert.severity}
                </Badge>
              </div>
              <div>
                <span className="text-slate-400 font-mono block">{t('threats.colMitigation')}</span>
                <span className="font-semibold text-slate-200 mt-1 block">
                  {selectedAlert.mitigationStatus}
                </span>
              </div>
              <div>
                <span className="text-slate-400 font-mono block">{t('common.protocol')}</span>
                <span className="font-mono text-cyan-300 mt-1 block">{selectedAlert.protocol}</span>
              </div>
            </div>

            <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
              <span className="text-slate-400 font-mono block mb-1">MITRE ATT&amp;CK Framework</span>
              <div className="flex items-center gap-2">
                <Badge variant="analyst" size="sm">
                  {selectedAlert.mitreTechniqueId || 'T1498'}
                </Badge>
                <span className="text-slate-200 font-medium">
                  {selectedAlert.mitreTechniqueName || 'Network Denial of Service'}
                </span>
              </div>
            </div>

            <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
              <span className="text-slate-400 font-mono block mb-1">{t('threats.colEndpoints')}</span>
              <div className="font-mono text-slate-300 text-xs">
                <div>Source IP: <span className="text-cyan-300">{selectedAlert.sourceIp}</span> (Port {selectedAlert.sourcePort ?? 0})</div>
                <div>Destination IP: <span className="text-cyan-300">{selectedAlert.destinationIp}</span> (Port {selectedAlert.destinationPort ?? 0})</div>
              </div>
            </div>

            <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
              <span className="text-slate-400 font-mono block mb-1">{t('threats.explainabilityTitle')}</span>
              <p className="text-slate-200 leading-relaxed">{selectedAlert.description}</p>
            </div>

            {selectedAlert.signatureRule && (
              <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
                <span className="text-slate-400 font-mono block mb-1">{t('traffic.matchedRule')}</span>
                <code className="text-xs text-amber-300 font-mono block bg-black/40 p-2 rounded">
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
