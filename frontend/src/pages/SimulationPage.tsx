import React, { useState, useEffect, useCallback } from 'react';
import {
  Play,
  Square,
  RotateCcw,
  CheckCircle2,
  Sliders,
  AlertTriangle,
} from 'lucide-react';
import { simulationApi } from '../services/api';
import type {
  ScenarioInfo,
  ScenarioType,
  SimulationProgressResponse,
  SimulationSummaryResponse,
} from '../types';
import { useAuth } from '../context/AuthContext';
import { useWebSocket } from '../context/WebSocketContext';
import { useLanguage } from '../context/LanguageContext';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { Button } from '../components/common/Button';
import { LoadingSpinner } from '../components/common/LoadingSpinner';

export const SimulationPage: React.FC = () => {
  const { hasRole } = useAuth();
  const { subscribeToSimulation, latestSummary } = useWebSocket();
  const { t } = useLanguage();

  const isAdmin = hasRole('ADMIN');
  const isAnalyst = hasRole('ANALYST');
  const canControl = isAdmin || isAnalyst;
  const canReset = isAdmin || isAnalyst;

  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<ScenarioType>('SYN_FLOOD_PATTERN');
  const [recordCount, setRecordCount] = useState<number>(50);

  const [progress, setProgress] = useState<SimulationProgressResponse | null>(null);
  const [summary, setSummary] = useState<SimulationSummaryResponse | null>(null);

  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isStarting, setIsStarting] = useState<boolean>(false);
  const [isStopping, setIsStopping] = useState<boolean>(false);
  const [isResetting, setIsResetting] = useState<boolean>(false);
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const loadInitialData = useCallback(async () => {
    try {
      const [scenariosRes, statusRes, summaryRes] = await Promise.all([
        simulationApi.getScenarios().catch(() => ({ data: [] })),
        simulationApi.getStatus().catch(() => null),
        simulationApi.getSummary().catch(() => null),
      ]);

      if (scenariosRes.data) {
        setScenarios(scenariosRes.data);
        if (scenariosRes.data.length > 0 && !selectedScenario) {
          setSelectedScenario(scenariosRes.data[0].type);
        }
      }
      if (statusRes?.data) setProgress(statusRes.data);
      if (summaryRes?.data) setSummary(summaryRes.data);
    } catch {
      // Handled
    } finally {
      setIsLoading(false);
    }
  }, [selectedScenario]);

  useEffect(() => {
    loadInitialData();

    // Live WebSocket Subscription for instant progress updates
    const unsubSim = subscribeToSimulation((liveProgress) => {
      setProgress(liveProgress);
      const st = liveProgress.state || liveProgress.currentState;
      if (st === 'COMPLETED' || st === 'STOPPED') {
        simulationApi.getSummary().then((res) => {
          if (res.data) setSummary(res.data);
        });
      }
    });

    return () => unsubSim();
  }, [loadInitialData, subscribeToSimulation]);

  const progressState = progress?.state || progress?.currentState || 'IDLE';
  const isRunning = progressState === 'RUNNING';

  // Resilient polling fallback while simulation is active
  useEffect(() => {
    let pollInterval: ReturnType<typeof setInterval> | null = null;
    if (isRunning) {
      pollInterval = setInterval(async () => {
        try {
          const statusRes = await simulationApi.getStatus();
          if (statusRes?.data) {
            setProgress(statusRes.data);
            const st = statusRes.data.state || statusRes.data.currentState;
            if (st === 'COMPLETED' || st === 'STOPPED' || st === 'FAILED') {
              const summaryRes = await simulationApi.getSummary();
              if (summaryRes?.data) setSummary(summaryRes.data);
            }
          }
        } catch {
          // ignore transient poll error
        }
      }, 400);
    }
    return () => {
      if (pollInterval) clearInterval(pollInterval);
    };
  }, [isRunning]);

  useEffect(() => {
    if (latestSummary) {
      setSummary(latestSummary);
    }
  }, [latestSummary]);

  useEffect(() => {
    if (progressState === 'COMPLETED' || progressState === 'STOPPED') {
      simulationApi.getSummary().then((res) => {
        if (res.data) setSummary(res.data);
      }).catch(() => {});
    }
  }, [progressState]);

  const handleStart = async () => {
    setIsStarting(true);
    setNotification(null);
    try {
      const res = await simulationApi.start(selectedScenario, recordCount);
      setNotification({
        type: 'success',
        message: res.message || `Started ${selectedScenario} with ${recordCount} packets.`,
      });
      // Immediately refresh status
      const statusRes = await simulationApi.getStatus();
      if (statusRes.data) {
        setProgress(statusRes.data);
        const st = statusRes.data.state || statusRes.data.currentState;
        if (st === 'COMPLETED' || st === 'STOPPED' || st === 'FAILED') {
          const summaryRes = await simulationApi.getSummary();
          if (summaryRes?.data) setSummary(summaryRes.data);
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Simulation failed to start';
      setNotification({ type: 'error', message: msg });
    } finally {
      setIsStarting(false);
    }
  };

  const handleStop = async () => {
    setIsStopping(true);
    try {
      await simulationApi.stop();
      setNotification({ type: 'success', message: 'Simulation stop signal sent.' });
      const statusRes = await simulationApi.getStatus();
      if (statusRes.data) {
        setProgress(statusRes.data);
        const summaryRes = await simulationApi.getSummary();
        if (summaryRes?.data) setSummary(summaryRes.data);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to stop simulation';
      setNotification({ type: 'error', message: msg });
    } finally {
      setIsStopping(false);
    }
  };

  const handleReset = async () => {
    setIsResetting(true);
    setNotification(null);
    try {
      await simulationApi.reset();
      setNotification({
        type: 'success',
        message: 'Simulation orchestrator, flow tracker, and correlation buffer reset to IDLE.',
      });
      const [statusRes, summaryRes] = await Promise.all([
        simulationApi.getStatus(),
        simulationApi.getSummary(),
      ]);
      if (statusRes.data) setProgress(statusRes.data);
      if (summaryRes.data) setSummary(summaryRes.data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Reset failed';
      setNotification({ type: 'error', message: msg });
    } finally {
      setIsResetting(false);
    }
  };

  if (isLoading) {
    return <LoadingSpinner message={t('simulation.loading')} />;
  }

  const recordsTotal = progress?.recordsTotal || progress?.totalRequested || summary?.requestedRecords || recordCount || 0;
  const recordsProcessed = progress?.recordsProcessed ?? progress?.eventsGenerated ?? summary?.totalRecordsProcessed ?? 0;
  const completionPercent = progress?.completionPercent ?? progress?.percentComplete ?? (recordsTotal > 0 ? Math.min(100, Math.round((recordsProcessed * 100) / recordsTotal)) : 0);
  const highCriticalAlerts = progress?.highCriticalAlerts ?? progress?.highCriticalCount ?? summary?.totalHighCriticalAlerts ?? 0;
  const displayDurationMs = (() => {
    if (summary?.durationMs && summary.durationMs > 0) {
      return summary.durationMs;
    }
    if (progress?.durationMs && progress.durationMs > 0) {
      return progress.durationMs;
    }
    const startStr = progress?.startedAt || progress?.startTime;
    if (startStr) {
      const startMs = new Date(startStr).getTime();
      const endStr = progress?.completedAt;
      const endMs = endStr ? new Date(endStr).getTime() : 0;
      if (startMs > 0 && endMs > startMs) {
        return endMs - startMs;
      }
    }
    return 0;
  })();

  const displayThroughput = (() => {
    if (
      summary?.throughputRecordsPerSec &&
      summary.throughputRecordsPerSec > 0
    ) {
      return summary.throughputRecordsPerSec;
    }

    if (displayDurationMs > 0 && recordsProcessed > 0) {
      return (recordsProcessed * 1000.0) / displayDurationMs;
    }

    return 0;
  })();

  return (
    <div className="cyber-page-content">
      {/* Page Header */}
      <div className="cyber-page-header">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h1 className="cyber-page-title mb-0">{t('simulation.title')}</h1>
            <Badge variant={isAdmin ? 'admin' : isAnalyst ? 'analyst' : 'student'} size="sm">
              {isAdmin ? 'ADMIN ORCHESTRATION' : isAnalyst ? 'ANALYST EVALUATION' : 'STUDENT READ-ONLY'}
            </Badge>
          </div>
          <p className="cyber-page-desc">
            {t('simulation.desc')}
          </p>
        </div>
        <div className="cyber-page-header-actions">
          {canReset && (
            <Button
              variant="outline"
              size="sm"
              onClick={handleReset}
              isLoading={isResetting}
              disabled={isRunning}
              leftIcon={<RotateCcw size={14} />}
            >
              {isResetting ? t('simulation.resetting') : t('simulation.btnReset')}
            </Button>
          )}
        </div>
      </div>

      {notification && (
        <div
          className={`p-3 mb-4 rounded text-xs flex items-center gap-2 border ${
            notification.type === 'success'
              ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300'
              : 'bg-red-950/40 border-red-800/60 text-red-300'
          }`}
        >
          {notification.type === 'success' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
          <span>{notification.message}</span>
        </div>
      )}

      {/* Simulation Live Status Banner */}
      <Card
        className="mb-6"
        title={t('simulation.liveProgressTitle')}
        badge={
          <Badge
            variant={
              progressState === 'RUNNING'
                ? 'critical'
                : progressState === 'COMPLETED'
                ? 'low'
                : 'neutral'
            }
            size="sm"
            dot
          >
            {progressState}
          </Badge>
        }
      >
        <div className="flex flex-col gap-4">
          {/* Progress Bar */}
          <div>
            <div className="flex items-center justify-between text-xs font-mono text-slate-300 mb-1">
              <span>
                {t('simulation.activeScenario')}{' '}
                <strong className="text-cyan-400 font-sans">
                  {progress?.scenarioType || selectedScenario}
                </strong>
              </span>
              <span>
                {recordsProcessed} / {recordsTotal} Packets ({completionPercent}%)
              </span>
            </div>
            <div className="cyber-progress-track">
              <div
                className={`cyber-progress-fill ${isRunning ? 'animate-pulse' : ''}`}
                style={{ width: `${completionPercent}%` }}
              />
            </div>
          </div>

          {/* Quick Metrics */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
            <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800">
              <span className="text-[10px] text-slate-400 font-mono block">{t('simulation.packetsProcessed')}</span>
              <span className="text-sm font-bold text-slate-200 font-mono">
                {recordsProcessed}
              </span>
            </div>
            <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800">
              <span className="text-[10px] text-slate-400 font-mono block">{t('simulation.alertsGenerated')}</span>
              <span className="text-sm font-bold text-red-400 font-mono">
                {highCriticalAlerts}
              </span>
            </div>
            <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800">
              <span className="text-[10px] text-slate-400 font-mono block">{t('simulation.duration')}</span>
              <span className="text-sm font-bold text-cyan-400 font-mono">
                {displayDurationMs} ms
              </span>
            </div>
            <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800">
              <span className="text-[10px] text-slate-400 font-mono block">Safety Scope</span>
              <span className="text-[11px] font-semibold text-emerald-400 block truncate">
                In-Memory Safe
              </span>
            </div>
          </div>

          {/* Control Buttons */}
          <div className="flex items-center gap-3 pt-2">
            {canControl ? (
              !isRunning ? (
                <Button
                  variant="primary"
                  size="md"
                  onClick={handleStart}
                  isLoading={isStarting}
                  leftIcon={<Play size={16} />}
                >
                  {isStarting ? t('simulation.starting') : t('simulation.btnStart')}
                </Button>
              ) : (
                <Button
                  variant="danger"
                  size="md"
                  onClick={handleStop}
                  isLoading={isStopping}
                  leftIcon={<Square size={16} />}
                >
                  {isStopping ? t('simulation.stopping') : t('simulation.btnStop')}
                </Button>
              )
            ) : (
              <span className="text-xs text-amber-400 font-mono px-3 py-1.5 bg-amber-950/30 rounded border border-amber-800/40">
                Simulation Triggers Restricted to Analyst &amp; Admin Clearance
              </span>
            )}
          </div>
        </div>
      </Card>

      {/* Scenario Selection Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        <Card
          className="lg:col-span-2"
          title={t('simulation.scenarioCardTitle')}
          subtitle={t('simulation.scenarioCardSub')}
        >
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {scenarios.map((sc) => {
              const isSelected = selectedScenario === sc.type;
              return (
                <div
                  key={sc.type}
                  className={`cyber-scenario-card ${isSelected ? 'cyber-scenario-card--selected' : ''}`}
                  onClick={() => !isRunning && setSelectedScenario(sc.type)}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-semibold text-xs text-slate-200">
                      {sc.type.replace(/_/g, ' ')}
                    </span>
                    {sc.type === 'NORMAL_TRAFFIC' ? (
                      <Badge variant="low" size="sm">Baseline</Badge>
                    ) : sc.type === 'MIXED_SUSPICIOUS_ACTIVITY' ? (
                      <Badge variant="critical" size="sm">Multi-Stage</Badge>
                    ) : (
                      <Badge variant="high" size="sm">Threat</Badge>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    {sc.description}
                  </p>
                </div>
              );
            })}
          </div>
        </Card>

        {/* Configuration Parameters */}
        <Card
          title="Simulation Parameters"
          subtitle="Tune packet volume and rate"
          badge={<Sliders size={14} className="text-cyan-400" />}
        >
          <div className="flex flex-col gap-4">
            <div>
              <div className="flex items-center justify-between text-xs text-slate-300 mb-2">
                <span>{t('simulation.recordCount', { count: recordCount })}</span>
              </div>
              <input
                type="range"
                min="10"
                max="500"
                step="10"
                disabled={isRunning}
                className="cyber-range w-full"
                value={recordCount}
                onChange={(e) => setRecordCount(Number(e.target.value))}
              />
              <div className="flex justify-between text-[10px] text-slate-500 font-mono mt-1">
                <span>10 (Quick)</span>
                <span>250 (Standard)</span>
                <span>500 (Stress Max)</span>
              </div>
            </div>

            <div className="p-3 bg-slate-900/60 rounded border border-slate-800 text-xs text-slate-400 leading-relaxed">
              <span className="font-semibold text-slate-200 block mb-1">Defense Pipeline Guarantee:</span>
              Packets flow through 5-tuple flow tracking, 41-feature extraction, Snort signature checking, and Welford Z-score anomaly scoring.
            </div>
          </div>
        </Card>
      </div>

      {/* Completed Run Summary */}
      {summary && (
        <Card
          title={t('simulation.summaryTitle')}
          subtitle={t('simulation.summarySub')}
          badge={<Badge variant="low" size="sm">Completed</Badge>}
        >
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-4">
            <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
              <span className="text-slate-400 text-[10px] font-mono block">{t('simulation.packetsProcessed')}</span>
              <span className="text-lg font-bold text-slate-200 font-mono">
                {summary.totalRecordsProcessed}
              </span>
            </div>
            <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
              <span className="text-slate-400 text-[10px] font-mono block">Throughput Rate</span>
              <span className="text-lg font-bold text-cyan-400 font-mono">
                {displayThroughput.toFixed(1)} /s
              </span>
            </div>
            <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
              <span className="text-slate-400 text-[10px] font-mono block">{t('simulation.alertsGenerated')}</span>
              <span className="text-lg font-bold text-red-400 font-mono">
                {summary.totalHighCriticalAlerts}
              </span>
            </div>
            <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
              <span className="text-slate-400 text-[10px] font-mono block">{t('simulation.correlationsDetected')}</span>
              <span className="text-lg font-bold text-purple-400 font-mono">
                {summary.correlationsDetected}
              </span>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
};
