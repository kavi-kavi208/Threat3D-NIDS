import React, { useState, useEffect, useCallback, Suspense, lazy } from 'react';
import {
  RotateCw,
  Server,
  Shield,
  Radio,
  Layers,
  Search,
  Eye,
  Activity,
} from 'lucide-react';
import { telemetryApi } from '../services/api';
import type { NetworkNode, NodeStatus } from '../types';
import { useWebSocket } from '../context/WebSocketContext';
import { useLanguage } from '../context/LanguageContext';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { Button } from '../components/common/Button';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { EmptyState } from '../components/common/EmptyState';
import { Modal } from '../components/common/Modal';
const NetworkTopology3D = lazy(() =>
  import('../components/topology/NetworkTopology3D').then((m) => ({ default: m.NetworkTopology3D }))
);

export const TopologyPage: React.FC = () => {
  const { subscribeToNodes } = useWebSocket();
  const { t } = useLanguage();
  const [nodes, setNodes] = useState<NetworkNode[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(null);

  const loadNodes = useCallback(async () => {
    setError(null);
    try {
      const data = await telemetryApi.getNodes();
      setNodes(data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to fetch network topology nodes';
      setError(msg);
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadNodes();

    // Subscribe to live node status transitions over WebSocket
    const unsubscribe = subscribeToNodes((updatedNode) => {
      setNodes((prev) =>
        prev.map((n) => (n.id === updatedNode.id ? updatedNode : n))
      );
    });

    return () => unsubscribe();
  }, [loadNodes, subscribeToNodes]);

  const handleRefresh = () => {
    setIsRefreshing(true);
    loadNodes();
  };

  const getStatusBadgeVariant = (status: string) => {
    switch (status) {
      case 'HEALTHY':
        return 'healthy';
      case 'SUSPICIOUS':
        return 'suspicious';
      case 'COMPROMISED':
        return 'compromised';
      case 'ISOLATED':
        return 'isolated';
      default:
        return 'neutral';
    }
  };

  const getNodeTypeIcon = (type: string) => {
    switch (type) {
      case 'FIREWALL':
        return <Shield size={16} className="text-red-400" />;
      case 'ROUTER':
        return <Radio size={16} className="text-cyan-400" />;
      case 'WEB_SERVER':
        return <Server size={16} className="text-blue-400" />;
      case 'DB_SERVER':
        return <Layers size={16} className="text-purple-400" />;
      default:
        return <Activity size={16} className="text-slate-400" />;
    }
  };

  const filteredNodes = nodes.filter((node) => {
    const matchesSearch =
      (node.label ?? '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (node.ipAddress ?? '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (node.nodeType ?? '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (node.subnet && node.subnet.toLowerCase().includes(searchQuery.toLowerCase()));

    const matchesStatus = statusFilter === 'ALL' || node.status === statusFilter;

    return matchesSearch && matchesStatus;
  });

  const statusSummary = {
    HEALTHY: nodes.filter((n) => n.status === 'HEALTHY').length,
    SUSPICIOUS: nodes.filter((n) => n.status === 'SUSPICIOUS').length,
    COMPROMISED: nodes.filter((n) => n.status === 'COMPROMISED').length,
    ISOLATED: nodes.filter((n) => n.status === 'ISOLATED').length,
  };

  if (isLoading) {
    return <LoadingSpinner message={t('topology.loadingData')} />;
  }

  return (
    <div className="cyber-page-content">
      {/* Page Header */}
      <div className="cyber-page-header">
        <div>
          <h1 className="cyber-page-title">{t('topology.title')}</h1>
          <p className="cyber-page-desc">
            {t('topology.desc')}
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
            {isRefreshing ? t('common.refreshing') : t('topology.refreshNodes')}
          </Button>
        </div>
      </div>

      {error && (
        <div className="cyber-auth-error mb-6">
          <span>{error}</span>
        </div>
      )}

      {/* 3D Canvas Main Viewport */}
      <div className="mb-6">
        <Suspense fallback={<LoadingSpinner message={t('topology.loadingData')} />}>
          <NetworkTopology3D
            nodes={nodes}
            onSelectNode={(node) => setSelectedNode(node)}
            selectedNodeId={selectedNode?.id}
            height={480}
          />
        </Suspense>
      </div>


      {/* Node Search and Filter Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 mb-4">
        <div className="cyber-search-wrapper w-full sm:w-80">
          <Search size={16} className="cyber-search-icon" />
          <input
            type="text"
            className="cyber-input cyber-search-input"
            placeholder={t('topology.searchPlaceholder')}
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <div className="flex items-center gap-2 overflow-x-auto w-full sm:w-auto">
          {(['ALL', 'HEALTHY', 'SUSPICIOUS', 'COMPROMISED', 'ISOLATED'] as const).map((st) => {
            const label = st === 'ALL' ? t('common.all') :
              st === 'HEALTHY' ? t('common.healthy') :
              st === 'SUSPICIOUS' ? t('common.suspicious') :
              st === 'COMPROMISED' ? t('common.compromised') : t('common.isolated');
            return (
              <button
                key={st}
                type="button"
                className={`cyber-filter-pill ${statusFilter === st ? 'cyber-filter-pill--active' : ''}`}
                onClick={() => setStatusFilter(st)}
              >
                {label} {st !== 'ALL' && `(${statusSummary[st as NodeStatus] || 0})`}
              </button>
            );
          })}
        </div>
      </div>

      {/* Nodes Table */}
      <Card title={t('topology.tableTitle')} subtitle={t('topology.tableSub')}>
        {filteredNodes.length === 0 ? (
          <EmptyState
            title={t('topology.noNodesFound')}
            description=""
          />
        ) : (
          <div className="cyber-table-container">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>{t('topology.colNode')}</th>
                  <th>{t('topology.colIp')}</th>
                  <th>{t('topology.colSubnet')}</th>
                  <th>{t('topology.colCoords')}</th>
                  <th>Open Ports</th>
                  <th>{t('topology.colStatus')}</th>
                  <th>{t('topology.colAction')}</th>
                </tr>
              </thead>
              <tbody>
                {filteredNodes.map((node) => (
                  <tr key={node.id} className="cyber-table-row">
                    <td>
                      <div className="flex items-center gap-2">
                        {getNodeTypeIcon(node.nodeType)}
                        <div>
                          <span className="font-semibold text-xs text-slate-200 block">
                            {node.label}
                          </span>
                          <span className="text-[10px] text-slate-400 font-mono">
                            {node.nodeType} ({node.id})
                          </span>
                        </div>
                      </div>
                    </td>
                    <td className="font-mono text-xs text-cyan-300">
                      {node.ipAddress}
                    </td>
                    <td className="font-mono text-xs text-slate-400">
                      {node.subnet || 'N/A'}
                    </td>
                    <td className="font-mono text-xs text-slate-300">
                      [{(node.posX ?? 0).toFixed(1)}, {(node.posY ?? 0).toFixed(1)}, {(node.posZ ?? 0).toFixed(1)}]
                    </td>
                    <td className="font-mono text-xs text-slate-400">
                      {node.openPorts || 'None'}
                    </td>
                    <td>
                      <Badge variant={getStatusBadgeVariant(node.status)} size="sm" dot>
                        {node.status}
                      </Badge>
                    </td>
                    <td>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setSelectedNode(node)}
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

      {/* Node Inspector Modal */}
      <Modal
        isOpen={!!selectedNode}
        onClose={() => setSelectedNode(null)}
        title={
          selectedNode && (
            <div className="flex items-center gap-2">
              {getNodeTypeIcon(selectedNode.nodeType)}
              <span>{t('topology.inspectorTitle')} &mdash; {selectedNode.label}</span>
            </div>
          )
        }
        footer={
          <Button variant="primary" size="sm" onClick={() => setSelectedNode(null)}>
            {t('common.close')}
          </Button>
        }
      >
        {selectedNode && (
          <div className="flex flex-col gap-4 text-xs">
            <div className="grid grid-cols-2 gap-3 p-3 bg-slate-900/60 rounded border border-slate-800">
              <div>
                <span className="text-slate-400 font-mono block">{t('topology.colNode')}</span>
                <span className="text-slate-200 font-semibold mt-1 block">
                  {selectedNode.label} ({selectedNode.id})
                </span>
              </div>
              <div>
                <span className="text-slate-400 font-mono block">{t('topology.colStatus')}</span>
                <Badge variant={getStatusBadgeVariant(selectedNode.status)} size="sm" dot className="mt-1">
                  {selectedNode.status}
                </Badge>
              </div>
              <div>
                <span className="text-slate-400 font-mono block">{t('topology.colIp')} &amp; MAC</span>
                <span className="text-cyan-300 font-mono mt-1 block">
                  {selectedNode.ipAddress} &bull; {selectedNode.macAddress || 'N/A'}
                </span>
              </div>
              <div>
                <span className="text-slate-400 font-mono block">{t('topology.colSubnet')} &amp; {t('topology.colType')}</span>
                <span className="text-slate-200 font-mono mt-1 block">
                  {selectedNode.subnet} ({selectedNode.nodeType})
                </span>
              </div>
            </div>

            <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
              <span className="text-slate-400 font-mono block mb-1">3D Topology Vector Space</span>
              <div className="grid grid-cols-3 gap-2 font-mono text-center">
                <div className="p-2 bg-black/40 rounded border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">POS X</span>
                  <span className="text-cyan-400 font-bold">{(selectedNode.posX ?? 0).toFixed(2)}</span>
                </div>
                <div className="p-2 bg-black/40 rounded border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">POS Y</span>
                  <span className="text-cyan-400 font-bold">{(selectedNode.posY ?? 0).toFixed(2)}</span>
                </div>
                <div className="p-2 bg-black/40 rounded border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">POS Z</span>
                  <span className="text-cyan-400 font-bold">{(selectedNode.posZ ?? 0).toFixed(2)}</span>
                </div>
              </div>
            </div>

            <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
              <span className="text-slate-400 font-mono block mb-1">Configured Services &amp; Ports</span>
              <span className="text-slate-200 font-mono">
                {selectedNode.openPorts ? `Ports: ${selectedNode.openPorts}` : 'No open services exposed'}
              </span>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};
