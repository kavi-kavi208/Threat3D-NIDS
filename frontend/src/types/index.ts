// TypeScript Types for Threat3D NIDS Frontend

export interface ApiResponse<T> {
  success: boolean;
  message?: string;
  data: T;
  timestamp: string;
  error?: string;
}

export type UserRole = 'ROLE_ADMIN' | 'ROLE_ANALYST' | 'ROLE_STUDENT' | 'ADMIN' | 'ANALYST' | 'STUDENT';

export interface AuthResponse {
  token: string;
  type: string;
  username: string;
  fullName: string;
  role: string;
  expiresInMs: number;
}

export interface UserProfileResponse {
  id: number;
  username: string;
  fullName: string;
  email: string;
  role: string;
  enabled: boolean;
  createdAt: string;
}

export type NodeStatus = 'HEALTHY' | 'SUSPICIOUS' | 'COMPROMISED' | 'ISOLATED';
export type NodeType = 'FIREWALL' | 'ROUTER' | 'WEB_SERVER' | 'DB_SERVER' | 'AUTH_SERVER' | 'WORKSTATION' | 'ATTACKER';

export interface NetworkNode {
  id: string;
  label: string;
  ipAddress: string;
  macAddress?: string;
  nodeType: NodeType | string;
  subnet?: string;
  posX: number;
  posY: number;
  posZ: number;
  status: NodeStatus | string;
  openPorts?: string;
  lastSeen: string;
}

export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type MitigationStatus = 'ACTIVE' | 'MITIGATED' | 'BLOCKED' | 'IGNORED';

export interface ThreatAlertResponse {
  id: number;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  attackType: string;
  severity: SeverityLevel | string;
  threatScore: number;
  description: string;
  signatureRule?: string;
  mitigationStatus: MitigationStatus | string;
  mitreTechniqueId?: string;
  mitreTechniqueName?: string;
  isAnomalous?: boolean;
}

export interface ThreatSummaryResponse {
  totalAlerts: number;
  activeAlerts: number;
  mitigatedAlerts: number;
  severityCounts: Record<string, number>;
  attackTypeCounts: Record<string, number>;
}

export interface NetworkFlow {
  id: number;
  flowKey?: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  packetCount: number;
  byteCount: number;
  durationMs: number;
  synCount: number;
  ackCount: number;
  finCount: number;
  rstCount: number;
  flowStart: string;
  flowEnd?: string;
}

export interface TrafficStats {
  totalRecordsProcessed: number;
  totalEventsGenerated: number;
  totalAlertsPersistedDb: number;
  totalPipelineErrors: number;
  activeFlowCount: number;
  anomalyBaselineReady: boolean;
  anomalySampleCount: number;
  safetyDisclaimer: string;
}

export interface TrafficRecordRequest {
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  packetSize?: number;
  tcpFlags?: string;
  payloadLength?: number;
  direction?: string;
  applicationProtocol?: string;
  connectionStatus?: string;
  simulatedPayloadSnippet?: string;
}

export interface DetectionEventResponse {
  eventId: string;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  threatType: string;
  severity: SeverityLevel | string;
  threatScore: number;
  signatureMatched: boolean;
  matchedRuleId?: string;
  matchedRuleName?: string;
  anomalous: boolean;
  anomalyScore: number;
  anomalousFeatures: string[];
  mitreTechniqueId: string;
  mitreTechniqueName: string;
  recommendedAction: string;
  explanation: string;
}

export interface CorrelationSummary {
  correlationId: string;
  sourceIp: string;
  stageCount: number;
  stages: string[];
  threatType: string;
  severity: string;
  escalatedScore: number;
  description: string;
  windowDurationSeconds: number;
}

export interface RecommendationSummary {
  recommendationId: string;
  action: string;
  targetIp: string;
  confidenceScore: number;
  mitreTechniqueId: string;
  suggestedRule: string;
  remediationSteps: string[];
  indicatorsOfCompromise: string[];
  safetyDisclaimer: string;
}

export interface PipelineResultResponse {
  detectionEvent: DetectionEventResponse;
  correlation?: CorrelationSummary;
  recommendation?: RecommendationSummary;
  persistedAsAlert: boolean;
  alertId?: number;
  errorMessage?: string;
}

export type ScenarioType =
  | 'NORMAL_TRAFFIC'
  | 'PORT_SCAN_PATTERN'
  | 'SYN_FLOOD_PATTERN'
  | 'ICMP_FLOOD_PATTERN'
  | 'BRUTE_FORCE_PATTERN'
  | 'WEB_ANOMALY_PATTERN'
  | 'MIXED_SUSPICIOUS_ACTIVITY';

export interface ScenarioInfo {
  type: ScenarioType;
  description: string;
}

export interface SimulationStartResult {
  accepted: boolean;
  message: string;
  scenarioType: ScenarioType;
  recordCount: number;
}

export interface SimulationProgressResponse {
  state: 'IDLE' | 'RUNNING' | 'COMPLETED' | 'STOPPED' | 'FAILED';
  currentState?: 'IDLE' | 'RUNNING' | 'COMPLETED' | 'STOPPED' | 'FAILED';
  scenarioType?: ScenarioType;
  recordsTotal: number;
  totalRequested?: number;
  recordsProcessed: number;
  eventsGenerated: number;
  highCriticalAlerts: number;
  highCriticalCount?: number;
  startTime?: string;
  startedAt?: string;
  completedAt?: string;
  durationMs: number;
  errorMessage?: string;
  completionPercent: number;
  percentComplete?: number;
}

export interface SimulationSummaryResponse {
  scenarioType: ScenarioType;
  requestedRecords?: number;
  totalRecordsProcessed: number;
  totalEventsGenerated: number;
  totalHighCriticalAlerts: number;
  durationMs: number;
  throughputRecordsPerSec: number;
  threatDistribution: Record<string, number>;
  correlationsDetected: number;
  safetyNotice: string;
}

export interface SnortRule {
  id: string | number;
  sid: number;
  name: string;
  protocol: string;
  sourceIp?: string;
  sourcePort: string;
  destIp?: string;
  destPort: string;
  payloadPattern?: string;
  action?: string;
  severity: string;
  attackCategory: string;
  enabled: boolean;
  description: string;
  mitreTechniqueId?: string;
}

export interface SignatureEngineStatus {
  activeRulesCount: number;
  totalRulesCount: number;
}

export interface AnomalyEngineStatus {
  detectorName: string;
  isMachineLearning: boolean;
  algorithm: string;
  featureDimensions: number;
  warmupSamplesThreshold: number;
  sampleCount: number;
  baselineReady: boolean;
}

export interface EngineStatusResponse {
  signatureEngine: SignatureEngineStatus;
  anomalyEngine: AnomalyEngineStatus;
  safetyDisclaimer: string;
}
