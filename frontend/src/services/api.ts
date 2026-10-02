// Threat3D NIDS API Client Service
// SIMULATION ONLY — NO REAL NETWORK CHANGES

import type {
  ApiResponse,
  AuthResponse,
  UserProfileResponse,
  NetworkNode,
  TrafficRecordRequest,
  PipelineResultResponse,
  NetworkFlow,
  TrafficStats,
  ThreatAlertResponse,
  ThreatSummaryResponse,
  CorrelationSummary,
  RecommendationSummary,
  SnortRule,
  EngineStatusResponse,
  ScenarioInfo,
  SimulationStartResult,
  SimulationProgressResponse,
  SimulationSummaryResponse,
  ScenarioType,
} from '../types';

const TOKEN_KEY = 'threat3d_token';
const USER_KEY = 'threat3d_user';

export const getStoredToken = (): string | null => {
  return localStorage.getItem(TOKEN_KEY);
};

export const setStoredToken = (token: string): void => {
  localStorage.setItem(TOKEN_KEY, token);
};

export const clearStoredAuth = (): void => {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
};

export const getStoredUser = (): AuthResponse | null => {
  const userStr = localStorage.getItem(USER_KEY);
  if (!userStr) return null;
  try {
    return JSON.parse(userStr);
  } catch {
    return null;
  }
};

export const setStoredUser = (user: AuthResponse): void => {
  localStorage.setItem(USER_KEY, JSON.stringify(user));
};

async function fetchWithAuth<T>(
  url: string,
  options: RequestInit = {}
): Promise<T> {
  const token = getStoredToken();
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    ...(options.headers || {}),
  };

  if (token) {
    (headers as Record<string, string>)['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    clearStoredAuth();
    // Only dispatch an auth-expired event if not currently on login page
    if (!window.location.pathname.includes('/login')) {
      window.dispatchEvent(new CustomEvent('threat3d:unauthorized'));
    }
  }

  const contentType = response.headers.get('content-type');
  const isJson = contentType && contentType.includes('application/json');
  const data = isJson ? await response.json() : await response.text();

  if (!response.ok) {
    const errorMsg =
      (typeof data === 'object' && data !== null && (data.error || data.message)) ||
      `Request failed with status ${response.status}`;
    throw new Error(errorMsg);
  }

  return data as T;
}

// ---------------- API MODULES ----------------

export const authApi = {
  async login(credentials: { username: string; password: string }): Promise<AuthResponse> {
    const data = await fetchWithAuth<AuthResponse>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });
    setStoredToken(data.token);
    setStoredUser(data);
    return data;
  },

  async register(registration: {
    username: string;
    password: string;
    fullName: string;
    email: string;
    role?: string;
  }): Promise<AuthResponse> {
    const data = await fetchWithAuth<AuthResponse>('/api/v1/auth/register', {
      method: 'POST',
      body: JSON.stringify(registration),
    });
    setStoredToken(data.token);
    setStoredUser(data);
    return data;
  },

  async getProfile(): Promise<UserProfileResponse> {
    return fetchWithAuth<UserProfileResponse>('/api/v1/auth/me');
  },

  logout(): void {
    clearStoredAuth();
  },
};

export const telemetryApi = {
  async getNodes(): Promise<NetworkNode[]> {
    return fetchWithAuth<NetworkNode[]>('/api/v1/telemetry/nodes');
  },
};

export const trafficApi = {
  async analyze(record: TrafficRecordRequest): Promise<ApiResponse<PipelineResultResponse>> {
    return fetchWithAuth<ApiResponse<PipelineResultResponse>>('/api/v2/traffic/analyze', {
      method: 'POST',
      body: JSON.stringify(record),
    });
  },

  async batch(records: TrafficRecordRequest[]): Promise<ApiResponse<PipelineResultResponse[]>> {
    return fetchWithAuth<ApiResponse<PipelineResultResponse[]>>('/api/v2/traffic/batch', {
      method: 'POST',
      body: JSON.stringify(records),
    });
  },

  async getRecentFlows(): Promise<ApiResponse<NetworkFlow[]>> {
    return fetchWithAuth<ApiResponse<NetworkFlow[]>>('/api/v2/traffic/recent');
  },

  async getStats(): Promise<ApiResponse<TrafficStats>> {
    return fetchWithAuth<ApiResponse<TrafficStats>>('/api/v2/traffic/stats');
  },
};

export const threatApi = {
  async getAlerts(severity?: string): Promise<ApiResponse<ThreatAlertResponse[]>> {
    const query = severity && severity !== 'ALL' ? `?severity=${encodeURIComponent(severity)}` : '';
    return fetchWithAuth<ApiResponse<ThreatAlertResponse[]>>(`/api/v2/threats${query}`);
  },

  async getAlertById(id: number): Promise<ApiResponse<ThreatAlertResponse>> {
    return fetchWithAuth<ApiResponse<ThreatAlertResponse>>(`/api/v2/threats/${id}`);
  },

  async getSummary(): Promise<ApiResponse<ThreatSummaryResponse>> {
    return fetchWithAuth<ApiResponse<ThreatSummaryResponse>>('/api/v2/threats/summary');
  },

  async updateMitigationStatus(
    id: number,
    status: string
  ): Promise<ApiResponse<ThreatAlertResponse>> {
    return fetchWithAuth<ApiResponse<ThreatAlertResponse>>(`/api/v2/threats/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    });
  },
};

export const detectionApi = {
  async getCorrelations(): Promise<ApiResponse<CorrelationSummary[]>> {
    return fetchWithAuth<ApiResponse<CorrelationSummary[]>>('/api/v2/detection/correlations');
  },

  async getCorrelationBuffer(): Promise<ApiResponse<Record<string, number>>> {
    return fetchWithAuth<ApiResponse<Record<string, number>>>('/api/v2/detection/correlations/buffer');
  },

  async getRecommendations(): Promise<ApiResponse<RecommendationSummary[]>> {
    return fetchWithAuth<ApiResponse<RecommendationSummary[]>>('/api/v2/detection/recommendations');
  },

  async getSnortRules(enabledOnly = false): Promise<ApiResponse<SnortRule[]>> {
    return fetchWithAuth<ApiResponse<SnortRule[]>>(`/api/v2/detection/rules?enabledOnly=${enabledOnly}`);
  },

  async getEngineStatus(): Promise<ApiResponse<EngineStatusResponse>> {
    return fetchWithAuth<ApiResponse<EngineStatusResponse>>('/api/v2/detection/engine/status');
  },
};

export const simulationApi = {
  async getScenarios(): Promise<ApiResponse<ScenarioInfo[]>> {
    return fetchWithAuth<ApiResponse<ScenarioInfo[]>>('/api/v2/simulation/scenarios');
  },

  async start(scenarioType: ScenarioType, recordCount = 50): Promise<ApiResponse<SimulationStartResult>> {
    return fetchWithAuth<ApiResponse<SimulationStartResult>>('/api/v2/simulation/start', {
      method: 'POST',
      body: JSON.stringify({ scenarioType, recordCount }),
    });
  },

  async stop(): Promise<ApiResponse<string>> {
    return fetchWithAuth<ApiResponse<string>>('/api/v2/simulation/stop', {
      method: 'POST',
    });
  },

  async reset(): Promise<ApiResponse<string>> {
    return fetchWithAuth<ApiResponse<string>>('/api/v2/simulation/reset', {
      method: 'POST',
    });
  },

  async getStatus(): Promise<ApiResponse<SimulationProgressResponse>> {
    return fetchWithAuth<ApiResponse<SimulationProgressResponse>>('/api/v2/simulation/status');
  },

  async getSummary(includeResults = false): Promise<ApiResponse<SimulationSummaryResponse>> {
    return fetchWithAuth<ApiResponse<SimulationSummaryResponse>>(
      `/api/v2/simulation/summary?includeResults=${includeResults}`
    );
  },
};
