import type { ChatResponse } from '../types/chatTypes';
import { getStoredToken } from './api';

/**
 * Calls the backend chat explanation endpoint.
 * On failure, falls back to the Java offline expert service at `/api/offline-expert`.
 */
export const fetchThreatExplanation = async (query: string, contextThreatId?: string): Promise<ChatResponse> => {
  const token = getStoredToken();
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  try {
    const resp = await fetch('/api/v2/chat/explain', {
      method: 'POST',
      headers,
      body: JSON.stringify({ query, threatId: contextThreatId }),
    });
    if (!resp.ok) {
      throw new Error(`Backend error: ${resp.status}`);
    }
    const data = await resp.json();
    return data as ChatResponse;
  } catch (e) {
    // Offline fallback – POST to Java service.
    const fallbackResp = await fetch('/api/offline-expert', {
      method: 'POST',
      headers,
      body: JSON.stringify({ query, threatId: contextThreatId }),
    });
    if (!fallbackResp.ok) {
      const err = await fallbackResp.text();
      throw new Error(err || 'Offline expert failed');
    }
    const fallback: ChatResponse = await fallbackResp.json();
    return fallback;
  }
};
