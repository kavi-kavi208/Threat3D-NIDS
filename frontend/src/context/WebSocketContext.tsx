// Threat3D NIDS Real-time WebSocket & STOMP Context
import React, { createContext, useContext, useEffect, useState, useRef, useCallback, type ReactNode } from 'react';
import { Client, type IMessage } from '@stomp/stompjs';
import SockJS from 'sockjs-client';
import type {
  DetectionEventResponse,
  ThreatAlertResponse,
  SimulationProgressResponse,
  SimulationSummaryResponse,
  NetworkNode,
} from '../types';

interface WebSocketContextType {
  isConnected: boolean;
  latestEvent: DetectionEventResponse | null;
  latestAlert: ThreatAlertResponse | null;
  latestProgress: SimulationProgressResponse | null;
  latestSummary: SimulationSummaryResponse | null;
  activeAttacks: Array<{
    sourceIp: string;
    destinationIp: string;
    threatType: string;
    severity: string;
    timestamp: number;
  }>;
  subscribeToAlerts: (callback: (alert: ThreatAlertResponse) => void) => () => void;
  subscribeToTelemetry: (callback: (event: DetectionEventResponse) => void) => () => void;
  subscribeToSimulation: (callback: (progress: SimulationProgressResponse) => void) => () => void;
  subscribeToNodes: (callback: (node: NetworkNode) => void) => () => void;
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined);

export const WebSocketProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [latestEvent, setLatestEvent] = useState<DetectionEventResponse | null>(null);
  const [latestAlert, setLatestAlert] = useState<ThreatAlertResponse | null>(null);
  const [latestProgress, setLatestProgress] = useState<SimulationProgressResponse | null>(null);
  const [latestSummary, setLatestSummary] = useState<SimulationSummaryResponse | null>(null);
  const [activeAttacks, setActiveAttacks] = useState<
    Array<{
      sourceIp: string;
      destinationIp: string;
      threatType: string;
      severity: string;
      timestamp: number;
    }>
  >([]);

  const clientRef = useRef<Client | null>(null);
  const alertListenersRef = useRef<Set<(alert: ThreatAlertResponse) => void>>(new Set());
  const telemetryListenersRef = useRef<Set<(event: DetectionEventResponse) => void>>(new Set());
  const simListenersRef = useRef<Set<(progress: SimulationProgressResponse) => void>>(new Set());
  const nodeListenersRef = useRef<Set<(node: NetworkNode) => void>>(new Set());

  useEffect(() => {
    // Connect to STOMP over SockJS at /ws
    const socketFactory = () => new SockJS('/ws');

    const client = new Client({
      webSocketFactory: socketFactory,
      reconnectDelay: 3000,
      heartbeatIncoming: 4000,
      heartbeatOutgoing: 4000,
      debug: () => {}, // Suppress console noise
      onConnect: () => {
        setIsConnected(true);

        // 1. Subscribe to /topic/telemetry
        client.subscribe('/topic/telemetry', (message: IMessage) => {
          try {
            const event: DetectionEventResponse = JSON.parse(message.body);
            setLatestEvent(event);
            telemetryListenersRef.current.forEach((fn) => fn(event));

            // Track active attack for 3D visual pulses
            if (event.severity === 'HIGH' || event.severity === 'CRITICAL' || event.anomalous) {
              setActiveAttacks((prev) => [
                {
                  sourceIp: event.sourceIp,
                  destinationIp: event.destinationIp,
                  threatType: event.threatType,
                  severity: event.severity,
                  timestamp: Date.now(),
                },
                ...prev.slice(0, 19), // keep last 20
              ]);
            }
          } catch {
            // Ignored
          }
        });

        // 2. Subscribe to /topic/alerts
        client.subscribe('/topic/alerts', (message: IMessage) => {
          try {
            const alert: ThreatAlertResponse = JSON.parse(message.body);
            setLatestAlert(alert);
            alertListenersRef.current.forEach((fn) => fn(alert));
          } catch {
            // Ignored
          }
        });

        // 3. Subscribe to /topic/simulation
        client.subscribe('/topic/simulation', (message: IMessage) => {
          try {
            const prog: SimulationProgressResponse = JSON.parse(message.body);
            setLatestProgress(prog);
            simListenersRef.current.forEach((fn) => fn(prog));
          } catch {
            // Ignored
          }
        });

        // 4. Subscribe to /topic/simulation/summary
        client.subscribe('/topic/simulation/summary', (message: IMessage) => {
          try {
            const sum: SimulationSummaryResponse = JSON.parse(message.body);
            setLatestSummary(sum);
          } catch {
            // Ignored
          }
        });

        // 5. Subscribe to /topic/nodes
        client.subscribe('/topic/nodes', (message: IMessage) => {
          try {
            const node: NetworkNode = JSON.parse(message.body);
            nodeListenersRef.current.forEach((fn) => fn(node));
          } catch {
            // Ignored
          }
        });
      },
      onDisconnect: () => {
        setIsConnected(false);
      },
      onStompError: () => {
        setIsConnected(false);
      },
    });

    client.activate();
    clientRef.current = client;

    // Prune expired active attacks older than 6 seconds
    const cleanupInterval = setInterval(() => {
      const now = Date.now();
      setActiveAttacks((prev) => prev.filter((a) => now - a.timestamp < 6000));
    }, 2000);

    return () => {
      clearInterval(cleanupInterval);
      if (clientRef.current) {
        clientRef.current.deactivate();
      }
    };
  }, []);

  const subscribeToAlerts = useCallback((callback: (alert: ThreatAlertResponse) => void) => {
    alertListenersRef.current.add(callback);
    return () => {
      alertListenersRef.current.delete(callback);
    };
  }, []);

  const subscribeToTelemetry = useCallback((callback: (event: DetectionEventResponse) => void) => {
    telemetryListenersRef.current.add(callback);
    return () => {
      telemetryListenersRef.current.delete(callback);
    };
  }, []);

  const subscribeToSimulation = useCallback((callback: (progress: SimulationProgressResponse) => void) => {
    simListenersRef.current.add(callback);
    return () => {
      simListenersRef.current.delete(callback);
    };
  }, []);

  const subscribeToNodes = useCallback((callback: (node: NetworkNode) => void) => {
    nodeListenersRef.current.add(callback);
    return () => {
      nodeListenersRef.current.delete(callback);
    };
  }, []);

  return (
    <WebSocketContext.Provider
      value={{
        isConnected,
        latestEvent,
        latestAlert,
        latestProgress,
        latestSummary,
        activeAttacks,
        subscribeToAlerts,
        subscribeToTelemetry,
        subscribeToSimulation,
        subscribeToNodes,
      }}
    >
      {children}
    </WebSocketContext.Provider>
  );
};

export const useWebSocket = (): WebSocketContextType => {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error('useWebSocket must be used within a WebSocketProvider');
  }
  return context;
};
