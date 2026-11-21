import { useState, useEffect, useRef, useCallback } from 'react';

export interface UseWebSocketReturn {
  data: any;
  status: 'connected' | 'connecting' | 'reconnecting' | 'disconnected' | 'error';
  reconnect: () => void;
  lastUpdated: number;
}

/**
 * Resilient, performance-optimized WebSocket hook.
 * Handles auto-reconnection, protocol safety, and throttled state updates.
 */
export const useWebSocket = (
  url: string,
  protocols?: string | string[],
  throttleMs = 1000
): UseWebSocketReturn => {
  const [data, setData] = useState<any>(null);
  const [status, setStatus] = useState<UseWebSocketReturn['status']>('connecting');
  const [lastUpdated, setLastUpdated] = useState<number>(0);

  const isCleaningUp = useRef(false);
  const latestData = useRef<any>(null);
  const throttleTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastFlush = useRef(0);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectCount = useRef(0);

  const flush = useCallback(() => {
    if (latestData.current !== null) {
      setData(latestData.current);
      const now = Date.now();
      lastFlush.current = now;
      setLastUpdated(now);
    }
    throttleTimer.current = null;
  }, []);

  const connect = useCallback(() => {
    if (isCleaningUp.current) return;

    const previousSocket = wsRef.current;
    wsRef.current = null;
    if (previousSocket) {
      try {
        previousSocket.close();
      } catch (_) {}
    }

    if (reconnectTimer.current) {
      clearTimeout(reconnectTimer.current);
      reconnectTimer.current = null;
    }

    setStatus(reconnectCount.current > 0 ? 'reconnecting' : 'connecting');

    try {
      // Protocol safe creation
      const ws = protocols && (Array.isArray(protocols) ? protocols.length > 0 : Boolean(protocols))
        ? new WebSocket(url, protocols)
        : new WebSocket(url);

      wsRef.current = ws;

      ws.onopen = () => {
        if (isCleaningUp.current || wsRef.current !== ws) return;
        reconnectCount.current = 0;
        setStatus('connected');
      };

      ws.onmessage = (event) => {
        if (isCleaningUp.current || wsRef.current !== ws) return;
        try {
          const parsed = JSON.parse(event.data);
          latestData.current = parsed;

          const now = Date.now();
          const elapsed = now - lastFlush.current;

          if (elapsed >= throttleMs) {
            flush();
          } else if (!throttleTimer.current) {
            throttleTimer.current = setTimeout(flush, throttleMs - elapsed);
          }
        } catch (e) {
          console.error("Failed to parse websocket message", e);
        }
      };

      ws.onclose = () => {
        if (isCleaningUp.current || wsRef.current !== ws) return;
        wsRef.current = null;
        setStatus('disconnected');
        reconnectCount.current += 1;
        // Exponential backoff capped at 5 seconds
        const delay = Math.min(1000 * Math.pow(1.5, reconnectCount.current), 5000);
        reconnectTimer.current = setTimeout(connect, delay);
      };

      ws.onerror = () => {
        if (isCleaningUp.current || wsRef.current !== ws) return;
        setStatus('error');
        try {
          if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
            ws.close();
          }
        } catch (_) {}
      };
    } catch (err) {
      console.warn("WebSocket connection attempt failed:", err);
      setStatus('error');
      reconnectCount.current += 1;
      reconnectTimer.current = setTimeout(connect, 3000);
    }
  }, [url, protocols, throttleMs, flush]);

  useEffect(() => {
    isCleaningUp.current = false;
    connect();

    return () => {
      isCleaningUp.current = true;
      const socket = wsRef.current;
      wsRef.current = null;
      if (socket) {
        try { socket.close(); } catch (_) {}
      }
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current);
        reconnectTimer.current = null;
      }
      if (throttleTimer.current) {
        clearTimeout(throttleTimer.current);
        throttleTimer.current = null;
      }
    };
  }, [connect]);

  const manualReconnect = useCallback(() => {
    reconnectCount.current = 0;
    connect();
  }, [connect]);

  return { data, status, reconnect: manualReconnect, lastUpdated };
};
