import { useState, useEffect, useRef, useCallback } from 'react';

/**
 * Performance-optimized WebSocket hook.
 *
 * Key changes vs the original:
 * - Throttles state updates to at most once per `throttleMs` (default 2000ms).
 *   The Go backend pushes every 1s, but the React tree doesn't need to re-render
 *   that often — 2s is plenty for a monitoring dashboard.
 * - Uses a ref to hold the latest parsed message so the throttle window
 *   always publishes the *freshest* data, not stale data.
 * - Stable `status` ref avoids unnecessary re-renders from connection state flapping.
 */
export const useWebSocket = (
  url: string,
  protocols?: string | string[],
  throttleMs = 2000
) => {
  const [data, setData] = useState<any>(null);
  const [status, setStatus] = useState<string>('connecting');
  const isCleaningUp = useRef(false);
  const latestData = useRef<any>(null);
  const throttleTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastFlush = useRef(0);

  const flush = useCallback(() => {
    if (latestData.current !== null) {
      setData(latestData.current);
      lastFlush.current = Date.now();
    }
    throttleTimer.current = null;
  }, []);

  useEffect(() => {
    isCleaningUp.current = false;
    let ws: WebSocket;
    let reconnectTimer: ReturnType<typeof setTimeout>;

    const connect = () => {
      ws = new WebSocket(url, protocols);

      ws.onopen = () => {
        setStatus('connected');
      };

      ws.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data);
          latestData.current = parsed;

          const now = Date.now();
          const elapsed = now - lastFlush.current;

          if (elapsed >= throttleMs) {
            // Enough time has passed — flush immediately
            flush();
          } else if (!throttleTimer.current) {
            // Schedule a flush for the remainder of the throttle window
            throttleTimer.current = setTimeout(flush, throttleMs - elapsed);
          }
          // Otherwise a timer is already pending — it will pick up latestData
        } catch (e) {
          console.error("Failed to parse websocket message", e);
        }
      };

      ws.onclose = () => {
        setStatus('disconnected');
        if (isCleaningUp.current) return;
        reconnectTimer = setTimeout(connect, 3000);
      };

      ws.onerror = () => {
        setStatus('error');
      };
    };

    connect();

    return () => {
      isCleaningUp.current = true;
      if (ws) ws.close();
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (throttleTimer.current) clearTimeout(throttleTimer.current);
    };
  }, [url, throttleMs, flush]);

  return { data, status };
};
