"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";
import type { CeremonyStatus, ChainProvenance, Payment, StatusResponse } from "./types";

/** Poll every 1.5s while `active` is true. Returns latest value + manual refresh. */
function usePoll<T>(
  fetcher: () => Promise<T>,
  active: boolean,
  initial?: T,
): { data: T | undefined; error: string | null; refresh: () => void } {
  const [data, setData] = useState<T | undefined>(initial);
  const [error, setError] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const fetcherRef = useRef(fetcher);
  const requested = useRef(0);
  const applied = useRef(0);
  fetcherRef.current = fetcher;

  const run = useCallback(async () => {
    const request = ++requested.current;
    try {
      const d = await fetcherRef.current();
      if (request < applied.current) return;
      applied.current = request;
      setData(d);
      setError(null);
    } catch (e) {
      if (request < applied.current) return;
      applied.current = request;
      setError((e as Error).message);
    }
  }, []);

  useEffect(() => {
    if (!active) return;
    let cancelled = false;
    run();
    const tick = () => {
      run().finally(() => {
        if (!cancelled) timerRef.current = setTimeout(tick, 1500);
      });
    };
    timerRef.current = setTimeout(tick, 1500);
    return () => {
      cancelled = true;
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [active, run]);

  return { data, error, refresh: run };
}

export function useStatus(active: boolean) {
  return usePoll<StatusResponse>(() => api<StatusResponse>("status"), active);
}

export function useCeremonyStatus(vault: string, active: boolean) {
  return usePoll<CeremonyStatus>(
    () => api<CeremonyStatus>(`status?vault=${encodeURIComponent(vault)}`),
    active,
  );
}

export function usePayments(vault: string, active: boolean) {
  return usePoll<ChainProvenance & { payments: Payment[] }>(
    () => api(`payments?vault=${encodeURIComponent(vault)}`),
    active,
  );
}
