"use client";

import { useEffect, useRef, useState } from "react";
import { connectLokiSigner, LokiSignerStartupTimeout, pairDevice, type ConnectProgress, type Slot } from "../lib/api.ts";

const button = "btn-glass w-full min-w-0 rounded-full px-5 py-3.5 font-medium transition disabled:opacity-60";

export function NativeTabConnection({ member, slot, disabled, onBusy, onConnected }: {
  member?: Slot;
  slot?: number; // May be a slot just reserved with the pairing link, not yet on the roster.
  disabled: boolean;
  onBusy: (busy: boolean) => void;
  onConnected: () => void;
}) {
  // Existing members select their flow from the signed registration field, not tab state.
  const lokiSigner = slot !== undefined && (!member || member.lokisigner_url !== undefined);
  const [link, setLink] = useState("");
  const [progress, setProgress] = useState<ConnectProgress>();
  const [error, setError] = useState<Error>();
  const request = useRef<AbortController | null>(null);
  useEffect(() => () => request.current?.abort(), []);

  const connect = async () => {
    if (request.current) return;
    setError(undefined);
    onBusy(true);
    const attempt = new AbortController();
    request.current = attempt;
    try {
      if (lokiSigner) await connectLokiSigner(slot, setProgress, attempt.signal);
      else await pairDevice(link, slot ?? member?.slot, attempt.signal);
      if (!attempt.signal.aborted) onConnected();
    } catch (e) { if (!attempt.signal.aborted) setError(e as Error); }
    finally { request.current = null; setProgress(undefined); onBusy(false); }
  };
  const cancel = <button type="button" className="min-h-11 text-mint" onClick={() => request.current?.abort()}>Cancel connection</button>;

  if (!lokiSigner) return <>
    <p className="my-2">Unlock your profile in the member app, then paste the local pairing link it prints or shows. Keep the link private.</p>
    <input type="password" value={link} autoComplete="off" spellCheck={false} aria-label="Local member pairing link"
      onChange={(e) => setLink(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && !disabled && link.trim()) void connect(); }}
      placeholder="http://127.0.0.1:3601/#…" className="glass mb-3 w-full rounded-full px-5 py-3" />
    {error && <p role="alert" className="mb-3 text-danger [overflow-wrap:anywhere]">{error.message}</p>}
    <button type="button" className={button} disabled={disabled || !link.trim()} onClick={connect}>{disabled ? "Connecting…" : "Pair this tab"}</button>
    {disabled && cancel}
  </>;

  return <>
    <p className="my-2">Open and unlock LokiSigner on this Mac. Connect each wallet tab you want to use.</p>
    {error && <p role="alert" className="my-2 text-danger [overflow-wrap:anywhere]">{error.message}</p>}
    <button type="button" className={button} disabled={disabled} onClick={connect}>
      {error instanceof LokiSignerStartupTimeout ? "Try again" : "Connect LokiSigner"}
    </button>
    {progress && <>
      <p role="status" className="my-2 text-sm text-[var(--ink)]">
        {progress.phase === "starting"
          ? "LokiSigner is still starting. This tab will retry for up to a minute. Allow local network access if your browser asks."
          : <>Compare this code with LokiSigner, then choose Allow there: <strong className="font-mono text-lg tracking-widest text-mint">{progress.code}</strong></>}
      </p>
      {cancel}
    </>}
  </>;
}
