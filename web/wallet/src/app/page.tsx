"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { LokiTunnel } from "@/components/LokiTunnel";
import { NativeTabConnection } from "@/components/NativeTabConnection";
import {
  api,
  ApiError,
  fund,
  createSigner,
  enroll,
  unlock,
  hasSigner,
  hasSignerHint,
  forgetSession,
  logout,
  listSlots,
  hasLokiSignerSession,
  lastLokiSignerSlot,
  requestPairingLink,
  PairingSlotTaken,
  pendingApprovals,
  exportRecoveryBackup,
  manageBrowserCustody,
  restoreSigner,
  setupBrowserRecovery,
  signerKind,
  recoveryBackup,
  recoveryStatus,
  type CustodyMethod,
  type PairingLink,
  type PendingApproval,
  type Slot,
  type RecoveryStatus,
} from "@/lib/api";
import { comparesInLokiSigner, emptyHistoryText, invitePreview, nativeRosterRefusal, pairingSecondsLeft, paymentLabel, rememberedVaultSlot, rememberVaultSlot, storageLabel } from "@/lib/wallet-ui";
import { toggleTheme, useIsDark } from "@/lib/theme";
import { useCeremonyStatus, usePayments, useStatus } from "@/lib/hooks";
import type {
  CeremonyStatus,
  ChainProvenance,
  InviteSlot,
  Payment,
  PaymentReview,
  PaymentSession,
  StatusResponse,
  VaultSummary,
} from "@/lib/types";

// ─── util ────────────────────────────────────────────────────────────────────

const zatToTaz = (zat: number | string) => {
  const n = Number(zat) / 1e8;
  return Number.isFinite(n) ? n.toLocaleString(undefined, { maximumFractionDigits: 8 }) : "—";
};

const short = (s: string, head = 8, tail = 6) =>
  s.length > head + tail + 1 ? `${s.slice(0, head)}…${s.slice(-tail)}` : s;

/** Pull the invite code out of a pasted link, or return the trimmed input as-is. */
function extractInvite(raw: string): string {
  const s = raw.trim();
  try {
    const url = new URL(s);
    return url.searchParams.has("invite") ? "" : new URLSearchParams(url.hash.slice(1)).get("invite") ?? s;
  } catch {
    return s;
  }
}

/** A shareable invite link for a join code — opens the app straight into Join. */
function inviteLink(code: string): string {
  return typeof window === "undefined" ? code : `${window.location.origin}/#invite=${encodeURIComponent(code)}`;
}

// ─── navigation state ────────────────────────────────────────────────────────

type View =
  | { id: "home" }
  | { id: "create-vault" }
  | { id: "join-vault"; invite?: string }
  | { id: "ceremony"; vault: string }
  | { id: "overview"; vault: VaultSummary }
  | { id: "send"; vault: VaultSummary }
  | { id: "review"; vault: VaultSummary; attempt: string; proposer?: number; proposedHere?: boolean }
  | { id: "history"; vault: VaultSummary };

// ─── root ─────────────────────────────────────────────────────────────────────

export default function App() {
  // null = still checking the device session; false = show login; true = signed in.
  const [authed, setAuthed] = useState<boolean | null>(null);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [view, setView] = useState<View>({ id: "home" });
  const [pendingInvite, setPendingInvite] = useState<string | null>(null);
  const { data: status, error: statusError, refresh: refreshStatus } = useStatus(authed === true);

  // Fragments stay out of the initial request. Keep the claim only in memory across sign-in.
  useEffect(() => {
    const url = new URL(window.location.href);
    const fragment = new URLSearchParams(url.hash.slice(1));
    const code = fragment.get("invite");
    if (code === null) return;
    fragment.delete("invite");
    url.hash = fragment.toString();
    window.history.replaceState(window.history.state, "", url);
    if (code) setPendingInvite(code);
  }, []);

  useEffect(() => {
    if (authed === true && pendingInvite) {
      setView({ id: "join-vault", invite: pendingInvite });
      setPendingInvite(null);
    }
  }, [authed, pendingInvite]);

  const checkSession = useCallback(async () => {
    setAuthed(null); setSessionError(null);
    // A reload keeps the slot but not the grant. Reconnect without waiting for the browser signer.
    if (lastLokiSignerSlot() !== undefined && signerKind() === "browser") {
      setAuthed(false);
      return;
    }
    const lokiSigner = hasLokiSignerSession();
    try {
      const s = await api<StatusResponse>("status");
      setAuthed(s.phase === "home");
    } catch (e) {
      if (lokiSigner && !hasLokiSignerSession()) setAuthed(false);
      else if (e instanceof ApiError && e.status === 401) setAuthed(false);
      else setSessionError((e as Error).message);
    }
  }, []);
  useEffect(() => { void checkSession(); }, [checkSession]);

  // Same desync can bite mid-use (the host restarts after sign-in): a later status comes back
  // "locked", or an action 401s with "profile is locked"/"not signed in". Bounce to Login
  // rather than surface a cryptic error — unlocking locally reconnects the device.
  useEffect(() => {
    const lockedPhase = status?.phase === "locked" || status?.phase === "new_profile";
    if (authed === true && lockedPhase) {
      setView({ id: "home" });
      setAuthed(false);
    }
  }, [authed, status]);

  // Any action (Join, Create, …) that hits a locked/expired host fires `loki:auth-lost` from
  // the api() helper — route straight to Login so the user never sees a dead "profile is
  // locked" on an action screen.
  useEffect(() => {
    const onAuthLost = () => {
      setView({ id: "home" });
      setAuthed(false);
    };
    window.addEventListener("loki:auth-lost", onAuthLost);
    return () => window.removeEventListener("loki:auth-lost", onAuthLost);
  }, []);

  const signOut = async () => {
    const locked = await logout();
    setSessionError(locked ? null : "Signed out. Your share could not be locked; close this tab to be safe.");
    setView({ id: "home" });
    setAuthed(false);
  };

  if (authed === null) return <FullScreen>{sessionError ? (
    <GlassCard className="w-full max-w-md">
      <h1 className="text-2xl font-semibold">Unable to connect</h1>
      <p className="mt-3 text-sm text-muted">We couldn’t check your session. Your signer may still be unlocked in this browser.</p>
      <ErrMsg msg={sessionError} />
      <Btn className="mt-4" onClick={checkSession}>Retry connection</Btn>
      <button className="mt-3 min-h-11 text-sm text-mint" onClick={() => { forgetSession(); setSessionError(null); setAuthed(false); }}>Sign out and start over</button>
    </GlassCard>
  ) : <Splash sub="Connecting…" />}</FullScreen>;
  if (!authed) return <Login notice={sessionError} onLoggedIn={() => { setAuthed(true); refreshStatus(); }} />;

  const network = status?.network;
  const profile = status?.profile;

  return (
    <>
      <LokiTunnel calm={["send", "review"].includes(view.id)} />
      <header className="glass fixed inset-x-0 top-0 z-30 flex h-20 items-center justify-between gap-3 px-5 sm:px-10">
        <button
          aria-label="Loki home"
          onClick={() => view.id !== "home" && setView({ id: "home" })}
          className="font-display min-h-11 shrink-0 text-lg font-extrabold tracking-[0.22em] text-[var(--ink)]"
        >
          LOKI
        </button>
        <div className="flex min-w-0 items-center gap-3 text-sm">
          {profile?.name && (
            <span className="hidden min-w-0 items-center gap-1.5 text-muted sm:flex">
              <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-mint" />
              <span className="max-w-40 truncate" title={profile.name}>{profile.name}</span>
            </span>
          )}
          {network && (
            <span className="eyebrow shrink-0 rounded-full border px-3 py-1" style={{ borderColor: "var(--border)" }}>
              {network}
            </span>
          )}
          <ThemeToggle />
          <button onClick={signOut} className="min-h-11 shrink-0 px-1 text-muted transition hover:text-danger">
            Log out
          </button>
        </div>
      </header>
      <main className="flex min-h-dvh w-full items-center justify-center overflow-y-auto px-5 py-24 sm:px-6">
        <Screen key={`${view.id}:${"vault" in view ? (typeof view.vault === "string" ? view.vault : view.vault.vault) : ""}:${"attempt" in view ? view.attempt : ""}`}>
          <ViewRouter
            view={view}
            status={status}
            statusError={statusError}
            profile={profile}
            onNavigate={setView}
            onStatusRefresh={refreshStatus}
          />
        </Screen>
      </main>
    </>
  );
}

// ─── screen wrapper ───────────────────────────────────────────────────────────

function useScreenFocus() {
  const ref = useRef<HTMLDivElement>(null);
  const [announcement, setAnnouncement] = useState("");
  useEffect(() => {
    const root = ref.current;
    if (!root) return;
    let last: Element | null = null;
    let lastTitle = "";
    const update = () => {
      const heading = root.querySelector<HTMLElement>("[data-screen-heading]") ?? root.querySelector<HTMLElement>("h1, h2");
      const title = heading?.textContent ?? "Wallet";
      if (heading === last && title === lastTitle) return;
      last = heading; lastTitle = title;
      const target = heading ?? root;
      target.tabIndex = -1;
      target.focus({ preventScroll: true });
      setAnnouncement(title);
    };
    update();
    const observer = new MutationObserver(update);
    observer.observe(root, { childList: true, subtree: true, characterData: true });
    return () => observer.disconnect();
  }, []);
  return { ref, announcement };
}

function Screen({ children }: { children: React.ReactNode }) {
  const { ref, announcement } = useScreenFocus();
  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2, ease: "easeOut" }}
      className="screen-transition w-full min-w-0 max-w-xl [overflow-wrap:anywhere]"
    >
      <p className="sr-only" aria-live="polite" aria-atomic="true">{announcement}</p>
      {children}
    </motion.div>
  );
}

// ─── view router ──────────────────────────────────────────────────────────────

function ViewRouter({
  view,
  status,
  statusError,
  profile,
  onNavigate,
  onStatusRefresh,
}: {
  view: View;
  status: StatusResponse | undefined;
  statusError: string | null;
  profile: { name: string; id: string } | undefined;
  onNavigate: (v: View) => void;
  onStatusRefresh: () => void;
}) {
  if (statusError && !status) {
    return (
      <GlassCard>
        <h2 className="text-2xl font-semibold">Unable to load wallet</h2>
        <ErrMsg msg={statusError} />
        <p className="mt-3 text-sm text-muted">We’ll keep trying to reconnect.</p>
        <Btn className="mt-4" onClick={onStatusRefresh}>Retry</Btn>
      </GlassCard>
    );
  }

  switch (view.id) {
    case "home":
      if (!status) return <Splash sub="Loading your wallet…" />;
      return (
        <>
          {statusError && <div className="mb-4"><ErrMsg msg={statusError} /><Btn variant="ghost" onClick={onStatusRefresh}>Retry refresh</Btn></div>}
          {status.persisted === false && (
            <div className="mb-4"><ErrMsg msg="This browser no longer keeps your signer's storage persistent, so it may delete your share under storage pressure. Export every vault's recovery backup and keep your 24 recovery words." /></div>
          )}
          {status.relay && <p className="mb-4 text-xs text-muted">Signer relay: <span className="font-mono">{status.relay}</span></p>}
          <Home
            profile={profile}
            vaults={status?.vaults ?? []}
            secureElement={status?.secure_element}
            onNavigate={onNavigate}
            onRefresh={onStatusRefresh}
          />
        </>
      );
    case "create-vault":
      return (
        <CreateVault
          profileId={profile?.id}
          onBack={() => onNavigate({ id: "home" })}
          onCreated={(vault) => onNavigate({ id: "ceremony", vault })}
        />
      );
    case "join-vault":
      return (
        <JoinVault
          profileId={profile?.id}
          initialInvite={view.invite}
          onBack={() => onNavigate({ id: "home" })}
          onJoined={(vault) => onNavigate({ id: "ceremony", vault })}
        />
      );
    case "ceremony":
      return (
        <CeremonyView
          vault={view.vault}
          secureElement={status?.secure_element}
          onDone={() => { onNavigate({ id: "home" }); onStatusRefresh(); }}
          onRestart={() => onNavigate({ id: "create-vault" })}
        />
      );
    case "overview":
      return (
        <VaultOverview
          vault={view.vault}
          onSend={() => onNavigate({ id: "send", vault: view.vault })}
          onHistory={() => onNavigate({ id: "history", vault: view.vault })}
          onApprove={({ attempt, proposer }) => onNavigate({
            id: "review", vault: view.vault, attempt,
            proposer: signerKind() === "browser" ? proposer : undefined, proposedHere: false,
          })}
          onBack={() => onNavigate({ id: "home" })}
        />
      );
    case "send":
      return (
        <Send
          vault={view.vault}
          onBack={() => onNavigate({ id: "overview", vault: view.vault })}
          onDraft={(attempt) => onNavigate({ id: "review", vault: view.vault, attempt, proposedHere: true })}
        />
      );
    case "review":
      return (
        <ReviewApprove
          profileId={profile?.id}
          proposedHere={view.proposedHere}
          vault={view.vault}
          attempt={view.attempt}
          proposer={view.proposer}
          onBack={() => onNavigate({ id: "history", vault: view.vault })}
        />
      );
    case "history":
      return (
        <History
          vault={view.vault}
          network={status?.network}
          onReview={(attempt) => onNavigate({ id: "review", vault: view.vault, attempt })}
          onBack={() => onNavigate({ id: "overview", vault: view.vault })}
        />
      );
  }
}

// ─── shared primitives ────────────────────────────────────────────────────────

function Row({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex flex-col gap-1 border-b border-[var(--border)] py-3 last:border-0 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
      <span className="shrink-0 text-sm text-muted">{label}</span>
      <div className={`min-w-0 text-sm [overflow-wrap:anywhere] sm:text-right ${mono ? "font-mono break-all" : ""}`}>{value}</div>
    </div>
  );
}

function Btn({
  children,
  onClick,
  disabled,
  variant = "mint",
  className = "",
}: {
  children: React.ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: "mint" | "amber" | "danger" | "ghost";
  className?: string;
}) {
  const styles: Record<string, string> = {
    mint: "btn-primary",
    amber: "btn-primary",
    danger: "btn-glass text-danger",
    ghost: "btn-glass",
  };
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`w-full min-w-0 rounded-full px-5 py-3.5 font-medium transition disabled:opacity-60 ${styles[variant]} ${className}`}
    >
      {children}
    </button>
  );
}

function GlassCard({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <div className={`glass min-w-0 rounded-2xl p-5 sm:px-6 ${className}`}>{children}</div>;
}

function BackLink({ onClick, label = "← Back" }: { onClick: () => void; label?: string }) {
  return (
    <button onClick={onClick} className="mb-4 min-h-11 rounded-full px-3 text-sm text-muted transition hover:bg-[var(--surface-2)] hover:text-mint">
      {label}
    </button>
  );
}

function ErrMsg({ msg }: { msg: string | null }) {
  if (!msg) return null;
  return <p role="alert" className="mt-3 rounded-xl border border-danger/25 bg-[var(--surface-2)] px-4 py-3 text-left text-sm leading-relaxed text-danger [overflow-wrap:anywhere]">{msg}</p>;
}

// Every member gets a stable colour from their slot, so everyone sees the same person in the
// same colour across the ceremony, approvals, and history.
const MEMBER_COLORS = ["#2f69ff", "#e24d78", "#17b890", "#9b51e0", "#f29e0a", "#00b4d8", "#ff6b3d", "#4c6ef5"];
function memberColor(slot: number) {
  return MEMBER_COLORS[(Math.max(1, slot) - 1) % MEMBER_COLORS.length];
}
function MemberAvatar({ slot, name, size = 28 }: { slot: number; name?: string; size?: number }) {
  const c = memberColor(slot);
  const label = (name?.trim()?.[0] ?? String(slot)).toUpperCase();
  return (
    <span
      className="inline-grid shrink-0 place-items-center rounded-full font-semibold text-white"
      style={{ width: size, height: size, fontSize: Math.round(size * 0.42), background: c, boxShadow: `0 3px 10px -3px ${c}` }}
      title={name ?? `Member ${slot}`}
      aria-hidden
    >
      {label}
    </span>
  );
}

// Light/dark toggle. Shows the current theme's glyph (sun in light, moon in dark); a click
// pins the opposite and persists it. Reads on both themes via --muted / --ink tokens.
function ThemeToggle() {
  const dark = useIsDark();
  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}
      title={dark ? "Switch to light theme" : "Switch to dark theme"}
      className="grid h-11 w-11 shrink-0 place-items-center rounded-full text-muted transition hover:text-[var(--ink)]"
    >
      {dark ? (
        // moon
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
        </svg>
      ) : (
        // sun
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
        </svg>
      )}
    </button>
  );
}

// ─── sign in ──────────────────────────────────────────────────────────────────

function FullScreen({ children, calm = false }: { children: React.ReactNode; calm?: boolean }) {
  const { ref, announcement } = useScreenFocus();
  return (
    <main className="flex min-h-dvh w-full items-center justify-center p-5">
      <LokiTunnel calm={calm} />
      <div ref={ref} className="flex w-full justify-center">
        <p className="sr-only" aria-live="polite" aria-atomic="true">{announcement}</p>
        {children}
      </div>
    </main>
  );
}

function Splash({ sub }: { sub: string }) {
  return (
    <div className="panel w-full max-w-md px-6 py-9 text-center">
      <div className="eyebrow mb-3">Shielded multisig</div>
      <h1 className="font-display text-4xl font-bold tracking-tight">Loki</h1>
      <p role="status" className="mt-4 flex items-center justify-center gap-2 text-sm text-muted">
        <span aria-hidden="true" className="h-4 w-4 shrink-0 animate-spin rounded-full border-2 border-mint/20 border-t-mint motion-reduce:animate-none" />
        {sub}
      </p>
    </div>
  );
}

// The signer lives in this browser now: a passkey (Touch/Face ID, security key, or
// phone) unlocks the sealed share, with a passphrase fallback for machines without
// WebAuthn. No install, no 127.0.0.1 pairing link. Tiers match definition §2.B.
function Login({ onLoggedIn, notice }: { onLoggedIn: () => void; notice: string | null }) {
  const [existing, setExisting] = useState<boolean>(hasSignerHint); // a share sealed here? sync guess, confirmed below
  const [mode, setMode] = useState<"passkey" | "passphrase">("passkey");
  const [platform, setPlatform] = useState(false); // biometric authenticator present?
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    // A signer error (another tab holds the signer, or the signer origin is unreachable) is
    // shown, not mistaken for "no signer here".
    // A share this browser had but the signer lost (404) offers Restore, not Unlock.
    hasSigner().then(setExisting).catch((e) => { setErr((e as Error).message); if ((e as ApiError).status === 404) setExisting(false); });
    const pk = (window as unknown as { PublicKeyCredential?: { isUserVerifyingPlatformAuthenticatorAvailable?: () => Promise<boolean> } }).PublicKeyCredential;
    pk?.isUserVerifyingPlatformAuthenticatorAvailable?.().then(setPlatform).catch(() => setPlatform(false));
  }, []);

  const unlocking = existing === true;
  const go = async (method: CustodyMethod) => {
    setBusy(true); setErr(null);
    try {
      // The passkey ceremony or passphrase entry happens in the signer's own window (its
      // origin), which opens over this page; this page never sees the secret.
      if (unlocking) await unlock({ method });
      else await createSigner({ name: name.trim() || "You", method });
      onLoggedIn();
    } catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };
  const [nativeOpen, setNativeOpen] = useState(false);
  const [nativeBusy, setNativeBusy] = useState(false);
  const [apps, setApps] = useState<Slot[]>();
  const [choice, setChoice] = useState<number | "paste">();
  useEffect(() => {
    const last = lastLokiSignerSlot();
    if (last !== undefined) { setChoice(last); setNativeOpen(true); }
  }, []);
  useEffect(() => {
    if (!nativeOpen) return;
    const loading = new AbortController();
    listSlots(loading.signal).then(setApps).catch(() => {
      if (!loading.signal.aborted) setApps([]); // An existing headless member can still paste.
    });
    return () => loading.abort();
  }, [nativeOpen]);
  const lokiSigners = apps?.filter((m) => m.lokisigner_url !== undefined) ?? [];
  const selected = choice ?? (lokiSigners.length === 0 && apps ? "paste" : undefined);
  const selectedSlot = typeof selected === "number" ? selected : undefined;
  const selectedMember = apps?.find((m) => m.slot === selectedSlot);

  return <FullScreen calm>
    <div className="panel w-full max-w-md px-6 py-8 sm:px-10">
      <div className="font-display text-center text-5xl font-semibold tracking-tight">Loki</div>
      <h1 className="mb-2 mt-8 text-xl font-semibold">{unlocking ? "Unlock your signer" : "Create your signer"}</h1>
      <p className="mb-5 text-sm text-muted">
        Your signing share lives in this browser, in the Loki signer&apos;s own storage, sealed under your
        passkey or passphrase. This page and the coordinator never receive it. Testnet only.
      </p>

      {!unlocking && (
        <label className="block text-xs text-muted">Your name on the roster
          <input value={name} autoComplete="name" spellCheck={false}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Alex" className="glass mb-4 mt-2 w-full rounded-full px-5 py-3" />
        </label>
      )}

      {mode === "passkey" ? (
        <div className="space-y-3">
          <Btn disabled={busy} onClick={() => go("platform")}>
            {busy ? "Waiting for passkey…" : unlocking
              ? (platform ? "Unlock with Touch/Face ID" : "Unlock with a passkey")
              : (platform ? "Create with Touch/Face ID" : "Create with a passkey")}
          </Btn>
          <Btn variant="ghost" disabled={busy} onClick={() => go("roaming")}>Use a security key or phone</Btn>
          <button className="min-h-11 w-full text-sm text-mint" onClick={() => { setErr(null); setMode("passphrase"); }}>
            No passkey on this device? Use a passphrase
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-xs text-muted">You type the passphrase in the Loki signer window, not on this page.</p>
          <Btn disabled={busy} onClick={() => go("passphrase")}>
            {busy ? "Waiting for the signer…" : unlocking ? "Unlock with passphrase" : "Create with passphrase"}
          </Btn>
          <button className="min-h-11 w-full text-sm text-mint" onClick={() => { setErr(null); setMode("passkey"); }}>
            Use a passkey instead
          </button>
        </div>
      )}

      {!unlocking && (
        // A fresh browser: rebuild a vault member from its 24 words and backup file, entered on
        // the signer page, sealed under the passkey or passphrase chosen above.
        <button className="mt-3 min-h-11 w-full text-sm text-mint" disabled={busy}
          onClick={async () => {
            setBusy(true); setErr(null);
            try { await restoreSigner({ name: name.trim() || "You", method: mode === "passphrase" ? "passphrase" : "platform" }); onLoggedIn(); }
            catch (e) { setErr((e as Error).message); }
            finally { setBusy(false); }
          }}>
          Restore from recovery words and a backup file
        </button>
      )}

      <ErrMsg msg={err ?? notice} />

      <button className="mt-5 min-h-11 w-full text-xs text-muted hover:text-mint"
        onClick={() => { setErr(null); setExisting(!unlocking); }}>
        {unlocking ? "Set up a different signer instead" : "Already have a signer here? Unlock it"}
      </button>

      {/* A native member app (LokiSigner / loki_member_app) instead of the browser signer: this
          tab then drives that member over its loopback device API. A new app first takes a
          pairing link (step 1); an app that is already paired goes straight to step 2. */}
      <details open={nativeOpen} className="mt-4 text-xs text-muted" onToggle={(e) => setNativeOpen(e.currentTarget.open)}>
        <summary className="min-h-11 cursor-pointer hover:text-mint">Use a native member app instead</summary>
        <h2 className="mb-1 mt-3 text-sm font-semibold text-[var(--ink)]">1 · Pair a new native signer</h2>
        <NativePairingLink open={nativeOpen} onReserved={setChoice} onRegistered={setApps} />
        <h2 className="mb-1 mt-5 text-sm font-semibold text-[var(--ink)]">2 · Connect this wallet tab</h2>
        {nativeOpen && <>
          {(lokiSigners.length > 0 || selectedSlot !== undefined) && <label className="my-2 block">
            Member app
            <select value={selected ?? ""} disabled={busy || nativeBusy} onChange={(e) => setChoice(e.target.value === "paste" ? "paste" : Number(e.target.value))}
              className="glass mt-1 w-full rounded-full px-4 py-2.5 text-[var(--ink)]">
              {selected === undefined && <option value="" disabled>Choose a member app</option>}
              {lokiSigners.map((m) => <option key={m.slot} value={m.slot}>LokiSigner · Slot {m.slot}</option>)}
              {selectedSlot !== undefined && !lokiSigners.some((m) => m.slot === selectedSlot) &&
                <option value={selectedSlot}>Member app · Slot {selectedSlot}</option>}
              <option value="paste">Headless or older member app</option>
            </select>
          </label>}
          {selected === undefined && lokiSigners.length === 0 && <p role="status" className="my-2">Reading the member roster…</p>}
          {/* Starting a browser-signer action unmounts and cancels a pending native connection. */}
          {selected !== undefined && !busy && <NativeTabConnection key={selected} member={selectedMember} slot={selectedSlot} disabled={nativeBusy}
            onBusy={setNativeBusy} onConnected={onLoggedIn} />}
        </>}
      </details>
    </div>
  </FullScreen>;
}

// Step 1 of pairing a native member app: a `loki://pair` link from the coordinator. Each
// request reserves a slot for 120 s and the coordinator caps pending reservations, so only the
// member asks for a new link, never a timer. While the link is out, and for a minute after it
// lapses, the public roster shows whether LokiSigner registered that slot.
const ROSTER_POLL_MS = 3000;
const ROSTER_GRACE_MS = 60_000;

function NativePairingLink({ open, onReserved, onRegistered }: { open: boolean; onReserved: (slot: number) => void; onRegistered: (roster: Slot[]) => void }) {
  const [link, setLink] = useState<PairingLink | null>(null);
  const [slot, setSlot] = useState<number>(); // a new link asks for this slot again
  const [registered, setRegistered] = useState<number | null>(null);
  const [now, setNow] = useState(0);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState<boolean | null>(null); // null: not copied, false: copy failed

  const request = async (want: number | undefined) => {
    setBusy(true); setErr(null); setCopied(null);
    try {
      const issued = await requestPairingLink(want);
      setSlot(issued.slot); setNow(Date.now()); setLink(issued); setRegistered(null);
      onReserved(issued.slot);
    } catch (e) {
      // A taken slot stays taken: stop watching it, and let the next link take a new slot.
      if (e instanceof PairingSlotTaken) setSlot(undefined);
      setLink(null); setErr((e as Error).message);
    }
    finally { setBusy(false); }
  };
  const copy = async () => {
    try { await navigator.clipboard.writeText(link!.url); setCopied(true); setTimeout(() => setCopied(null), 1500); }
    catch { setCopied(false); }
  };

  const watching = open && link !== null && registered === null;
  useEffect(() => {
    if (!watching) return;
    const tick = setInterval(() => {
      setNow(Date.now());
      if (Date.now() >= link.expires) clearInterval(tick);
    }, 250);
    let stopped = false;
    const poll = setInterval(async () => {
      if (Date.now() > link.expires + ROSTER_GRACE_MS) { clearInterval(poll); return; }
      try {
        const roster = await listSlots();
        if (!stopped && roster.some((m) => m.slot === link.slot)) { setRegistered(link.slot); onRegistered(roster); }
      } catch {} // the next poll retries
    }, ROSTER_POLL_MS);
    return () => { stopped = true; clearInterval(tick); clearInterval(poll); };
  }, [watching, link, onRegistered]);

  if (registered !== null) {
    // The roster shows only that some identity registered this slot, not that it is this member's.
    return <>
      <p role="status" className="my-2 font-medium text-mint">
        Slot {registered} now appears on the roster. If LokiSigner is running and paired with that slot, connect below.
      </p>
      <button type="button" disabled={busy} onClick={() => request(undefined)} className="min-h-11 text-mint">
        {busy ? "Requesting…" : "LokiSigner did not pair? Get a link for another slot"}
      </button>
      {err && <p role="alert" className="mb-3 leading-relaxed text-danger [overflow-wrap:anywhere]">{err}</p>}
    </>;
  }
  if (!link) {
    return <>
      <p className="my-2">Get a link that opens LokiSigner and reserves a slot for two minutes.</p>
      {err && <p role="alert" className="mb-3 leading-relaxed text-danger [overflow-wrap:anywhere]">{err}</p>}
      <Btn variant="ghost" disabled={busy} onClick={() => request(slot)}>
        {busy ? "Requesting…" : err ? (slot === undefined ? "Get a new link" : "Try again") : "Get a pairing link"}
      </Btn>
    </>;
  }
  const left = pairingSecondsLeft(link.expires, now);
  if (left === 0) {
    return <>
      <p role="status" className="my-2">
        The link for slot {link.slot} expired. If LokiSigner is running and paired with that slot, connect below.
        Otherwise get a new link for the same slot.
      </p>
      <Btn variant="ghost" disabled={busy} onClick={() => request(slot)}>{busy ? "Requesting…" : "Get a new link"}</Btn>
    </>;
  }
  return <>
    <p className="my-2">
      Slot <span className="font-semibold text-[var(--ink)]">{link.slot}</span> is reserved for this link.
      {" "}Expires in <span className="font-mono text-[var(--ink)]">{Math.floor(left / 60)}:{String(left % 60).padStart(2, "0")}</span>.
    </p>
    <div className="mb-3 flex gap-2">
      <a href={link.url} className="btn-primary min-w-0 flex-1 rounded-full px-5 py-3.5 text-center text-sm font-medium">Open LokiSigner</a>
      <button type="button" onClick={copy} className="btn-glass rounded-full px-5 py-3.5 text-sm font-medium">
        {copied ? "Copied" : "Copy link"}
      </button>
    </div>
    {copied === false && <p role="alert" className="mb-2 text-danger">Could not copy. Use Open LokiSigner instead.</p>}
    <p className="mb-1">LokiSigner then asks, in this order:</p>
    <ol className="list-decimal space-y-1 pl-5">
      <li>“Pair this device with slot {link.slot}?” with the coordinator. Choose Continue only if it shows {window.location.origin}.</li>
      <li>“Pair this device with slot {link.slot}?” again, with the network and endpoints. Enter a local profile passphrase and choose Pair.</li>
      <li>For a new profile, “Save your recovery words privately”. Write them down, then choose “I saved these words”.</li>
      <li>“LokiSigner is running”. Choose Done, then connect this tab in step 2 below.</li>
    </ol>
  </>;
}

// Describe protection on the signer host, not custody inside this browser.
function SecureStorageBadge({ se }: { se?: string }) {
  const { enclave, label, detail } = storageLabel(se, signerKind());
  return (
    <span
      className="pill text-[11px] text-muted"
      title={detail}
    >
      <span className={`dot ${enclave ? "bg-mint text-mint" : "bg-amber text-amber"}`} />
      {label}
    </span>
  );
}

function AccountNumber() {
  const [id, setId] = useState<number | null>(null);
  useEffect(() => {
    try { setId(JSON.parse(sessionStorage.getItem("loki_me") ?? "null")?.slot ?? null); } catch {}
  }, []);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  // Register this browser's signer in the coordinator's public roster (frostd-only member, no
  // advertised URL). The signer signs the registration on its own origin; registering the same
  // identity again returns the same slot, so this also recovers the number after a reload.
  const register = async () => {
    setBusy(true); setErr(null);
    try {
      const member = await enroll();
      try { sessionStorage.setItem("loki_me", JSON.stringify({ slot: member.slot })); } catch {}
      setId(member.slot);
    } catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };
  if (id) return <p className="mb-5 text-xs text-muted">Account number: <span className="select-all font-mono">{id}</span> · Your public roster slot in this vault.</p>;
  return <div className="mb-5">
    <Btn variant="ghost" disabled={busy} onClick={register}>{busy ? "Registering…" : "Register this signer with the coordinator"}</Btn>
    <ErrMsg msg={err} />
  </div>;
}

// ─── home ─────────────────────────────────────────────────────────────────────

function Home({
  profile,
  vaults,
  secureElement,
  onNavigate,
  onRefresh,
}: {
  profile: { name: string; id: string } | undefined;
  vaults: VaultSummary[];
  secureElement?: string;
  onNavigate: (v: View) => void;
  onRefresh: () => void;
}) {
  const browser = signerKind() === "browser";
  return (
    <div>
      <div className="mb-6 flex flex-col items-start gap-3 sm:flex-row sm:items-center sm:justify-between">
        <h2 className="min-w-0 text-2xl font-semibold">{profile?.name ?? "Wallet"}</h2>
        <SecureStorageBadge se={secureElement} />
      </div>

      <AccountNumber />
      {[{ title: "Active vaults", items: vaults.filter((v) => v.active !== false) },
        { title: "Setting up", items: vaults.filter((v) => v.active === false) }].map(({ title, items }) => (
        (title === "Active vaults" || items.length > 0) && <section key={title} className="mb-6">
          <h3 className="eyebrow mb-3">{title}</h3>
          {items.length === 0 ? <GlassCard className="py-8 text-center text-sm text-muted">
            <p className="mb-2 font-display text-lg font-semibold text-foreground">No active vaults yet</p>
            <p>{vaults.length ? "Finish setup below to activate your vault." : browser ? "Join with an invite link." : "Create one or join with an invite link."}</p>
          </GlassCard> : <div className="space-y-2.5">{items.map((v) => (
            <button key={v.vault}
              onClick={() => onNavigate(v.active === false ? { id: "ceremony", vault: v.vault } : { id: "overview", vault: v })}
              className="glass w-full rounded-2xl p-5 text-left transition hover:-translate-y-0.5 hover:border-mint/30">
              <div className="flex items-start justify-between gap-3">
                <span className="min-w-0 font-medium">{v.name}</span>
                <span className="shrink-0 rounded-full bg-mint/10 px-2.5 py-0.5 text-xs text-mint">{v.threshold} of {v.members} approvals</span>
              </div>
              <div className="mt-1 flex items-center justify-between gap-2">
                <span className="font-mono text-xs text-muted">{short(v.vault)}</span>
                {v.active === false && <span className="shrink-0 text-xs text-amber">Finish setup →</span>}
              </div>
            </button>
          ))}</div>}
        </section>
      ))}

      <div className="grid gap-3 sm:grid-cols-2">
        {!browser && <Btn variant="mint" onClick={() => onNavigate({ id: "create-vault" })}>
          Create vault
        </Btn>}
        <Btn variant="ghost" onClick={() => onNavigate({ id: "join-vault" })}>
          Join vault
        </Btn>
      </div>
      {browser && <BrowserSignerRecovery onRestored={onRefresh} />}
    </div>
  );
}

// The embedded signer starts recovery and custody operations in a separate signer tab.
function BrowserSignerRecovery({ onRestored }: { onRestored: () => void }) {
  const [hasWords, setHasWords] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    recoveryStatus("").then((s) => setHasWords(s.recovery_identity)).catch((e) => setErr((e as Error).message));
  }, []);
  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true); setErr(null);
    try { await fn(); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  return (
    <section className="mt-6 space-y-3">
      <h3 className="eyebrow">Recovery</h3>
      <p className="text-xs text-muted">
        {hasWords
          ? "Your 24 recovery words are set. Each vault's backup is sealed to them; download it from the vault."
          : "Set up 24 recovery words. You need them, and each vault's backup file, to restore this signer in another browser."}
      </p>
      {hasWords === false && <Btn disabled={busy} onClick={() => run(async () => { await setupBrowserRecovery(); setHasWords(true); })}>Set up recovery words</Btn>}
      <Btn variant="ghost" disabled={busy} onClick={() => run(async () => { await restoreSigner({}); onRestored(); })}>Restore another vault</Btn>
      <Btn variant="ghost" disabled={busy} onClick={() => run(async () => { if (await manageBrowserCustody()) window.location.reload(); })}>Manage browser signer</Btn>
      <ErrMsg msg={err} />
    </section>
  );
}

// ─── create vault ─────────────────────────────────────────────────────────────

function CreateVault({
  profileId,
  onBack,
  onCreated,
}: {
  profileId?: string;
  onBack: () => void;
  onCreated: (vault: string) => void;
}) {
  const [name, setName] = useState("");
  const [members, setMembers] = useState(3);
  const [threshold, setThreshold] = useState(2);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // the host requires 2 <= threshold < members <= 16
  const t = Math.min(threshold, members - 1);
  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      const res = await api<{ vault: string }>("create", { name, members, threshold: t });
      rememberVaultSlot(profileId, res.vault, 1);
      onCreated(res.vault);
    } catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };

  const range = (lo: number, hi: number) => Array.from({ length: hi - lo + 1 }, (_, i) => lo + i);

  return (
    <div>
      <BackLink onClick={onBack} />
      <h2 className="mb-6 text-2xl font-semibold">Set up vault</h2>
      <GlassCard className="space-y-3">
        <div className="rounded-xl border border-mint/25 bg-mint/10 p-4">
          <p className="text-2xl font-semibold text-mint">{t} of {members} approvals</p>
          <p className="mt-1 text-sm text-muted">Required for every payment</p>
        </div>
        <p className="text-sm text-muted">
          {members} people hold a share; any {t} of them must approve each payment. Share an
          invite link with each of the others, then verify the members together.
        </p>
        <label className="block text-left text-xs text-muted">
          Vault name
          <input
            placeholder="Vault name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && name && !busy && submit()}
            className="glass mt-1.5 w-full rounded-full px-5 py-3 outline-none"
          />
        </label>
        <div className="grid grid-cols-2 gap-3">
          <label className="text-left text-xs text-muted">
            Members
            <select
              value={members}
              onChange={(e) => setMembers(Number(e.target.value))}
              className="glass mt-1 w-full rounded-full px-6 py-2.5 text-left text-sm text-foreground outline-none bg-transparent"
            >
              {range(3, 16).map((n) => (
                <option key={n} value={n} className="bg-[var(--surface-2)] text-foreground">{n}</option>
              ))}
            </select>
          </label>
          <label className="text-left text-xs text-muted">
            Approvals needed
            <select
              value={t}
              onChange={(e) => setThreshold(Number(e.target.value))}
              className="glass mt-1 w-full rounded-full px-6 py-2.5 text-left text-sm text-foreground outline-none bg-transparent"
            >
              {range(2, members - 1).map((n) => (
                <option key={n} value={n} className="bg-[var(--surface-2)] text-foreground">{n}</option>
              ))}
            </select>
          </label>
        </div>
      </GlassCard>
      <div className="mt-4">
        <Btn onClick={submit} disabled={!name || busy}>
          {busy ? "Starting…" : "Set up vault"}
        </Btn>
      </div>
      <ErrMsg msg={err} />
    </div>
  );
}

// ─── join vault ───────────────────────────────────────────────────────────────

function JoinVault({
  profileId,
  initialInvite,
  onBack,
  onJoined,
}: {
  profileId?: string;
  initialInvite?: string;
  onBack: () => void;
  onJoined: (vault: string) => void;
}) {
  const [invite, setInvite] = useState(initialInvite ?? "");
  const code = extractInvite(invite);
  const preview = invitePreview(code);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async () => {
    if (!code) return;
    setBusy(true); setErr(null);
    try {
      const res = await api<{ vault: string }>("join", { invite: code });
      if (preview?.vault === res.vault) rememberVaultSlot(profileId, res.vault, preview.slot);
      onJoined(res.vault);
    } catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };

  return (
    <div>
      <BackLink onClick={onBack} />
      <h2 className="mb-2 text-2xl font-semibold">Join a vault</h2>
      <p className="mb-5 text-sm text-muted">
        Paste the invite link the creator sent you (or just open their link). You join their vault,
        then everyone verifies the members together and the keys are created.
      </p>
      <GlassCard>
        <label className="block text-xs text-muted">
          Invite link or code
          <input
            placeholder="Paste invite link"
            value={invite}
            onChange={(e) => setInvite(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && invite && !busy && submit()}
            className="glass mt-1.5 w-full rounded-full px-5 py-3 font-mono outline-none"
          />
        </label>
      </GlassCard>
      <GlassCard className="mt-4">
        <h3 className="eyebrow mb-2">Invite preview</h3>
        {preview ? <>
          <p className="text-lg font-semibold">{preview.name}</p>
          <p className="mt-1 text-mint">{preview.threshold} of {preview.members} approvals</p>
          <p className="mt-2 text-xs text-muted">These details come from the invite. Confirm the vault name and approval requirement with the creator before joining.</p>
        </> : <p className="text-sm text-muted">{invite ? "Preview unavailable for this invite. Ask the creator for the vault name and approval requirement before joining." : "Paste an invite to see its vault name and approval requirement."}</p>}
      </GlassCard>
      <div className="mt-4">
        <Btn onClick={submit} disabled={!code || busy}>
          {busy ? "Joining…" : "Join →"}
        </Btn>
      </div>
      <ErrMsg msg={err} />
    </div>
  );
}

// ─── ceremony ─────────────────────────────────────────────────────────────────

// The phases the host actually emits (see host/ceremony.rs status): waiting → roster → keys →
// active. Backup is done inside the key-generation step, not as its own phase.
const CEREMONY_PHASES: CeremonyStatus["phase"][] = [
  "waiting_for_members",
  "compare_roster",
  "creating_keys",
  "active",
];

const PHASE_LABEL: Record<CeremonyStatus["phase"], string> = {
  waiting_for_members: "Waiting for members",
  compare_roster: "Verify members",
  creating_keys: "Creating keys",
  setup_interrupted: "Setup interrupted",
  active: "Active",
};

function CeremonyView({
  vault,
  secureElement,
  onDone,
  onRestart,
}: {
  vault: string;
  secureElement?: string;
  onDone: () => void;
  onRestart: () => void;
}) {
  const { data: cs, error, refresh } = useCeremonyStatus(vault, true);

  if (error) {
    return (
      <GlassCard>
        <h2 className="text-2xl font-semibold">Vault setup unavailable</h2>
        <ErrMsg msg={error} />
        <p className="mt-3 text-sm text-muted">We’ll keep trying to reconnect.</p>
        <Btn className="mt-4" onClick={refresh}>Retry</Btn>
      </GlassCard>
    );
  }

  if (!cs) {
    return <GlassCard><p role="status" className="py-5 text-center text-sm text-muted">Loading vault setup…</p></GlassCard>;
  }

  if (cs.phase === "active") {
    return (
      <GlassCard className="text-center">
        <div aria-hidden="true" className="mx-auto mb-4 grid h-14 w-14 place-items-center rounded-full bg-mint/10 text-3xl text-mint">✓</div>
        <h2 className="text-2xl font-semibold text-mint mb-2">Vault ready</h2>
        <p className="text-muted text-sm mb-4">Setup is complete and the vault is active.</p>
        <p className="mb-6 text-sm text-foreground/90">
          {storageLabel(secureElement, signerKind()).detail}
        </p>
        <div className="mb-8 flex justify-center"><SecureStorageBadge se={secureElement} /></div>
        <Btn onClick={onDone}>Go to vault →</Btn>
      </GlassCard>
    );
  }

  return (
    <div>
      <h2 className="mb-4 text-2xl font-semibold">Set up vault</h2>
      <PhaseLadder current={cs.phase} />

      <div className="mt-6">
        {cs.phase === "waiting_for_members" && (
          <WaitingForMembers invites={cs.invites ?? []} />
        )}
        {/* Only LokiSigner's native window reports `roster_dialog`. */}
        {cs.phase === "compare_roster" && comparesInLokiSigner(cs) && (
          <NativeCompareRoster
            creator={cs.invites !== undefined}
            vault={vault}
            fingerprint={cs.fingerprint}
            rosterCode={cs.roster_code ?? undefined}
            confirmations={cs.confirmations ?? 0}
            confirmed={cs.confirmed ?? false}
            members={cs.members}
            dialog={cs.roster_dialog ?? null}
          />
        )}
        {cs.phase === "compare_roster" && !comparesInLokiSigner(cs) && (
          <CompareRoster
            key={cs.roster_code ?? ""}
            creator={cs.invites !== undefined}
            vault={vault}
            fingerprint={cs.fingerprint}
            rosterCode={cs.roster_code ?? undefined}
            confirmations={cs.confirmations ?? 0}
            confirmed={cs.confirmed ?? false}
            members={cs.members}
          />
        )}
        {cs.phase === "creating_keys" && (
          <GlassCard>
            <p role="status" className="py-5 text-center text-sm text-muted">
              {PHASE_LABEL[cs.phase]}… please wait.
            </p>
          </GlassCard>
        )}
        {cs.phase === "setup_interrupted" && (
          <GlassCard className="text-center">
            <h3 className="mb-3 text-lg font-semibold text-amber">Vault setup interrupted</h3>
            <ErrMsg msg={cs.error ?? "Key generation stopped before this vault became active."} />
            <p className="my-4 text-sm text-muted">
              This setup cannot be resumed safely. Create a new vault and share its new invitations
              with every member. Each member must compare and confirm the new verification code.
              The interrupted vault is kept for reference.
            </p>
            <Btn onClick={onRestart}>Create a new vault</Btn>
          </GlassCard>
        )}
      </div>
    </div>
  );
}

function PhaseLadder({ current }: { current: CeremonyStatus["phase"] }) {
  const currentIdx = CEREMONY_PHASES.indexOf(current);
  return (
    <div className="flex flex-wrap gap-1.5">
      {CEREMONY_PHASES.map((p, i) => (
        <span
          key={p}
          aria-current={i === currentIdx ? "step" : undefined}
          className={`rounded-full px-2.5 py-0.5 text-[11px] font-medium transition ${
            i < currentIdx
              ? "bg-mint/15 text-mint"
              : i === currentIdx
              ? "bg-mint text-[var(--on-accent)]"
              : "border border-[var(--border)] bg-[var(--surface-2)] text-muted"
          }`}
        >
          {PHASE_LABEL[p]}
        </span>
      ))}
    </div>
  );
}

function FullValue({ value, label, expanded = false }: { value: string; label: string; expanded?: boolean }) {
  return <details open={expanded || undefined} className="min-w-0 text-left text-xs">
    <summary className="min-h-11 cursor-pointer py-2 font-mono text-muted">{short(value, 16, 10)} · Full {label}</summary>
    <p tabIndex={0} className="select-all break-all rounded-xl border border-[var(--border)] bg-[var(--surface-2)] p-3 font-mono">{value}</p>
  </details>;
}

function WaitingForMembers({ invites }: { invites: InviteSlot[] }) {
  const [copied, setCopied] = useState<number | null>(null);
  const [copyFailed, setCopyFailed] = useState<number | null>(null);
  const copy = async (slot: number, code: string) => {
    try {
      setCopyFailed(null);
      await navigator.clipboard.writeText(inviteLink(code));
      setCopied(slot);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      setCopyFailed(slot);
    }
  };
  // A joiner's status carries no invite list (only the creator holds it), so an empty
  // array here means the viewer has already joined and is just waiting for the others.
  if (invites.length === 0) {
    return (
      <GlassCard>
        <p role="status" className="text-sm leading-relaxed text-muted">
          You&apos;re in. Waiting for the other members to join — setup advances
          automatically once everyone has joined.
        </p>
      </GlassCard>
    );
  }
  const joined = invites.filter((i) => i.joined).length;
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted">
        Send <span className="text-foreground">one link to each person</span>. They open it, create
        their account, and they&apos;re in — setup advances automatically once everyone has
        joined.
      </p>
      <p className="pill text-muted">
        <span className={`dot ${joined === invites.length ? "bg-mint text-mint" : "bg-amber text-amber"}`} />
        {joined} of {invites.length} joined
      </p>
      {invites.map((inv, i) => (
        <div key={inv.slot} className="glass flex items-center justify-between gap-3 rounded-2xl p-4">
          <div className="flex min-w-0 items-center gap-3">
            <MemberAvatar slot={inv.slot} />
            <div className="min-w-0">
              <p className="mb-1 text-xs text-muted">Invite {i + 1}</p>
              {inv.joined ? <p className="text-xs text-muted">Joined ✓</p> : <FullValue value={inviteLink(inv.code)} label="invite link" expanded={copyFailed === inv.slot} />}
              {copyFailed === inv.slot && <p role="alert" className="text-xs text-danger">Copy failed. Select the full link above and copy manually.</p>}
            </div>
          </div>
          {inv.joined ? (
            <span className="shrink-0 text-xs text-mint">✓ in</span>
          ) : (
            <button
              onClick={() => copy(inv.slot, inv.code)}
              aria-label={`Copy invite ${i + 1} link`}
              className="btn-glass shrink-0 rounded-full px-3 py-2 text-sm"
            >
              {copied === inv.slot ? "✓ copied" : "Copy link"}
            </button>
          )}
        </div>
      ))}
    </div>
  );
}

function CompareRoster({
  creator = false,
  vault,
  fingerprint,
  rosterCode,
  confirmations,
  confirmed,
  members,
}: {
  creator?: boolean;
  vault: string;
  fingerprint: string | undefined;
  rosterCode?: string;
  confirmations: number;
  confirmed: boolean;
  members: number;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  // The parent keys this form by roster code so a status refresh cannot carry approval over.
  const [checked, setChecked] = useState(false);

  const [confirmedHere, setConfirmedHere] = useState(confirmed);
  useEffect(() => {
    setConfirmedHere(confirmed);
  }, [confirmed]);

  const agree = async () => {
    setBusy(true); setErr(null);
    try {
      // The signer accepts agreement only with the 24-digit code it derives itself, the one shown.
      await api("agree", { vault, fingerprint, roster_code: rosterCode });
      setConfirmedHere(true);
    } catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };

  const allConfirmed = members > 0 && confirmations >= members;
  const headless = signerKind() === "native";

  return (
    <div>
      {rosterCode && headless ? (
        <p className="text-sm text-muted mb-4">
          Request confirmation to show the code in your signer&apos;s terminal. Compare all 24 digits
          with the other members on their trusted screens or terminals, then answer in your terminal.
        </p>
      ) : rosterCode ? (
        <>
          <p className="text-sm text-muted mb-4">
            Security check: compare all 24 digits with every member on a call or in person.
            Confirm only if everyone sees <span className="text-foreground">exactly the same code</span>.
          </p>
          <GlassCard className="mb-4 text-center">
            <h3 className="eyebrow mb-2">Compare this code</h3>
            <p className="font-mono text-base font-semibold tracking-wide text-amber sm:text-xl">{rosterCode}</p>
          </GlassCard>
        </>
      ) : (
        <p role="status" className="mb-4 text-sm text-muted">The signer has not provided a roster code. You can’t confirm members without it.</p>
      )}
      {creator && (
        <p className="pill text-muted mb-4">
          <span className={`dot ${allConfirmed ? "bg-mint text-mint" : "bg-amber text-amber"}`} />
          {confirmations} of {members} confirmed
        </p>
      )}
      {rosterCode && !confirmedHere && !allConfirmed && (
        <>
          {!headless && <label className="glass mb-3 flex items-start gap-3 rounded-2xl p-4 text-left text-sm text-foreground cursor-pointer">
            <input type="checkbox" className="mt-0.5 h-4 w-4 shrink-0 accent-amber" checked={checked}
              onChange={(e) => setChecked(e.target.checked)} />
            <span>I compared all 24 digits with the other members and they match.</span>
          </label>}
          <Btn variant="amber" onClick={agree} disabled={busy || !fingerprint || (!headless && !checked)}>
            {headless ? (busy ? "Check your signer’s terminal…" : "Request local confirmation") : (busy ? "Confirming…" : "Confirm members")}
          </Btn>
        </>
      )}
      {(confirmedHere || allConfirmed) && (
        <p role="status" className="glass rounded-2xl p-4 text-center text-sm text-mint">{allConfirmed ? "All members confirmed — advancing…" : "You confirmed — waiting for others."}</p>
      )}
      <ErrMsg msg={err} />
    </div>
  );
}

/** A LokiSigner member compares the code in LokiSigner, which records agreement only when the
 *  member chooses "Codes match" there. This page never shows the code it was sent to compare. */
function NativeCompareRoster({
  creator = false,
  vault,
  fingerprint,
  rosterCode,
  confirmations,
  confirmed,
  members,
  dialog,
}: {
  creator?: boolean;
  vault: string;
  fingerprint: string | undefined;
  rosterCode?: string;
  confirmations: number;
  confirmed: boolean;
  members: number;
  dialog: CeremonyStatus["roster_dialog"];
}) {
  const [asking, setAsking] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [confirmedHere, setConfirmedHere] = useState(false);

  const ask = async () => {
    setAsking(true); setErr(null);
    try {
      // The request names the code the member's signer derived; LokiSigner shows it and agrees
      // only when the member chooses "Codes match" there.
      await api("agree", { vault, fingerprint, roster_code: rosterCode });
      setConfirmedHere(true);
    } catch (e) {
      setErr(nativeRosterRefusal((e as Error).message, e instanceof ApiError));
    } finally { setAsking(false); }
  };

  const allConfirmed = members > 0 && confirmations >= members;
  // The member's own status reports a confirmation made after this page lost the request.
  const done = confirmed || confirmedHere || allConfirmed;
  const waiting = !done && (asking || dialog === "open");
  const refusal = err ?? (dialog === "codes_differ" ? nativeRosterRefusal("roster codes differ", true) : null);

  return (
    <div>
      <p className="mb-4 text-sm text-muted">
        Security check: <span className="text-foreground">LokiSigner shows this vault&apos;s code</span>,
        not this page. Compare it with every other member over a channel you already trust, such
        as a call or in person, and answer in LokiSigner. Choose Codes match there only if every
        member sees the same code.
      </p>
      {creator && (
        <p className="pill text-muted mb-4">
          <span className={`dot ${allConfirmed ? "bg-mint text-mint" : "bg-amber text-amber"}`} />
          {confirmations} of {members} confirmed
        </p>
      )}
      {!done && !waiting && dialog !== "codes_differ" && (
        <Btn variant="amber" onClick={ask} disabled={!fingerprint || !rosterCode}>
          Compare in LokiSigner
        </Btn>
      )}
      {waiting && (
        <p role="status" className="glass rounded-2xl p-4 text-center text-sm text-foreground">
          LokiSigner is showing the code. Compare it with every other member, then answer in
          LokiSigner. Unanswered after 10 minutes, it is refused.
        </p>
      )}
      {done && (
        <p role="status" className="glass rounded-2xl p-4 text-center text-sm text-mint">{allConfirmed ? "All members confirmed — advancing…" : "You confirmed in LokiSigner — waiting for others."}</p>
      )}
      {!done && <ErrMsg msg={refusal} />}
    </div>
  );
}

// ─── vault overview ───────────────────────────────────────────────────────────

function ProviderProvenance({ chain_trust }: ChainProvenance) {
  return chain_trust === "provider_reported" && (
    <p className="mb-3 text-xs text-muted">Reported by your chain provider · not independently verified</p>
  );
}

function VaultOverview({
  vault,
  onSend,
  onHistory,
  onApprove,
  onBack,
}: {
  vault: VaultSummary;
  onSend: () => void;
  onHistory: () => void;
  onApprove: (payment: PendingApproval) => void;
  onBack: () => void;
}) {
  const [address, setAddress] = useState<string | null>(null);
  type Balance = ChainProvenance & { balance_zat: number };
  const [balance, setBalance] = useState<Balance | null>(null);
  const [copied, setCopied] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);
  const [verifyingAddress, setVerifyingAddress] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [loadVersion, setLoadVersion] = useState(0);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [balanceErr, setBalanceErr] = useState<string | null>(null);
  const [retrying, setRetrying] = useState(false);
  const needsTouchID = balanceErr === "Touch ID is required to open this vault.";
  const [funding, setFunding] = useState<"idle" | "requesting" | "unconfirmed">("idle");
  const [pending, setPending] = useState<PendingApproval[] | null>(null);
  const [pendingError, setPendingError] = useState<string | null>(null);
  const [pendingVersion, setPendingVersion] = useState(0);

  // Poll for payments another member proposed that need THIS member's approval — the co-signer's
  // inbox. Without this a co-signer has no way to discover a pending payment to approve.
  useEffect(() => {
    let active = true;
    const load = () =>
      pendingApprovals(vault.vault)
        .then((r) => { if (active) { setPending(r.pending); setPendingError(null); } })
        .catch((e) => active && setPendingError((e as Error).message));
    load();
    const timer = setInterval(load, 3000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [vault.vault, pendingVersion]);

  useEffect(() => {
    let active = true;
    setLoadErr(null);
    // Load independently: a hosted vault's balance can be unavailable (needs a scan /
    // roster the signer can't open), but the address must still render.
    api<{ address: string }>(`address?vault=${vault.vault}`)
      .then((r) => { if (active) { setAddress(r.address); setLoadErr(null); } })
      .catch((e) => active && setLoadErr((e as Error).message));
    // Poll the balance so a deposit (or a still-scanning signer) shows up without a reload.
    const loadBalance = () =>
      api<Balance>("balance", { vault: vault.vault })
        .then((r) => { if (active) { setBalance(r); setBalanceErr(null); } })
        .catch((e) => active && setBalanceErr((e as Error).message));
    loadBalance();
    const timer = setInterval(loadBalance, 5000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [vault.vault, loadVersion]);

  const retryDetails = async () => {
    if (needsTouchID) {
      setRetrying(true);
      try {
        setBalance(await api<Balance>("balance", { vault: vault.vault, retry_touch_id: true }));
        setBalanceErr(null);
      } catch (e) { setBalanceErr((e as Error).message); }
      finally { setRetrying(false); }
    }
    setLoadVersion((v) => v + 1);
  };

  const copy = async () => {
    if (!address) return;
    try {
      setCopyFailed(false);
      await navigator.clipboard.writeText(address);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { setCopyFailed(true); }
  };

  const verifyAddress = async () => {
    setVerifyingAddress(true);
    setVerifyError(null);
    try { await api("verify-address", { vault: vault.vault }); }
    catch (e) { setVerifyError((e as Error).message); }
    finally { setVerifyingAddress(false); }
  };

  const requestFunds = async () => {
    if (!address || funding === "requesting") return;
    setFunding("requesting"); setLoadErr(null);
    try {
      const storageKey = `loki_funding:${vault.vault}:${address}`;
      const attempt = sessionStorage.getItem(storageKey) ?? crypto.randomUUID();
      sessionStorage.setItem(storageKey, attempt);
      const { mined } = await fund(address, attempt);
      setFunding(mined ? "idle" : "unconfirmed");
      if (mined) {
        sessionStorage.removeItem(storageKey);
        setLoadVersion((v) => v + 1);
      }
    } catch (e) {
      setLoadErr((e as Error).message);
      setFunding("idle");
    }
  };

  return (
    <div>
      <BackLink onClick={onBack} />
      <div className="mb-3 flex items-start justify-between gap-3">
        <h2 className="min-w-0 text-2xl font-semibold">{vault.name}</h2>
        <span className="pill shrink-0 font-mono text-muted">{vault.threshold}/{vault.members}</span>
      </div>
      <p className="eyebrow mb-2">Balance</p>
      <div className="mb-2 font-mono text-3xl font-semibold [overflow-wrap:anywhere] sm:text-4xl">
        {balance ? zatToTaz(balance.balance_zat) : "—"}
        <span className="ml-2 text-xl text-muted">TAZ</span>
      </div>
      {balance && <ProviderProvenance chain_trust={balance.chain_trust} />}

      {!balance && !balanceErr && (
        <p role="status" className="glass mb-4 rounded-2xl p-4 text-sm text-muted">Loading balance…</p>
      )}
      {balanceErr && (
        <div className="mb-4"><ErrMsg msg={needsTouchID ? balanceErr : balance ? "Balance could not refresh. The amount shown may be out of date. Retrying automatically." : "Balance is unavailable. Retrying automatically."} /></div>
      )}
      {loadErr && <div className="mb-4"><ErrMsg msg={loadErr} /></div>}
      {(loadErr || balanceErr || retrying) && <Btn variant="ghost" className="mb-4" disabled={retrying} onClick={retryDetails}>{retrying ? "Waiting for LokiSigner…" : needsTouchID ? "Retry Touch ID" : "Retry wallet details"}</Btn>}

      <div className="mb-5">
        <div className="mb-2 flex items-center gap-2">
          <h3 className="eyebrow">Approvals</h3>
          {pending && pending.length > 0 && (
            <span className="rounded-full bg-amber px-2 py-0.5 text-[11px] font-bold leading-none text-[var(--on-accent)]">{pending.length}</span>
          )}
        </div>
        {pendingError ? (
          <GlassCard>
            <ErrMsg msg={`Approval inbox unavailable: ${pendingError}${pending ? " Showing the last loaded requests." : ""}`} />
            <Btn variant="ghost" className="mt-3" onClick={() => { setPending(null); setPendingError(null); setPendingVersion((v) => v + 1); }}>Retry approval inbox</Btn>
          </GlassCard>
        ) : pending === null ? (
          <GlassCard className="py-6 text-center text-sm text-muted"><span role="status">Loading approval inbox…</span></GlassCard>
        ) : pending.length === 0 ? (
          <GlassCard className="flex items-center justify-center gap-2 py-6 text-center text-sm text-muted">
            <span className="text-mint">✓</span> No payments awaiting your approval
          </GlassCard>
        ) : (
          <GlassCard className="border-2 border-amber/60 bg-amber/10 ring-4 ring-amber/15">
            <div className="space-y-3">
              {pending.map((p) => (
                <div key={`${p.proposer}:${p.attempt}`} className="flex flex-col gap-3 border-b border-[var(--border)] pb-3 last:border-0 last:pb-0 sm:flex-row sm:items-center sm:justify-between">
                  <div className="min-w-0">
                    <p className="font-mono text-base font-semibold">{zatToTaz(p.amount_zat)} TAZ</p>
                    <p className="truncate font-mono text-[11px] text-muted">to {short(p.recipient, 12, 8)}</p>
                    <p className="mt-1 flex items-center gap-2 text-[11px] text-muted"><MemberAvatar slot={p.proposer} size={22} /> Proposed by Member {p.proposer}</p>
                    {p.replaces && <p className="mt-1 text-[11px] text-amber">{p.replaces.cancel ? "Cancels" : "Retries"} stuck payment {short(p.replaces.attempt, 6, 4)} with the same note</p>}
                  </div>
                  <button
                    onClick={() => onApprove(p)}
                    className="btn-primary shrink-0 rounded-full px-5 py-2.5 text-sm font-semibold"
                  >
                    Review &amp; approve →
                  </button>
                </div>
              ))}
            </div>
          </GlassCard>
        )}
      </div>

      <GlassCard className="mb-4">
        <Row label="Policy" value={`${vault.threshold} of ${vault.members}`} mono />
        <Row label="Vault ID" value={<FullValue value={vault.vault} label="vault ID" />} />
        {address && (
          <Row
            label="Address"
            value={
              <FullValue value={address} label="receive address" expanded={copyFailed} />
            }
          />
        )}
        {!address && !loadErr && <p role="status" className="mt-3 text-sm text-muted">Loading receive address…</p>}
        {signerKind() === "native" ? (
          <p className="mt-3 text-sm leading-relaxed text-muted">
            Open <strong>Vault addresses…</strong> in LokiSigner. Give senders the address copied from LokiSigner,
            or compare the full vault ID and address in both places before sharing the one shown here.
          </p>
        ) : (
          <>
            <p className="mt-3 text-sm leading-relaxed text-muted">
              Copy from the signer&apos;s own tab, or compare the full vault ID and address before sharing the address shown here.
            </p>
            <Btn variant="ghost" className="mt-3 text-sm" disabled={verifyingAddress} onClick={verifyAddress}>
              {verifyingAddress ? "Waiting for the signer…" : "Verify on signer"}
            </Btn>
            <ErrMsg msg={verifyError} />
          </>
        )}
      </GlassCard>

      {copyFailed && <ErrMsg msg="Copy failed. Expand and select the full receive address above to copy it manually." />}
      {address && (
        <div className={`mb-3 grid gap-3 ${address.startsWith("uregtest1") ? "sm:grid-cols-2" : "grid-cols-1"}`}>
          <button
            onClick={copy}
            className="btn-glass rounded-full px-4 py-3 text-sm"
          >
            {copied ? "✓ Copied" : "Copy address"}
          </button>
          {/* Regtest has an on-demand in-app faucet; testnet funds come from an external one. */}
          {address.startsWith("uregtest1") && (
            <button
              onClick={requestFunds}
              disabled={funding === "requesting"}
              className="btn-glass rounded-full px-4 py-3 text-sm text-amber disabled:opacity-60"
            >
              {funding === "requesting" ? "Funding…" : funding === "unconfirmed" ? "Check funding" : "Request test funds"}
            </button>
          )}
        </div>
      )}
      {funding === "unconfirmed" && (
        <p role="status" className="mb-4 text-sm text-muted">
          The faucet accepted the transfer, but it has not confirmed that it was mined.
          Checking funding again will reuse the same transfer request.
        </p>
      )}

      {/* Testnet has no in-app faucet: send the member to an external one with the address. */}
      {address && !address.startsWith("uregtest1") && (
        <a
          href="https://faucet.testnet.valargroup.dev"
          target="_blank"
          rel="noreferrer"
          className="btn-glass mb-3 block rounded-2xl px-5 py-3 text-center text-sm leading-relaxed text-amber sm:rounded-full"
        >
          Get testnet TAZ → copy the address above, paste it at the faucet
        </a>
      )}

      <div className="mb-4 grid grid-cols-2 gap-3">
        {signerKind() !== "browser" && <Btn variant="mint" onClick={onSend}>Send</Btn>}
        <Btn variant="ghost" onClick={onHistory}>History</Btn>
      </div>

      {signerKind() === "browser" ? <BrowserBackupCard vault={vault.vault} /> : <RecoveryCard vault={vault.vault} />}
    </div>
  );
}

// Download this vault's recovery backup from the in-browser signer: ciphertext only the 24
// words open, saved from the separate signer tab.
function BrowserBackupCard({ vault }: { vault: string }) {
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const save = async () => {
    setBusy(true); setErr(null);
    try { await exportRecoveryBackup(vault); setDone(true); }
    catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };
  return (
    <GlassCard className="mt-4">
      <h3 className="eyebrow mb-2">Recovery backup</h3>
      <p className="mb-3 text-xs text-muted">Keep this file with your 24 recovery words. Together they restore your share in a new browser.</p>
      <Btn variant="ghost" disabled={busy} onClick={save}>{busy ? "Waiting for the signer…" : done ? "Download again" : "Download recovery backup"}</Btn>
      <ErrMsg msg={err} />
    </GlassCard>
  );
}

// ─── recovery ───────────────────────────────────────────────────────────────

/** The member app exposes status and encrypted backups, not the recovery words. */
function RecoveryCard({ vault }: { vault: string }) {
  const [status, setStatus] = useState<RecoveryStatus | null>(null);
  const [exportFingerprint, setExportFingerprint] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const [statusError, setStatusError] = useState<string | null>(null);
  const [checking, setChecking] = useState(true);
  const refresh = useCallback(async () => {
    setChecking(true); setStatusError(null);
    try { setStatus(await recoveryStatus(vault)); }
    catch (e) { setStatusError((e as Error).message); }
    finally { setChecking(false); }
  }, [vault]);
  useEffect(() => { void refresh(); }, [refresh]);

  const inApp = status?.recovery_in_app === true;
  const download = async () => {
    setBusy(true); setErr(null); setExportFingerprint(null);
    try {
      const { vault: id, backup, fingerprint } = await recoveryBackup(vault);
      const url = URL.createObjectURL(new Blob([JSON.stringify({ vault: id, backup })], { type: "application/json" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = `loki-recovery-${vault}.json`;
      link.click();
      setExportFingerprint(fingerprint ?? null);
      setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };

  return (
    <GlassCard>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h3 className="eyebrow">Recovery</h3>
        <span className="text-xs text-muted">
          {checking ? "Checking recovery…" : statusError ? "Status unavailable" : status?.recovery_identity ? (status.recovery_backup ? "backed up" : "no vault backup yet") : "not set up"}
        </span>
      </div>

      {statusError && <div className="mb-3"><ErrMsg msg={`Could not check recovery: ${statusError}`} /><Btn variant="ghost" onClick={refresh}>Retry recovery status</Btn></div>}
      {checking && <p role="status" className="mb-3 text-sm text-muted">Loading recovery status…</p>}
      {status && (
        <div>
          {inApp ? (
            <>
              <p className="mb-2 text-xs text-muted">Use LokiSigner for recovery words and for restoring vaults. Never enter your words on this page.</p>
              <p className="mb-3 text-xs text-muted">Save the encrypted backup somewhere other than this Mac. If you lose this Mac without the file, the words alone cannot restore this vault.</p>
            </>
          ) : (
            <>
              <p className="mb-2 text-xs text-muted">Stop the member app before managing recovery. In the signer&apos;s private terminal, run <code>loki_member_app recovery-setup --data &lt;dir&gt;</code> to set up and confirm your words, or use <code>loki_member_app recovery-restore</code> with your backup and its fingerprint. Never enter your words on this page.</p>
              <p className="mb-3 text-xs text-muted">Save the encrypted backup off-device and separately record its SHA-256 fingerprint from the original signer. The words alone cannot restore this vault.</p>
            </>
          )}
          <Btn variant="ghost" disabled={busy || checking || !!statusError || !status?.recovery_backup} onClick={download}>
            {busy ? "Downloading…" : "Download encrypted backup"}
          </Btn>
          {exportFingerprint && <p role="status" className="mt-3 text-xs text-muted">
            Save this SHA-256 fingerprint separately for restore:<br />
            <code className="select-all break-all text-foreground">{exportFingerprint}</code>
          </p>}
        </div>
      )}
      <ErrMsg msg={err} />
    </GlassCard>
  );
}

// ─── send ─────────────────────────────────────────────────────────────────────

type DraftQuote = { attempt: string; fee_zat: string; change_zat: string };

function Send({
  vault,
  onBack,
  onDraft,
}: {
  vault: VaultSummary;
  onBack: () => void;
  onDraft: (attempt: string) => void;
}) {
  const [recipient, setRecipient] = useState("");
  const [amountTaz, setAmountTaz] = useState("");
  const [memo, setMemo] = useState("");
  const [draft, setDraft] = useState<(DraftQuote & { terms: Readonly<{ vault: string; recipient: string; amount_zat: string; memo: string }> }) | null>(null);
  const termsVersion = useRef(0);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const invalidateDraft = () => {
    termsVersion.current++;
    setDraft(null);
    setErr(null);
  };

  const prepareDraft = async () => {
    const version = termsVersion.current;
    setBusy(true); setErr(null);
    try {
      const taz = parseFloat(amountTaz);
      if (!Number.isFinite(taz) || taz <= 0) throw new Error("Enter a valid amount in TAZ.");
      const amount_zat = String(Math.round(taz * 1e8));
      const terms = { vault: vault.vault, recipient, amount_zat, memo };
      const quote = await api<DraftQuote>("payment-draft", terms);
      if (version === termsVersion.current) setDraft({ ...quote, terms });
    } catch (e) {
      if (version === termsVersion.current) setErr((e as Error).message);
    } finally { setBusy(false); }
  };

  const publish = async () => {
    if (!draft) return;
    setBusy(true); setErr(null);
    try {
      await api("payment-publish", { vault: draft.terms.vault, attempt: draft.attempt });
      onDraft(draft.attempt);
    } catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };

  return (
    <div>
      <BackLink onClick={onBack} />
      <h2 className="mb-6 text-2xl font-semibold">Send from {vault.name}</h2>
      <GlassCard className="mb-4 space-y-3">
        <label className="block text-xs text-muted">
          Recipient address
          <input
            placeholder="Recipient address"
            value={recipient}
            onChange={(e) => { setRecipient(e.target.value); invalidateDraft(); }}
            className="glass mt-1.5 w-full rounded-full px-5 py-3 font-mono outline-none"
          />
        </label>
        <label className="block text-xs text-muted">
          Amount (TAZ)
          <input
            placeholder="Amount (TAZ)"
            type="number"
            step="0.00000001"
            min="0"
            value={amountTaz}
            onChange={(e) => { setAmountTaz(e.target.value); invalidateDraft(); }}
            className="glass mt-1.5 w-full rounded-full px-5 py-3 font-mono outline-none"
          />
        </label>
        <label className="block text-xs text-muted">
          Memo (optional)
          <input
            placeholder="Memo (optional)"
            value={memo}
            onChange={(e) => { setMemo(e.target.value); invalidateDraft(); }}
            className="glass mt-1.5 w-full rounded-full px-5 py-3 outline-none"
          />
        </label>
      </GlassCard>

      {draft && (
        <GlassCard className="mb-4">
          <h3 className="eyebrow mb-3">Transaction summary</h3>
          <Row label="Recipient" value={short(draft.terms.recipient, 14, 10)} mono />
          <Row label="Amount" value={`${zatToTaz(draft.terms.amount_zat)} TAZ`} mono />
          <Row label="Fee" value={`${zatToTaz(draft.fee_zat)} TAZ`} mono />
          <Row label="Change" value={`${zatToTaz(draft.change_zat)} TAZ`} mono />
          {draft.terms.memo && <Row label="Memo" value={<span className="whitespace-pre-wrap">{draft.terms.memo}</span>} />}
        </GlassCard>
      )}

      {!draft ? (
        <Btn onClick={prepareDraft} disabled={!recipient || !amountTaz || busy}>
          {busy ? "Preparing…" : "Prepare →"}
        </Btn>
      ) : (
        <>
          <Btn variant="amber" onClick={publish} disabled={busy}>
            {busy ? "Requesting…" : "Request approvals"}
          </Btn>
          <p className="mt-2 text-center text-xs text-muted">
            Sends this exact payment to the group for approval. It only moves funds once the required members approve.
          </p>
        </>
      )}
      <ErrMsg msg={err} />
    </div>
  );
}

function SignerList({ signers, threshold, approvals = [], ready = false, complete = false }: { signers: number[]; threshold: number; approvals?: number[]; ready?: boolean; complete?: boolean }) {
  // Until the first approvals fix the signing group, any member may approve.
  const open = signers.length === 0;
  const recorded = new Set(approvals);
  const shown = new Set([...signers, ...recorded]);
  return <div className="my-3">
    <p className="text-xs text-muted">{ready ? "Signed · every member gets the transaction" : complete ? "Your signer finished · awaiting the signed transaction" : `${recorded.size} of ${threshold} approvals recorded here${open ? " · any member can approve" : ""}`}</p>
    <div className="mt-2 flex flex-wrap gap-2">
      {[...shown].map((slot) => <span key={slot} className="pill"><MemberAvatar slot={slot} size={24} /> Member {slot}{recorded.has(slot) ? " · approved" : " · proposed"}</span>)}
    </div>
  </div>;
}

// ─── review / approve ─────────────────────────────────────────────────────────

function ReviewApprove({
  profileId,
  proposedHere,
  vault,
  attempt,
  proposer,
  onBack,
}: {
  profileId?: string;
  proposedHere?: boolean;
  vault: VaultSummary;
  attempt: string;
  proposer?: number;
  onBack: () => void;
}) {
  const [review, setReview] = useState<PaymentReview | null>(null);
  const [session, setSession] = useState<PaymentSession | null>(null);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [ownSlot, setOwnSlot] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const triesRef = useRef(0);
  const approved = session?.approval_requested === true;

  const fetchSession = useCallback(async () => {
    try {
      const query = new URLSearchParams({ vault: vault.vault, attempt });
      if (proposer !== undefined) query.set("proposer", String(proposer));
      const value = await api<PaymentSession>(`payment-status?${query}`);
      setSession(value);
      setSessionError(null);
    } catch (e) { setSessionError((e as Error).message); }
  }, [vault.vault, attempt, proposer]);
  useEffect(() => {
    setOwnSlot(rememberedVaultSlot(profileId, vault.vault));
  }, [profileId, vault.vault]);
  useEffect(() => {
    void fetchSession();
    const timer = setInterval(fetchSession, 3000);
    return () => clearInterval(timer);
  }, [fetchSession]);

  const fetchReview = useCallback(async () => {
    try {
      const r = await api<PaymentReview>("payment-review", { vault: vault.vault, attempt, proposer });
      setReview(r);
      setErr(null);
    } catch (e) {
      // Early polls are expected to miss (the proposer may not have published yet); only after
      // ~15s of failures surface the error so the user isn't stranded on a forever-spinner.
      triesRef.current += 1;
      if (triesRef.current >= 10) setErr((e as Error).message);
    }
  }, [vault.vault, attempt, proposer]);

  useEffect(() => {
    if (approved) return;
    let active = true;
    triesRef.current = 0;
    setErr(null);
    fetchReview();
    const tick = () => {
      fetchReview().finally(() => {
        if (active) timerRef.current = setTimeout(tick, 1500);
      });
    };
    timerRef.current = setTimeout(tick, 1500);
    return () => { active = false; if (timerRef.current) clearTimeout(timerRef.current); };
  }, [approved, fetchReview]);

  const approve = async () => {
    if (!review) return;
    setBusy(true); setErr(null);
    try {
      await api("payment-approve", { vault: vault.vault, attempt, proposer, review_token: review.review_token, intent_hash: review.intent_hash });
      await fetchSession();
    } catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };

  const isProposer = proposedHere ?? (session && ownSlot !== null ? session.intent.proposer === ownSlot : null);

  if (session && ["confirmed", "replaced", "spent_unverified"].includes(session.phase)) {
    return (
      <GlassCard className="text-center">
        <h2 className="mb-2 text-2xl font-semibold">{paymentLabel(session.phase, false, false)}</h2>
        <p className="mb-4 text-sm text-muted">
          {session.phase === "confirmed" ? "The reported mined transaction matches this payment attempt." :
            session.phase === "replaced" ? "A different transaction was reported to have spent this payment’s input." :
              "This payment’s input was reported spent, but the spend hasn’t been matched to this payment."}
        </p>
        <ProviderProvenance chain_trust={session.chain_trust} />
        {session.approval_requested && <p className="mb-4 text-sm text-mint">You approved this payment.</p>}
        <Btn variant="ghost" onClick={onBack}>Back to History</Btn>
      </GlassCard>
    );
  }

  if (approved && session?.phase === "failed") {
    return (
      <GlassCard className="text-center">
        <div aria-hidden="true" className="mx-auto mb-4 grid h-14 w-14 place-items-center rounded-full bg-danger/10 text-3xl text-danger">✕</div>
        <h2 className="mb-2 text-2xl font-semibold text-danger">Payment signing failed</h2>
        <ErrMsg msg={session.error ?? null} />
        <p className="text-sm text-muted mb-8">Nothing was sent. Replace or discard it from History.</p>
        <Btn variant="ghost" onClick={onBack}>Back to History</Btn>
      </GlassCard>
    );
  }

  if (approved) {
    return (
      <GlassCard className="text-center">
        <div aria-hidden="true" className="mx-auto mb-4 grid h-14 w-14 place-items-center rounded-full bg-mint/10 text-3xl text-mint">✓</div>
        <h2 className="mb-2 text-2xl font-semibold text-mint">You approved this payment</h2>
        <ErrMsg msg={session?.error ?? null} />
        <p className="text-sm text-muted mb-8">
          It needs {vault.threshold} of {vault.members} members. Once enough have approved, the proposer builds the transaction, gives every member a copy, and sends it.
          {isProposer ? " You proposed this payment; this device sends it as soon as it is signed." : " Follow its progress in History. If it does not go out, any member holding the copy can send it."}
        </p>
        {session && <SignerList signers={session.intent.signers} threshold={vault.threshold} approvals={session.approvals} ready={session.signatures_received} complete={session.phase === "approved"} />}
        {sessionError && <><ErrMsg msg={`Could not refresh signer status: ${sessionError}`} /><Btn variant="ghost" onClick={fetchSession}>Retry signer status</Btn></>}
        <Btn variant="ghost" onClick={onBack}>Back to History</Btn>
      </GlassCard>
    );
  }

  if (!review) {
    return (
      <div>
        <BackLink onClick={onBack} />
        <GlassCard>
          <h2 className="text-2xl font-semibold">Review payment</h2>
          {err ? (
            <>
              <ErrMsg msg={`Couldn’t load this payment: ${err}`} />
              <p className="mt-3 text-sm text-muted">It may not exist yet, or the signer is unreachable. We’ll keep checking.</p>
              <Btn className="mt-3" variant="ghost" onClick={fetchReview}>Retry payment</Btn>
            </>
          ) : (
            <p role="status" className="mt-3 text-sm text-muted">Loading the payment to review…</p>
          )}
        </GlassCard>
      </div>
    );
  }

  return (
    <div>
      <BackLink onClick={onBack} />
      <h2 className="mb-1 text-2xl font-semibold">Approve payment</h2>
      <p className="mb-5 text-sm text-muted">
        from <span className="text-foreground">{vault.name}</span> · needs {vault.threshold} of {vault.members} approvals
      </p>
      {review.replaces && <GlassCard className="mb-4 border-2 border-amber/60 bg-amber/10">
        <p className="eyebrow mb-1 text-amber">{review.replaces.cancel ? "Cancels a stuck payment" : "Retries a stuck payment"}</p>
        <p className="text-sm">
          Replaces payment <span className="font-mono">{short(review.replaces.attempt, 8, 6)}</span>
          {review.replaces.amount_zat && review.replaces.recipient ? <> ({zatToTaz(review.replaces.amount_zat)} TAZ to <span className="font-mono">{short(review.replaces.recipient, 10, 6)}</span>)</> : null}.
        </p>
        <p className="mt-1 text-xs text-muted">
          It spends the same note, so only one of the two can ever be mined.{review.replaces.cancel ? " The note returns to the vault, less one fee." : ""}
        </p>
      </GlassCard>}
      <GlassCard className="mb-4">
        <div className="py-2 text-center">
          <p className="font-mono text-3xl font-semibold [overflow-wrap:anywhere] sm:text-4xl">
            {zatToTaz(review.amount_zat)} <span className="text-xl text-muted">TAZ</span>
          </p>
          <p className="eyebrow mt-3">Recipient</p>
          <p className="mt-1 font-mono text-xs break-all">{review.recipient}</p>
        </div>
        <div className="mt-3 border-t border-[var(--border)] pt-1">
          <Row label="Network fee" value={`${zatToTaz(review.fee_zat)} TAZ`} mono />
          {review.memo && <Row label="Memo" value={review.memo} />}
        </div>
      </GlassCard>
      {session ? <SignerList signers={session.intent.signers} threshold={vault.threshold} approvals={session.approvals} ready={session.signatures_received} complete={session.phase === "approved"} />
        : !sessionError && <p role="status" className="mb-3 text-xs text-muted">Loading signer approvals…</p>}
      {sessionError && <div className="mb-3"><ErrMsg msg={`Signer approvals unavailable: ${sessionError}`} /><Btn variant="ghost" onClick={fetchSession}>Retry signer list</Btn></div>}
      <p className="mb-3 text-center text-xs text-muted">
        Approving signs <span className="text-foreground">this exact payment</span> with your share.
        Check the amount and address first.
      </p>
      <Btn variant="amber" onClick={approve} disabled={busy || !!session?.error || (!!session && session.phase !== "signing")}>
        {busy ? "Approving…" : "Approve payment"}
      </Btn>
      <ErrMsg msg={err} />
    </div>
  );
}

// ─── history ──────────────────────────────────────────────────────────────────

const PHASE_PILL: Record<string, string> = {
  preparing: "border border-[var(--border)] bg-[var(--surface-2)] text-muted",
  approved: "bg-amber/15 text-amber",
  signed: "bg-amber/15 text-amber",
  broadcast: "bg-mint/15 text-mint",
  confirmed: "bg-mint text-[var(--on-accent)]",
  replaced: "border border-danger/40 bg-danger/10 text-danger",
};

/** Replace a stuck payment with a new request that spends exactly its note. */
function ReplacePanel({ vault, payment, onStarted }: {
  vault: VaultSummary; payment: Payment; onStarted: (attempt: string) => void;
}) {
  const [busy, setBusy] = useState<"retry" | "cancel" | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const start = async (mode: "retry" | "cancel") => {
    setBusy(mode); setErr(null);
    try {
      const draft = await api<{ attempt: string }>("payment-replace", { vault: vault.vault, attempt: payment.attempt, mode });
      await api("payment-publish", { vault: vault.vault, attempt: draft.attempt });
      onStarted(draft.attempt);
    } catch (e) { setErr((e as Error).message); }
    finally { setBusy(null); }
  };
  return <div className="mt-3 rounded-xl border border-amber/40 bg-amber/10 p-3">
    <p className="text-sm font-semibold text-amber">This payment looks stuck</p>
    <p className="mt-1 text-xs text-muted">
      Any member can replace it with a new request that spends the same note. It needs {vault.threshold} approvals.
      A note can be spent only once, so whichever transaction is mined first wins and the recipient is never paid twice.
    </p>
    <div className="mt-3 flex flex-col gap-2 sm:flex-row">
      <button className="btn-glass flex-1 rounded-full px-4 py-2 text-sm disabled:opacity-60" disabled={!!busy} onClick={() => start("retry")}>
        {busy === "retry" ? "Requesting…" : "Retry the same payment"}
      </button>
      <button className="btn-glass flex-1 rounded-full px-4 py-2 text-sm disabled:opacity-60" disabled={!!busy} onClick={() => start("cancel")}>
        {busy === "cancel" ? "Requesting…" : "Cancel · return the note to the vault (one fee)"}
      </button>
    </div>
    <ErrMsg msg={err} />
  </div>;
}

function History({
  vault,
  network,
  onReview,
  onBack,
}: {
  vault: VaultSummary;
  network?: StatusResponse["network"];
  onReview: (attempt: string) => void;
  onBack: () => void;
}) {
  const { data, error, refresh } = usePayments(vault.vault, true);
  const [sendingHere, setSendingHere] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  // Sends the signed transaction through this member's own lightwalletd, or sends it again.
  const send = async (attempt: string) => {
    setSendingHere(attempt); setErr(null);
    try {
      await api<{ phase: string; txid: string | null }>("payment-send", { vault: vault.vault, attempt });
      refresh();
    } catch (e) { setErr((e as Error).message); }
    finally { setSendingHere(null); }
  };

  const pending = data?.payments.find((p) => p.phase === "broadcast" && p.txid);
  const verifying = pending?.attempt;
  const verifyingTxid = pending?.txid;
  useEffect(() => {
    if (!verifying || !verifyingTxid) return;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let cancelled = false;
    let tries = 0;
    const tick = async () => {
      try {
        const res = await api<{ phase: string }>("payment-verify", { vault: vault.vault, attempt: verifying, txid: verifyingTxid });
        if (!cancelled && res.phase !== "broadcast") {
          refresh();
          return;
        }
      } catch {}
      tries += 1;
      // Cap at ~1min: the tx is broadcast and its id is shown; stop hammering the host if it's
      // slow to confirm (common on testnet) rather than polling forever and leaking timers.
      if (cancelled || tries >= 40) return;
      timer = setTimeout(tick, 1500);
    };
    timer = setTimeout(tick, 1500);
    return () => { cancelled = true; if (timer) clearTimeout(timer); };
  }, [verifying, verifyingTxid, vault.vault, refresh]);

  const payments = data?.payments ?? [];

  return (
    <div>
      <BackLink onClick={onBack} />
      <h2 className="mb-4 text-2xl font-semibold">History</h2>
      <ProviderProvenance chain_trust={data?.chain_trust} />

      {error && <div className="mb-4"><ErrMsg msg={error} /><Btn variant="ghost" onClick={refresh}>Retry history</Btn></div>}

      {!data ? (
        <GlassCard className="py-10 text-center text-sm text-muted">
          <p role="status">{error ? "History is unavailable. We’ll keep trying to reconnect." : "Loading payments…"}</p>
        </GlassCard>
      ) : payments.length === 0 ? (
        <GlassCard className="py-10 text-center text-sm text-muted">
          <p className="mb-2 font-display text-lg font-semibold text-foreground">No payments yet</p>
          <p>{emptyHistoryText(hasLokiSignerSession())}</p>
        </GlassCard>
      ) : (
        <div className="space-y-3">
          {payments.map((p) => {
            const confirmed = p.phase === "confirmed";
            const replaced = p.phase === "replaced";
            const unverified = p.phase === "spent_unverified";
            const txid = p.txid;
            const sending = !!p.sending || sendingHere === p.attempt;
            const settled = confirmed || replaced || unverified || ["cancelled", "expired"].includes(p.phase);
            return (
            <GlassCard key={p.attempt}>
              <div className="mb-2 flex flex-col items-start gap-3 sm:flex-row sm:justify-between">
                <div className="min-w-0">
                  <p className="eyebrow mb-1">{p.direction === "received" ? "Received" : p.amount_is_net ? "Net outflow" : p.replaces ? (p.replaces.cancel ? "Cancel request" : "Retry request") : confirmed ? "Sent" : "Payment proposal"}</p>
                  {p.recipient && <p className="font-mono text-xs text-muted break-all">{short(p.recipient, 14, 8)}</p>}
                  <p className="font-mono text-sm mt-0.5">{zatToTaz(p.amount_zat)} TAZ</p>
                  {p.fee_zat && <p className="mt-0.5 font-mono text-xs text-muted">+ fee {zatToTaz(p.fee_zat)} TAZ</p>}
                  {p.replaces && <p className="mt-1 text-xs text-muted">
                    Replaces payment {short(p.replaces.attempt, 6, 4)} with the same note{p.replaces.cancel ? "; the note goes back to the vault" : ""}.
                  </p>}
                </div>
                <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium shrink-0 ${PHASE_PILL[p.phase] ?? "border border-[var(--border)] bg-[var(--surface-2)] text-muted"}`}>
                  {paymentLabel(p.phase, false, sending && !settled)}
                </span>
              </div>
              {p.signers && !txid && !settled && <SignerList signers={p.signers} threshold={vault.threshold} approvals={p.approvals} complete={p.phase === "approved"} />}
              {replaced && <p className="text-xs text-muted">
                Another transaction was reported to have spent this payment’s note{p.spent_by ? ` (${short(p.spent_by, 8, 6)})` : ""}.
              </p>}
              {unverified && <p className="text-xs text-muted">
                This payment’s note was reported spent{p.spent_by ? ` (${short(p.spent_by, 8, 6)})` : ""}, but the spend hasn’t been matched to this attempt.
              </p>}
              {txid && !confirmed && p.phase === "signed" && <p className="text-xs text-muted">
                Signed by {vault.threshold} members. This device holds the final transaction{p.can_send ? " and can send it" : ""}.
              </p>}
              {txid && p.phase === "broadcast" && <p className="text-xs text-muted">
                Sent; awaiting a block. {p.can_send ? "This device holds the transaction and can send it again." : ""}
              </p>}
              <ErrMsg msg={settled ? null : p.error ?? null} />
              <div className="mt-3 flex flex-col gap-2 sm:flex-row">
                {p.phase === "signing" && !p.approval_requested && !p.error && <button
                  onClick={() => onReview(p.attempt)}
                  className="btn-glass flex-1 rounded-full px-4 py-2 text-sm"
                >
                  Review / approve
                </button>}
                {(p.can_discard || p.can_dismiss) && <button className="btn-glass flex-1 rounded-full px-4 py-2 text-sm" onClick={async () => {
                  setErr(null);
                  try { await api("payment-discard", { vault: vault.vault, attempt: p.attempt }); refresh(); }
                  catch (e) { setErr((e as Error).message); }
                }}>{p.can_dismiss ? "Dismiss on this device" : p.error || p.phase === "failed" ? "Discard failed payment" : "Cancel payment"}</button>}
                {(p.can_send || sending) && !settled && (
                  <button
                    onClick={() => send(p.attempt)}
                    disabled={sending}
                    className="btn-primary flex-1 rounded-full px-4 py-2 text-sm disabled:opacity-60"
                  >
                    {sending ? "Sending…" : p.phase === "broadcast" ? "Send again" : "Send now"}
                  </button>
                )}
                {txid && (
                  <button
                    onClick={() => { navigator.clipboard?.writeText(txid).catch(() => {}); }}
                    title={`Copy transaction id: ${txid}`}
                    aria-label={`Copy transaction ID ${txid}`}
                    className="btn-glass min-w-0 flex-1 rounded-2xl px-3 py-2 text-center font-mono text-xs leading-relaxed text-mint [overflow-wrap:anywhere]"
                  >
                    {confirmed
                      ? `✓ Confirmed${p.mined_height ? ` · block ${p.mined_height.toLocaleString()}` : ""}`
                      : p.phase === "signed" ? "Not sent yet" : "Awaiting confirmation"} · {short(txid, 8, 6)} ⧉
                  </button>
                )}
              </div>
              {p.can_replace && <ReplacePanel vault={vault} payment={p} onStarted={onReview} />}
              {txid && confirmed && (
                <p className="mt-1.5 text-center text-[11px] text-muted">
                  Reported mined{p.mined_height ? ` at block ${p.mined_height.toLocaleString()}` : ""}.{" "}
                  {network === "testnet" && <><a href={`https://testnet.zecblock.com/tx/${txid}`} target="_blank" rel="noreferrer" className="text-mint underline">View on ZecBlock ↗</a>.{" "}</>}
                  Tap the id to copy.
                </p>
              )}
            </GlassCard>
            );
          })}
        </div>
      )}
      <ErrMsg msg={err} />
    </div>
  );
}
