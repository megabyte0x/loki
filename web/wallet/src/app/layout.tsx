import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { signerOrigin } from "../lib/signer-config";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Loki — Shielded Multisig",
  description: "A shielded Zcash multisig wallet.",
};

// Render the shell per-request so a deploy is reflected immediately — never serve a
// statically-cached HTML that pins returning visitors to an old build's chunks.
export const dynamic = "force-dynamic";

/** The signer origin from the server's runtime configuration, or none (the signer then fails closed). */
function runtimeSignerOrigin(): string | undefined {
  try { return signerOrigin(); } catch { return undefined; }
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const origin = runtimeSignerOrigin();
  return (
    <html
      lang="en"
      // The pre-paint script below sets data-theme before React hydrates.
      suppressHydrationWarning
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <head>
        {/* The signer iframe's origin, chosen by server configuration only (signer.ts reads it). */}
        {origin && <meta name="loki-signer-origin" content={origin} />}
        {/* Apply a pinned theme before paint so a light pin on a dark system (or vice versa)
            doesn't flash. Unpinned users fall through to CSS prefers-color-scheme. */}
        <script
          dangerouslySetInnerHTML={{
            __html:
              "try{var t=localStorage.getItem('loki_theme');if(t==='light'||t==='dark')document.documentElement.setAttribute('data-theme',t)}catch(e){}",
          }}
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
