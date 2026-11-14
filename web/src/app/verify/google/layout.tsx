import type { Metadata } from "next";

// the page URL carries Google's one-time code: it is never sent on as a referrer
export const metadata: Metadata = { referrer: "no-referrer", robots: { index: false } };

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
