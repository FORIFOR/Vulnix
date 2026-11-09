import type { Metadata } from "next";
import { SessionProvider } from "@/components/layout/SessionProvider";
import { Shell } from "@/components/layout/Shell";
import { THEME_SCRIPT } from "@/lib/theme";
import "./globals.css";

export const metadata: Metadata = {
  title: "Vulnix — Find. Prove. Secure. | AI Security Testing Platform",
  description: "許可された範囲で、検出・実証・防御の検証を証拠付きで行う AI Security Testing Platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ja" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
      </head>
      <body>
        <SessionProvider>
          <Shell>{children}</Shell>
        </SessionProvider>
      </body>
    </html>
  );
}
