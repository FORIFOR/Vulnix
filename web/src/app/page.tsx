import { redirect } from "next/navigation";
import { Landing } from "@/components/landing/Landing";

export const dynamic = "force-dynamic";

// Public instance (VULNIX_PUBLIC_MODE=1): the landing page. Local operator instance:
// straight to the dashboard, as before (the landing page is at /welcome there).
export default function Home() {
  if (process.env.VULNIX_PUBLIC_MODE === "1") return <Landing />;
  redirect("/dashboard");
}
