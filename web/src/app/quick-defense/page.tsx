import { readFileSync } from "node:fs";
import { join } from "node:path";
import QuickDefense from "./QuickDefense";

export default function QuickDefensePage() {
  const bundledFeed: unknown = JSON.parse(
    readFileSync(join(process.cwd(), "..", "aegis", "feeds", "nvd-recent.json"), "utf8"),
  );
  return <QuickDefense bundledFeed={bundledFeed} />;
}
