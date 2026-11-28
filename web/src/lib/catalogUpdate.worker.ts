import { refreshCatalogs } from "./catalogCache";
import type { CatalogSource } from "./catalogUpdate";

self.onmessage = async ({ data }: MessageEvent<CatalogSource[]>) => {
  try {
    const failed = await refreshCatalogs(data, (source, count) => self.postMessage({ progress: { source, count } }));
    self.postMessage({ failed });
  } catch {
    self.postMessage({ error: true });
  }
};
