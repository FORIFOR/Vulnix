import { findCatalogRecords } from "./catalogCache";
import { scanProject, type ProjectFile } from "./projectDefense";

self.onmessage = async ({ data }: MessageEvent<{ files: ProjectFile[]; feed: unknown }>) => {
  try {
    self.postMessage({ result: await scanProject(data.files, data.feed, (progress) => self.postMessage({ progress }), findCatalogRecords) });
  } catch {
    self.postMessage({ error: true });
  }
};
