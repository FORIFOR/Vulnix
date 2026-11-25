// This module runs on the server. No project data is accepted or forwarded.
const NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const OSV = "https://osv-vulnerabilities.storage.googleapis.com";
export const catalogSources = ["NVD", "npm", "PyPI", "Go"] as const;
export type CatalogSource = (typeof catalogSources)[number];
export type CatalogUpdate = { source: CatalogSource; fetchedAt: string; scope: string; records?: unknown[]; failed?: boolean };

async function bounded(url: string, size: number, fetcher: typeof fetch, prefix = false): Promise<string> {
  const response = await fetcher(url, {
    cache: "no-store", redirect: "error",
    headers: prefix ? { Range: `bytes=0-${size - 1}` } : {},
    signal: AbortSignal.timeout(sourceTimeoutMs),
  });
  if (!response.ok || !response.body) throw new Error("source unavailable");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let text = "";
  let read = 0;
  try {
    while (read < size || !prefix) {
      const chunk = await reader.read();
      if (chunk.done) return text + decoder.decode();
      const allowed = size - read;
      if (!prefix && chunk.value.length > allowed) throw new Error("size limit");
      text += decoder.decode(chunk.value.subarray(0, allowed), { stream: true });
      read += Math.min(allowed, chunk.value.length);
    }
    return text.slice(0, text.lastIndexOf("\n") + 1);
  } finally {
    await reader.cancel().catch(() => {});
  }
}
const sourceTimeoutMs = 9000;

export async function fetchCatalogs(fetcher: typeof fetch = fetch, now = new Date()): Promise<CatalogUpdate[]> {
  const fetchedAt = now.toISOString();
  const nvdScope = "公開7日以内の先頭100件";
  const osvScope = "更新索引の先頭64 KiBから最大8勧告";
  return Promise.all(catalogSources.map(async (source): Promise<CatalogUpdate> => {
    const scope = source === "NVD" ? nvdScope : osvScope;
    try {
      if (source === "NVD") {
        const params = new URLSearchParams({
          pubStartDate: new Date(now.getTime() - 7 * 86400000).toISOString(),
          pubEndDate: fetchedAt, resultsPerPage: "100",
        });
        const data = JSON.parse(await bounded(`${NVD}?${params}`, 5 * 1024 * 1024, fetcher));
        if (data?.format !== "NVD_CVE" || !Array.isArray(data.vulnerabilities) || data.vulnerabilities.length > 100)
          throw new Error("invalid NVD response");
        return { source, fetchedAt, scope: `${scope}（該当総数 ${Number.isSafeInteger(data.totalResults) ? data.totalResults : "不明"}）`,
          records: data.vulnerabilities };
      }
      const index = await bounded(`${OSV}/${source}/modified_id.csv`, 64 * 1024, fetcher, true);
      const ids = [...new Set(index.split("\n").flatMap((line) => {
        const match = line.trim().match(/^\d{4}-\d{2}-\d{2}T[^,]*,((?:GHSA|GO|PYSEC|CVE)-[A-Za-z0-9-]{1,70})$/);
        return match ? [match[1]] : [];
      }))].slice(0, 8);
      if (!ids.length) throw new Error("no OSV records");
      const records = await Promise.all(ids.map(async (id) => {
        const data = JSON.parse(await bounded(`${OSV}/${source}/${id}.json`, 256 * 1024, fetcher));
        if (data?.id !== id || (!data.withdrawn && !Array.isArray(data.affected))) throw new Error("invalid OSV response");
        return data;
      }));
      return { source, fetchedAt, scope, records };
    } catch {
      return { source, fetchedAt, scope, failed: true };
    }
  }));
}
