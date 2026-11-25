import type { CatalogSource } from "./catalogUpdate";

const manifests = "catalog-manifests";
const records = "catalog-records";
const legacyStore = "public-catalogs";
const limitRecord = 4 * 1024 * 1024;
const limitTransfer = 384 * 1024 * 1024;
const maximumRows = 400_000;
const writeBatch = 256;
const idPattern = /^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$/;

export type CatalogManifest = {
  source: CatalogSource; generation: string; count: number; indexed: number;
  fetchedAt: string; publishedAt: string | null;
};
type LegacyCatalog = Partial<Record<"NVD" | "npm" | "PyPI" | "Go", { records?: unknown[] }>>;
type CatalogRow = { key: string; keys: string[]; payload: string };

function database() {
  return new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open("vulnix-advisories", 2);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(legacyStore)) db.createObjectStore(legacyStore);
      db.createObjectStore(manifests, { keyPath: "source" });
      db.createObjectStore(records, { keyPath: "key" }).createIndex("lookup", "keys", { multiEntry: true });
    };
    request.onsuccess = () => {
      request.result.onversionchange = () => request.result.close();
      resolve(request.result);
    };
    request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error("catalog cache busy"));
  });
}

function result<T>(request: IDBRequest<T>) {
  return new Promise<T>((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function committed(tx: IDBTransaction) {
  return new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(tx.error ?? new Error("catalog transaction aborted"));
  });
}

const obj = (value: unknown) => value && typeof value === "object" ? value as Record<string, unknown> : {};
const list = (value: unknown) => Array.isArray(value) ? value.map(obj) : [];
export const cpeKey = (part: string, vendor: string, product: string) => `cpe:${part}:${vendor}:${product}`;
export const packageKey = (ecosystem: string, name: string) =>
  `${ecosystem}:${ecosystem === "PyPI" ? name.toLowerCase().replace(/[-_.]+/g, "-") : name}`;

function indexedRow(source: CatalogSource, generation: string, payload: string, entry: Record<string, unknown>): CatalogRow | null {
  const nvd = source.startsWith("NVD-");
  const cve = obj(entry.cve);
  const id = nvd ? cve.id : entry.id;
  if (typeof id !== "string" || !idPattern.test(id)) throw new Error("invalid advisory identity");
  if (entry.withdrawn || cve.vulnStatus === "Rejected" || cve.vulnStatus === "Disputed") return null;
  const keys = new Set<string>();
  if (nvd) {
    for (const config of list(cve.configurations)) for (const node of list(config.nodes)) for (const match of list(node.cpeMatch)) {
      if (match.vulnerable !== true || typeof match.criteria !== "string") continue;
      const parsed = /^cpe:2\.3:([aho]):([\w.-]+):([\w.-]+):/.exec(match.criteria);
      if (parsed) keys.add(cpeKey(parsed[1], parsed[2], parsed[3]));
    }
  } else {
    for (const affected of list(entry.affected)) {
      const pkg = obj(affected.package);
      if (pkg.ecosystem === source && typeof pkg.name === "string" && pkg.name.length <= 512)
        keys.add(packageKey(source, pkg.name));
    }
  }
  if (keys.size > 8000) throw new Error("advisory index limit");
  const prefix = `${source}/${generation}/`;
  return keys.size ? { key: prefix + id, keys: [...keys].map((key) => prefix + key), payload } : null;
}

export async function readCatalogCache() {
  const db = await database();
  try {
    const tx = db.transaction([manifests, legacyStore]);
    const [sources, legacy] = await Promise.all([
      result<CatalogManifest[]>(tx.objectStore(manifests).getAll()),
      result<LegacyCatalog | undefined>(tx.objectStore(legacyStore).get("official")),
    ]);
    return { sources, legacy: legacy ?? {} };
  } finally { db.close(); }
}

function prefixRange(prefix: string) {
  return IDBKeyRange.bound(prefix, prefix + "\uffff");
}

async function writeRows(db: IDBDatabase, rows: CatalogRow[]) {
  const tx = db.transaction(records, "readwrite");
  const done = committed(tx);
  for (const row of rows) tx.objectStore(records).put(row);
  await done;
}

async function removeStaged(db: IDBDatabase, source: CatalogSource, keep?: string) {
  const prefix = `${source}/`;
  const tx = db.transaction(records, "readwrite");
  const done = committed(tx);
  const store = tx.objectStore(records);
  if (keep) {
    store.delete(IDBKeyRange.bound(prefix, `${prefix}${keep}/`, false, true));
    store.delete(IDBKeyRange.bound(`${prefix}${keep}/\uffff`, `${prefix}\uffff`, true));
  } else store.delete(prefixRange(prefix));
  await done;
}

export async function refreshCatalogs(sources: CatalogSource[], onProgress: (source: CatalogSource, count: number) => void) {
  if (!navigator.locks) throw new Error("catalog browser lock unavailable");
  return navigator.locks.request("vulnix-catalog-refresh", { ifAvailable: true }, async (lock) => {
    if (!lock) throw new Error("catalog already updating");
    const db = await database();
    const failed: CatalogSource[] = [];
    const deadline = Date.now() + 25 * 60_000;
    try {
      for (const source of sources) {
        if (Date.now() >= deadline) { failed.push(source); continue; }
        onProgress(source, 0);
        const generation = crypto.randomUUID();
        const old = await result<CatalogManifest | undefined>(db.transaction(manifests).objectStore(manifests).get(source));
        try {
          await removeStaged(db, source, old?.generation);
          const response = await fetch("/api/catalog/refresh", { method: "POST",
            headers: { "X-Aegis-Request": "1", "X-Vulnix-Catalog": source }, redirect: "error",
            signal: AbortSignal.timeout(Math.min(9 * 60_000, deadline - Date.now())),
          });
          if (!response.ok || !response.body) throw new Error("catalog download failed");
          const metadata = await importStream(db, source, generation, response.body, onProgress);
          const tx = db.transaction(manifests, "readwrite");
          const done = committed(tx);
          tx.objectStore(manifests).put(metadata);
          await done;
          await removeStaged(db, source, generation).catch(() => {});
        } catch {
          failed.push(source);
          await removeStaged(db, source, old?.generation).catch(() => {});
        }
      }
    } finally { db.close(); }
    return failed;
  });
}

async function importStream(db: IDBDatabase, source: CatalogSource, generation: string,
  stream: ReadableStream<Uint8Array>, onProgress: (source: CatalogSource, count: number) => void): Promise<CatalogManifest> {
  const reader = stream.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const rows: CatalogRow[] = [];
  let total = 0;
  let count = 0;
  let indexed = 0;
  let batchSize = 0;
  let lineBuffer = "";
  let publishedAt: string | null = null;
  let complete = false;
  try {
    while (true) {
      const { value, done } = await reader.read();
      total += value?.byteLength ?? 0;
      if (total > limitTransfer) throw new Error("catalog transfer limit");
      lineBuffer += decoder.decode(value, { stream: !done });
      let offset = 0;
      let next: number;
      while ((next = lineBuffer.indexOf("\n", offset)) !== -1) {
        const line = lineBuffer.slice(offset, next);
        offset = next + 1;
        if (complete || line.length > limitRecord) throw new Error("invalid catalog record boundary");
        const entry = obj(JSON.parse(line));
        if ("complete" in entry) {
          if (entry.complete !== count || !count) throw new Error("catalog count mismatch");
          if (typeof entry.publishedAt === "string" && Number.isFinite(Date.parse(entry.publishedAt)))
            publishedAt = new Date(entry.publishedAt).toISOString();
          complete = true;
          continue;
        }
        if (++count > maximumRows) throw new Error("catalog record count limit");
        const row = indexedRow(source, generation, line, entry);
        if (row) {
          rows.push(row);
          indexed++;
          batchSize += line.length;
        }
        if (rows.length >= writeBatch || batchSize >= limitRecord) {
          await writeRows(db, rows.splice(0));
          batchSize = 0;
          onProgress(source, count);
        }
      }
      lineBuffer = lineBuffer.slice(offset);
      if (lineBuffer.length > limitRecord) throw new Error("catalog line limit");
      if (done) break;
    }
    if (!complete || lineBuffer) throw new Error("catalog stream was incomplete");
    if (rows.length) await writeRows(db, rows);
    return { source, generation, count, indexed, fetchedAt: new Date().toISOString(), publishedAt };
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

export async function findCatalogRecords(packageKeys: string[], cpeKeys: string[], deadline: number) {
  const db = await database();
  try {
    const tx = db.transaction([manifests, records]);
    const catalog: CatalogManifest[] = await result(tx.objectStore(manifests).getAll());
    const lookup = tx.objectStore(records).index("lookup");
    const seen = new Set<string>();
    const osv: string[] = [];
    const vulnerabilities: string[] = [];
    const matches = (incomplete: boolean) => ({ osv: osv.map((row) => JSON.parse(row) as unknown),
      vulnerabilities: vulnerabilities.map((row) => JSON.parse(row) as unknown), incomplete });
    let bytes = 0;
    for (const snapshot of catalog) {
      const nvd = snapshot.source.startsWith("NVD-");
      const keys = nvd ? cpeKeys : packageKeys.filter((key) => key.startsWith(`${snapshot.source}:`));
      const destination = nvd ? vulnerabilities : osv;
      for (const key of keys) {
        if (performance.now() >= deadline) return matches(true);
        const withinLimit = await new Promise<boolean>((resolve, reject) => {
          const cursor = lookup.openCursor(`${snapshot.source}/${snapshot.generation}/${key}`);
          cursor.onerror = () => reject(cursor.error);
          cursor.onsuccess = () => {
            const row = cursor.result;
            if (!row) { resolve(true); return; }
            const { key, payload }: CatalogRow = row.value;
            if (!seen.has(key)) {
              bytes += payload.length;
              if (bytes > 16 * 1024 * 1024 || seen.size >= 12000 || performance.now() >= deadline) {
                resolve(false);
                return;
              }
              seen.add(key);
              destination.push(payload);
            }
            row.continue();
          };
        });
        if (!withinLimit) return matches(true);
      }
    }
    return matches(false);
  } finally { db.close(); }
}
