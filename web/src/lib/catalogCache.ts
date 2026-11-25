import type { CatalogSource, CatalogUpdate } from "./catalogUpdate";

export type OfficialCatalog = Partial<Record<CatalogSource, CatalogUpdate>>;
const store = "public-catalogs";

async function database() {
  return new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open("vulnix-advisories", 1);
    request.onupgradeneeded = () => request.result.createObjectStore(store);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error("catalog cache busy"));
  });
}

export async function readCatalogCache(): Promise<OfficialCatalog> {
  const db = await database();
  try {
    return await new Promise((resolve, reject) => {
      const request = db.transaction(store).objectStore(store).get("official");
      request.onsuccess = () => resolve(request.result ?? {});
      request.onerror = () => reject(request.error);
    });
  } finally { db.close(); }
}

export async function writeCatalogCache(catalog: OfficialCatalog): Promise<void> {
  const db = await database();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = db.transaction(store, "readwrite");
      transaction.oncomplete = () => resolve();
      transaction.onabort = () => reject(transaction.error);
      transaction.objectStore(store).put(catalog, "official");
    });
  } finally { db.close(); }
}
