import { parseDocument } from "yaml";

export interface CloudProject {
  id: string;
  number: string;
  label: string;
}

export interface CloudRunService {
  name: string;
  url: string;
  revision: string | null;
  images: string[];
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

const label = (v: unknown, max: number) => typeof v === "string" && v.length <= max ? v : "";
export const cloudExportLimit = 256 * 1024;

/** Read only the selection and deployment metadata. Environment variables and
 * identities from the console export are discarded; the export never leaves the browser. */
export function importCloudRunService(text: string, project: CloudProject): CloudRunService {
  if (new TextEncoder().encode(text).length > cloudExportLimit) throw new Error("256 KB以下のサービス定義を選択してください。");
  let raw: Record<string, unknown>;
  try {
    const doc = parseDocument(text, { schema: "core", uniqueKeys: true });
    if (doc.errors.length || doc.warnings.length) throw new Error("invalid YAML");
    raw = record(doc.toJS({ maxAliasCount: 0 }));
  } catch {
    throw new Error("Cloud Runのサービス定義を読み取れません。コンソールからコピーし直してください。");
  }
  const metadata = record(raw.metadata);
  const status = record(raw.status);
  const resource = /^projects\/([^/]+)\/locations\/[a-z0-9-]+\/services\/([a-z0-9-]+)$/.exec(label(raw.name, 256));
  const knative = raw.apiVersion === "serving.knative.dev/v1" && raw.kind === "Service";
  const namespace = resource?.[1] ?? (knative ? label(metadata.namespace, 30) : "");
  if (![project.number, project.id].includes(namespace)) {
    throw new Error("このサービス定義は選択したプロジェクトと一致しません。コンソールのプロジェクトを確認してください。");
  }
  const name = resource?.[2] ?? label(metadata.name, 63);
  if (!/^[a-z][a-z0-9-]{0,62}$/.test(name)) throw new Error("Cloud Runのサービス名を確認できません。");
  let url: URL;
  try {
    url = new URL(label(resource ? raw.uri : status.url, 512));
    if (url.protocol !== "https:" || !/^[a-z0-9-]+(?:\.[a-z0-9-]+)?\.run\.app$/.test(url.hostname) || url.username ||
        url.password || url.port || url.pathname !== "/" || url.search || url.hash) throw new Error("invalid");
  } catch {
    throw new Error("Cloud Runの既定HTTPS URLを確認できません。独自ドメインはURL入力から登録してください。");
  }
  const revision = label(resource ? raw.latestReadyRevision : status.latestReadyRevisionName, 300).split("/").at(-1);
  const template = resource ? record(raw.template) : record(record(record(raw.spec).template).spec);
  const images = Array.isArray(template.containers)
    ? template.containers.slice(0, 20).flatMap((c) => {
      const image = label(record(c).image, 512);
      return image && /^[A-Za-z0-9._:@/-]+$/.test(image) ? [image] : [];
    }) : [];
  return { name, url: url.origin, revision: revision && /^[a-z0-9-]{1,63}$/.test(revision) ? revision : null, images };
}
