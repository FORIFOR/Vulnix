export const osvSources = ["npm", "PyPI", "Go"] as const;
export type CatalogSource = (typeof osvSources)[number] | `NVD-${number}`;

export function catalogSources(year = new Date().getUTCFullYear()): CatalogSource[] {
  return [...osvSources, ...Array.from({ length: year - 2001 }, (_, i): CatalogSource => `NVD-${year - i}`)];
}

export function catalogSource(value: string | null): CatalogSource | undefined {
  return catalogSources().find((source) => source === value);
}
