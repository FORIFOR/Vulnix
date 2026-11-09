export type LearnLevel = "easy" | "detail" | "expert";

export interface LearningEntry {
  term: string;
  title: string;
  level: LearnLevel;
  askedAi?: boolean;
  ts: number;
}

const KEY = "vulnix-learning-history";
const EMPTY: LearningEntry[] = [];
let cacheRaw: string | null = null;
let cacheParsed: LearningEntry[] = EMPTY;
const listeners = new Set<() => void>();

export function subscribeLearning(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

export function getLearningSnapshot(): LearningEntry[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return EMPTY;
    if (raw === cacheRaw) return cacheParsed;
    cacheRaw = raw;
    cacheParsed = JSON.parse(raw) as LearningEntry[];
    return cacheParsed;
  } catch {
    return EMPTY;
  }
}

export function getLearningServerSnapshot(): LearningEntry[] {
  return EMPTY;
}

export function recordLearning(term: string, title: string, level: LearnLevel, askedAi = false): void {
  try {
    const cur = getLearningSnapshot().filter((e) => !(e.term === term && e.level === level));
    const next: LearningEntry[] = [
      { term, title, level, askedAi, ts: Math.floor(Date.now() / 1000) },
      ...cur,
    ].slice(0, 30);
    const raw = JSON.stringify(next);
    localStorage.setItem(KEY, raw);
    cacheRaw = raw;
    cacheParsed = next;
    listeners.forEach((cb) => cb());
  } catch {
    /* ignore storage restrictions */
  }
}

export function clearLearningHistory(): void {
  try {
    localStorage.removeItem(KEY);
    cacheRaw = null;
    cacheParsed = EMPTY;
    listeners.forEach((cb) => cb());
  } catch {
    /* ignore */
  }
}
