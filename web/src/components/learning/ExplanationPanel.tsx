"use client";

import { useState } from "react";
import { GLOSSARY } from "@/lib/glossary";

const LEVELS = [
  { key: "easy", label: "かんたん" },
  { key: "detail", label: "詳しく" },
  { key: "expert", label: "専門家" },
] as const;

export function ExplanationPanel({ term, context }: { term: string; context?: string }) {
  const [level, setLevel] = useState<(typeof LEVELS)[number]["key"]>("easy");
  const t = GLOSSARY[term];
  if (!t) return null;
  return (
    <div>
      <div className="mb-2 flex items-center justify-between gap-2">
        <span className="font-semibold">{t.title}</span>
        <span className="rounded bg-violet-100 px-1.5 py-0.5 text-[11px] text-violet-800 dark:bg-violet-900/50 dark:text-violet-200">
          学習
        </span>
      </div>
      <div role="tablist" className="mb-3 grid grid-cols-3 rounded-lg bg-zinc-100 p-0.5 text-xs dark:bg-zinc-800">
        {LEVELS.map((l) => (
          <button
            key={l.key}
            role="tab"
            aria-selected={level === l.key}
            onClick={() => setLevel(l.key)}
            className={`rounded-md py-1 ${level === l.key ? "bg-white font-semibold shadow-sm dark:bg-zinc-700" : "text-zinc-600 dark:text-zinc-400"}`}
          >
            {l.label}
          </button>
        ))}
      </div>
      <p className="leading-relaxed">{t[level]}</p>
      {context && (
        <p className="mt-3 rounded-lg bg-zinc-50 p-2 text-xs leading-relaxed text-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300">
          <span className="font-semibold">この診断では：</span>
          {context}
        </p>
      )}
      <button
        disabled
        title="AIチャットは未接続です（P1）"
        className="mt-3 w-full cursor-not-allowed rounded-lg border border-dashed border-zinc-300 py-1.5 text-xs text-zinc-500 dark:border-zinc-600"
      >
        AIに質問する（未接続）
      </button>
    </div>
  );
}
