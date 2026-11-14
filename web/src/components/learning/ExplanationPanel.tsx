"use client";

import { useEffect, useState } from "react";
import { command } from "@/lib/api";
import { GLOSSARY } from "@/lib/glossary";
import { recordLearning, type LearnLevel } from "@/lib/learningHistory";
import { SafeMarkdown } from "../SafeMarkdown";

const LEVELS: { key: LearnLevel; label: string }[] = [
  { key: "easy", label: "かんたん" },
  { key: "detail", label: "詳しく" },
  { key: "expert", label: "専門家" },
];

export function ExplanationPanel({
  term,
  context,
  findingId,
  assessmentId = "scan_001",
}: {
  term: string;
  context?: string;
  findingId?: string;
  assessmentId?: string;
}) {
  const [level, setLevel] = useState<LearnLevel>("easy");
  const [aiAnswer, setAiAnswer] = useState<string | null>(null);
  const [answerActor, setAnswerActor] = useState("診断コンテキスト解説");
  const [fromModel, setFromModel] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const t = GLOSSARY[term];

  useEffect(() => {
    if (t) recordLearning(term, t.title, level);
  }, [term, t, level]);

  if (!t) return null;

  const askAi = async () => {
    setBusy(true);
    setErr(null);
    try {
      const res = (await command(`/api/assessments/${assessmentId}/chat`, {
        question: `「${t.title}」について、この診断でなぜ検出されたのか、どの証拠から判断したのか、修正後にどう確認するのかを教えてください。`,
        term,
        finding_id: findingId,
      })) as { message?: { text: string; actor?: string; source?: string } };
      setAnswerActor(res.message?.actor ?? "診断コンテキスト解説");
      setFromModel(res.message?.source === "external_model");
      setAiAnswer(res.message?.text ?? "回答を取得しました。診断タブのチャット欄でも確認できます。");
      recordLearning(term, t.title, level, true);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

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
      {aiAnswer && (
        <div className="mt-3 rounded-lg border border-violet-200 bg-violet-50/70 p-2.5 text-xs leading-relaxed text-zinc-800 dark:border-violet-800 dark:bg-violet-950/40 dark:text-zinc-200">
          <div className="mb-1 font-semibold text-violet-900 dark:text-violet-300">{answerActor}</div>
          {fromModel ? <SafeMarkdown text={aiAnswer} /> : <div className="whitespace-pre-wrap">{aiAnswer}</div>}
        </div>
      )}
      {err && <p role="alert" className="mt-2 text-xs text-red-700 dark:text-red-300">{err}</p>}
      <button
        type="button"
        disabled={busy}
        onClick={askAi}
        className="mt-3 w-full rounded-lg border border-zinc-300 py-1.5 text-xs font-semibold text-zinc-800 hover:bg-zinc-100 disabled:opacity-50 dark:border-zinc-600 dark:text-zinc-100 dark:hover:bg-zinc-800"
      >
        {busy ? "解説を取得中…" : "診断について質問する（原因・証拠・対策）"}
      </button>
    </div>
  );
}
