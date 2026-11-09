"use client";

import { useEffect, useId, useRef, useState } from "react";
import { GLOSSARY } from "@/lib/glossary";
import { ExplanationPanel } from "./ExplanationPanel";

/** The "？" button. Opens a 3-level explanation tied to the current screen. */
export function HelpPopover({ term, context }: { term: string; context?: string }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);
  const id = useId();
  const t = GLOSSARY[term];

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  if (!t) return null;
  return (
    <span ref={ref} className="relative inline-flex align-middle">
      <button
        type="button"
        aria-label={`${t.title}の解説`}
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen((o) => !o)}
        className="ml-1 inline-flex h-5 w-5 items-center justify-center rounded-full border border-zinc-300 text-[11px] font-semibold text-zinc-600 hover:bg-zinc-100 dark:border-zinc-600 dark:text-zinc-300 dark:hover:bg-zinc-800"
      >
        ？
      </button>
      {open && (
        <div
          id={id}
          role="dialog"
          aria-label={t.title}
          className="absolute left-1/2 top-7 z-50 w-[min(22rem,calc(100vw-2rem))] -translate-x-1/2 rounded-xl border border-zinc-200 bg-white p-4 text-left text-sm font-normal text-zinc-800 shadow-xl dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100"
        >
          <ExplanationPanel term={term} context={context} />
        </div>
      )}
    </span>
  );
}
