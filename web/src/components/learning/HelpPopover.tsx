"use client";

import { useEffect, useLayoutEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { helpPopoverPosition } from "@/lib/helpPopoverPosition";
import { GLOSSARY } from "@/lib/glossary";
import { ExplanationPanel } from "./ExplanationPanel";

/** The "？" button. Opens a 3-level explanation tied to the current screen. */
export function HelpPopover({
  term,
  context,
  findingId,
}: {
  term: string;
  context?: string;
  findingId?: string;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const id = useId();
  const t = GLOSSARY[term];

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node) && !panelRef.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        buttonRef.current?.focus();
      }
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  useLayoutEffect(() => {
    if (!open) return;
    const panel = panelRef.current;
    const button = buttonRef.current;
    if (!panel || !button) return;
    const updatePosition = () => {
      const position = helpPopoverPosition(button.getBoundingClientRect(), {
        width: document.documentElement.clientWidth,
        height: window.innerHeight,
      }, panel.scrollHeight + 2);
      Object.assign(panel.style, {
        left: `${position.left}px`, top: `${position.top}px`,
        width: `${position.width}px`, maxHeight: `${position.maxHeight}px`,
        visibility: "visible",
      });
    };
    updatePosition();
    const observer = new ResizeObserver(updatePosition);
    observer.observe(panel);
    window.addEventListener("resize", updatePosition);
    window.addEventListener("scroll", updatePosition, true);
    return () => {
      observer.disconnect();
      window.removeEventListener("resize", updatePosition);
      window.removeEventListener("scroll", updatePosition, true);
    };
  }, [open]);

  if (!t) return null;
  return (
    <span ref={ref} className="relative inline-flex align-middle">
      <button
        ref={buttonRef}
        type="button"
        aria-label={`${t.title}の解説`}
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen((o) => !o)}
        className="ml-1 inline-flex h-5 w-5 items-center justify-center rounded-full border border-zinc-300 text-[11px] font-semibold text-zinc-600 hover:bg-zinc-100 dark:border-zinc-600 dark:text-zinc-300 dark:hover:bg-zinc-800"
      >
        ？
      </button>
      {open && createPortal(
        <div
          ref={panelRef}
          style={{ visibility: "hidden" }}
          id={id}
          role="dialog"
          aria-label={t.title}
          className="fixed z-50 overflow-y-auto overscroll-contain break-words rounded-xl border border-zinc-200 bg-white p-4 text-left text-sm font-normal text-zinc-800 shadow-xl dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100"
        >
          <ExplanationPanel term={term} context={context} findingId={findingId} />
        </div>,
        document.body,
      )}
    </span>
  );
}
