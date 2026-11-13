"use client";

import { useMemo, type ReactNode } from "react";
import { parseMarkdown, type Block, type Inline } from "@/lib/safeMarkdown";

/** Renders untrusted (AI) text as a safe Markdown subset. Every string becomes an
 *  escaped React text node; no HTML is injected and nothing becomes a link. */
export function SafeMarkdown({ text, className = "" }: { text: string; className?: string }) {
  const blocks = useMemo(() => parseMarkdown(text), [text]);
  return <div className={`space-y-2 break-words ${className}`}>{blocks.map(block)}</div>;
}

function inline(n: Inline, i: number): ReactNode {
  switch (n.t) {
    case "text":
      return n.v;
    case "br":
      return <br key={i} />;
    case "b":
      return <strong key={i} className="font-semibold">{n.c.map(inline)}</strong>;
    case "i":
      return <em key={i}>{n.c.map(inline)}</em>;
    case "code":
      return (
        <code key={i} className="rounded bg-zinc-100 px-1 py-0.5 font-mono text-[0.92em] dark:bg-zinc-800">
          {n.v}
        </code>
      );
  }
}

function block(b: Block, i: number): ReactNode {
  switch (b.t) {
    case "p":
      return <p key={i}>{b.c.map(inline)}</p>;
    case "h":
      return <p key={i} className="font-semibold">{b.c.map(inline)}</p>;
    case "ul":
      return (
        <ul key={i} className="list-disc space-y-1 pl-5">
          {b.items.map((it, j) => <li key={j}>{it.map(inline)}</li>)}
        </ul>
      );
    case "ol":
      return (
        <ol key={i} start={b.start} className="list-decimal space-y-1 pl-5">
          {b.items.map((it, j) => <li key={j}>{it.map(inline)}</li>)}
        </ol>
      );
    case "code":
      return (
        <pre key={i} className="overflow-x-auto rounded-md bg-zinc-100 p-2 font-mono text-[0.92em] dark:bg-zinc-800">
          <code>{b.v}</code>
        </pre>
      );
  }
}
