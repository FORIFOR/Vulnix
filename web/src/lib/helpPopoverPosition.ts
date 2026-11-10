/** Viewport coordinates for a portalled, fixed-position explanation panel. */
export function helpPopoverPosition(
  anchor: { left: number; width: number; top: number; bottom: number },
  viewport: { width: number; height: number },
  panelHeight: number,
) {
  const margin = 16;
  const gap = 8;
  const width = Math.min(352, Math.max(0, viewport.width - margin * 2));
  const left = Math.max(margin, Math.min(anchor.left + anchor.width / 2 - width / 2, viewport.width - margin - width));
  const below = Math.max(0, viewport.height - margin - anchor.bottom - gap);
  const above = Math.max(0, anchor.top - gap - margin);
  const placeAbove = panelHeight > below && above > below;
  const maxHeight = placeAbove ? above : below;
  const top = placeAbove
    ? Math.max(margin, anchor.top - gap - Math.min(panelHeight, maxHeight))
    : Math.max(margin, Math.min(anchor.bottom + gap, viewport.height - margin));
  return { left, top, width, maxHeight };
}
