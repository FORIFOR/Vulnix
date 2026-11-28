"use client";

import { useEffect, useRef } from "react";
import { init, use as registerCharts, type EChartsCoreOption } from "echarts/core";
import { GraphChart, HeatmapChart, LineChart, PieChart, ScatterChart, TreemapChart } from "echarts/charts";
import { GridComponent, TooltipComponent, VisualMapComponent } from "echarts/components";
import { SVGRenderer } from "echarts/renderers";

registerCharts([GraphChart, HeatmapChart, LineChart, PieChart, ScatterChart, TreemapChart, GridComponent, TooltipComponent, VisualMapComponent, SVGRenderer]);

export function IntelligenceChart({ option, onSelect, label }: {
  option: EChartsCoreOption;
  onSelect?: (index: number, name: string) => void;
  label: string;
}) {
  const host = useRef<HTMLDivElement>(null);
  const chart = useRef<ReturnType<typeof init> | null>(null);
  useEffect(() => {
    const node = host.current;
    if (!node) return;
    const instance = init(node, undefined, { renderer: "svg" });
    chart.current = instance;
    const resize = new ResizeObserver(() => { if (!instance.isDisposed() && node.clientWidth > 0 && node.clientHeight > 0) instance.resize(); });
    resize.observe(node);
    return () => { resize.disconnect(); instance.dispose(); chart.current = null; };
  }, []);

  useEffect(() => {
    const instance = chart.current;
    if (!instance) return;
    const motion = matchMedia("(prefers-reduced-motion: reduce)");
    const theme = new MutationObserver(update);
    function update() {
      if (!instance || instance.isDisposed()) return;
      const dark = document.documentElement.classList.contains("dark");
      const fg = dark ? "#d4d4d8" : "#3f3f46";
      const axes = Object.fromEntries(["xAxis", "yAxis"].flatMap((key) => {
        const value = option[key];
        if (!value || typeof value !== "object" || Array.isArray(value)) return [];
        const axis = value as Record<string, unknown>;
        const labels = typeof axis.axisLabel === "object" && axis.axisLabel !== null ? axis.axisLabel : {};
        return [[key, { ...axis, axisLabel: { color: fg, ...labels } }]];
      }));
      instance.setOption({
        ...option, ...axes, backgroundColor: "transparent", animation: !motion.matches,
        animationDuration: 260, animationDurationUpdate: 260,
        textStyle: { color: fg, fontFamily: "system-ui" },
        tooltip: { trigger: "item", ...(typeof option.tooltip === "object" && option.tooltip !== null ? option.tooltip : {}), renderMode: "richText", confine: true, appendToBody: false },
      });
    }
    update();
    theme.observe(document.documentElement, { attributeFilter: ["class"] });
    motion.addEventListener("change", update);
    return () => { theme.disconnect(); motion.removeEventListener("change", update); };
  }, [option]);

  useEffect(() => {
    const instance = chart.current;
    if (!instance || !onSelect) return;
    const click = ({ dataIndex, name }: { dataIndex?: number; name?: string }) => { if (typeof dataIndex === "number") onSelect(dataIndex, name ?? ""); };
    instance.on("click", click);
    return () => { instance.off("click", click); };
  }, [onSelect]);

  return <div ref={host} className="h-60 w-full min-w-0 overflow-hidden" role="img" aria-label={label} />;
}
