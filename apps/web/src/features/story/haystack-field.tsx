import { useEffect, useRef } from "react";

import {
  count,
  prefersReducedMotion,
  useChartTooltip,
  useElementWidth,
  useInView,
} from "./chart-kit";

const PITCH = 1.5;
const FADE_MS = 1400;

/** Seeded so the highlighted positions stay put between renders and visits. */
function randomPositions(total: number, picks: number) {
  let seed = 42;
  const next = () => (seed = (seed * 1664525 + 1013904223) >>> 0) / 2 ** 32;
  const positions = new Set<number>();
  while (positions.size < Math.min(picks, total)) positions.add(Math.floor(next() * total));
  return [...positions];
}

/** One dot per vulnerability published in a year, with the listed ones lit. */
export function HaystackField({
  published,
  listed,
  year,
}: {
  published: number;
  listed: number;
  year: number;
}) {
  const box = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const width = useElementWidth(box);
  const inView = useInView(box);
  const { tooltip, markProps } = useChartTooltip(box);

  const columns = Math.max(1, Math.floor(width / PITCH));
  const height = width ? Math.ceil(Math.ceil(published / columns) * PITCH) : 160;

  useEffect(() => {
    const element = canvas.current;
    if (!element || !width) return;
    const ratio = window.devicePixelRatio || 1;
    element.width = width * ratio;
    element.height = height * ratio;
    const context = element.getContext("2d")!;
    const styles = getComputedStyle(element);
    const field = styles.getPropertyValue("--muted-foreground");
    const surface = styles.getPropertyValue("--background");
    const accent = styles.getPropertyValue("--story-s1");
    const lit = randomPositions(published, listed);

    const draw = (fieldAlpha: number) => {
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
      context.clearRect(0, 0, width, height);
      context.globalAlpha = fieldAlpha;
      context.fillStyle = field;
      for (let i = 0; i < published; i++) {
        context.fillRect((i % columns) * PITCH, Math.floor(i / columns) * PITCH, 1, 1);
      }
      context.globalAlpha = 1;
      for (const position of lit) {
        const x = (position % columns) * PITCH;
        const y = Math.floor(position / columns) * PITCH;
        context.fillStyle = surface;
        context.beginPath();
        context.arc(x, y, 3.5, 0, Math.PI * 2);
        context.fill();
        context.fillStyle = accent;
        context.beginPath();
        context.arc(x, y, 2.2, 0, Math.PI * 2);
        context.fill();
      }
    };

    // Once in view, the unlisted field dims so only the listed dots stay bright.
    if (!inView || prefersReducedMotion()) {
      draw(inView ? 0.2 : 0.5);
      return;
    }
    let frame = 0;
    const start = performance.now();
    const step = (now: number) => {
      const t = Math.min(1, (now - start) / FADE_MS);
      draw(0.5 - 0.3 * t * (2 - t));
      if (t < 1) frame = requestAnimationFrame(step);
    };
    frame = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frame);
  }, [width, height, columns, published, listed, inView]);

  const summary = `${count(published)} vulnerabilities published in ${year}, ${count(listed)} on the KEV list by December 31`;
  return (
    <div ref={box} className="relative w-full" style={{ height }}>
      <canvas
        ref={canvas}
        role="img"
        style={{ width, height }}
        {...markProps(summary, <>{summary}</>)}
      />
      {tooltip}
    </div>
  );
}
