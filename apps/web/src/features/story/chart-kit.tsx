import {
  type FocusEvent,
  type PointerEvent,
  type ReactNode,
  type RefObject,
  useCallback,
  useEffect,
  useState,
} from "react";

export const percent = (value: number, digits = 0) => `${(value * 100).toFixed(digits)}%`;
export const count = (value: number) => value.toLocaleString("en-US");

export function prefersReducedMotion() {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/** Width of an element, kept current as it resizes. 0 until measured on the client. */
export function useElementWidth(ref: RefObject<HTMLElement | null>) {
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const element = ref.current;
    if (!element) return;
    const observer = new ResizeObserver(([entry]) =>
      setWidth(Math.floor(entry!.contentRect.width)),
    );
    observer.observe(element);
    return () => observer.disconnect();
  }, [ref]);
  return width;
}

/** True once the element has scrolled into view. Starts true for reduced motion. */
export function useInView(ref: RefObject<HTMLElement | null>) {
  const [inView, setInView] = useState(false);
  useEffect(() => {
    const element = ref.current;
    if (!element) return;
    if (prefersReducedMotion()) {
      setInView(true);
      return;
    }
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry!.isIntersecting) {
          setInView(true);
          observer.disconnect();
        }
      },
      { threshold: 0.35 },
    );
    observer.observe(element);
    return () => observer.disconnect();
  }, [ref]);
  return inView;
}

type Tip = { x: number; y: number; width: number; content: ReactNode };

/**
 * A hover and keyboard-focus tooltip positioned inside `ref`, which must be
 * `relative`. Spread `markProps(...)` onto each mark that should show one.
 */
export function useChartTooltip(ref: RefObject<HTMLElement | null>) {
  const [tip, setTip] = useState<Tip | null>(null);

  const showAt = useCallback(
    (clientX: number, clientY: number, content: ReactNode) => {
      const box = ref.current?.getBoundingClientRect();
      if (box) setTip({ x: clientX - box.left, y: clientY - box.top, width: box.width, content });
    },
    [ref],
  );
  const hide = useCallback(() => setTip(null), []);

  const markProps = (label: string, content: ReactNode) => ({
    tabIndex: 0,
    "aria-label": label,
    className: "outline-none focus-visible:outline-2 focus-visible:outline-ring",
    onPointerMove: (event: PointerEvent) => showAt(event.clientX, event.clientY, content),
    onPointerLeave: hide,
    onFocus: (event: FocusEvent<Element>) => {
      const box = event.currentTarget.getBoundingClientRect();
      showAt(box.left + box.width / 2, box.top, content);
    },
    onBlur: hide,
  });

  const tooltip = tip ? (
    <div
      className="pointer-events-none absolute z-10 w-max max-w-56 -translate-x-1/2 -translate-y-full rounded-md border bg-popover px-2 py-1 text-xs text-popover-foreground shadow-sm"
      style={{
        left: tip.width > 240 ? Math.min(Math.max(tip.x, 112), tip.width - 112) : tip.x,
        top: tip.y - 10,
      }}
    >
      {tip.content}
    </div>
  ) : null;

  return { tooltip, markProps, showAt, hide };
}

/** The table view every chart carries, so no value is only reachable by hover. */
export function DataTable({ head, rows }: { head: string[]; rows: (string | number)[][] }) {
  return (
    <details className="mt-2 text-xs text-muted-foreground">
      <summary className="cursor-pointer select-none">Data table</summary>
      <table className="mt-2 border-collapse tabular-nums">
        <thead>
          <tr>
            {head.map((cell) => (
              <th key={cell} className="border-b py-1 pr-4 text-left font-semibold">
                {cell}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={String(row[0])}>
              {row.map((cell, index) => (
                <td key={index} className="border-b py-1 pr-4">
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  );
}
