import { useId } from "react";
import type { ChartRow, Segment, Tone } from "../../dashboardData";

export interface LegendItem {
  key: string;
  label: string;
  tone: Tone;
}

/**
 * A horizontal bar chart made of plain HTML. It is meant to be read as text first: every row is a list item that states its label
 * and its value in words, so nothing depends on colour or on the bars themselves (they are decorative, `aria-hidden`).
 * Bars are scaled to the largest row of THIS chart; the number next to each bar is the real value. Stacked rows draw their
 * segments with a gap between them; a legend is shown whenever segments have more than one meaning.
 */
export function BarChart({ title, subtitle, unit, rows, legend, empty }: {
  title: string;
  subtitle?: string;
  unit: string;
  rows: ChartRow[];
  legend?: LegendItem[];
  empty: string;
}) {
  const id = useId();
  const max = Math.max(0, ...rows.map((r) => r.value));
  const nothing = rows.length === 0 || max === 0;
  const width = (value: number) => (max === 0 || value <= 0 ? 0 : Math.max(1.5, (value / max) * 100));

  return (
    <figure className="chart" aria-labelledby={`${id}-title`}>
      <figcaption>
        <h3 id={`${id}-title`}>{title}</h3>
        {subtitle && <p className="muted">{subtitle}</p>}
      </figcaption>
      {legend && legend.length > 1 && (
        <ul className="legend" aria-label="Legend">
          {legend.map((item) => (
            <li key={item.key}><span className={`swatch tone-${item.tone}`} aria-hidden="true" /> {item.label}</li>
          ))}
        </ul>
      )}
      {nothing && <p className="empty">{empty}</p>}
      {!nothing && (
        <ul className="bars" aria-label={`${title} (${unit})`}>
          {rows.map((row) => (
            <li key={row.key} className="bar-row">
              <span className="bar-label wrap">
                {row.icon && <span className="bar-icon" aria-hidden="true">{row.icon}</span>}
                {row.label}
              </span>
              <span className="bar-track" aria-hidden="true" title={describe(row, unit)}>
                {row.segments
                  ? row.segments.filter((s) => s.value > 0).map((s) => <span key={s.key} className={`bar-seg tone-${s.tone}`} style={{ width: `${(width(row.value) * s.value) / row.value}%` }} />)
                  : row.value > 0 && <span className={`bar-seg tone-${row.tone}`} style={{ width: `${width(row.value)}%` }} />}
              </span>
              <span className="bar-value">
                <strong>{row.value}</strong>
                {row.segments && row.value > 0 && <span className="muted"> ({parts(row.segments)})</span>}
                {row.detail && <span className="muted"> {row.detail}</span>}
              </span>
            </li>
          ))}
        </ul>
      )}
    </figure>
  );
}

const parts = (segments: Segment[]) => segments.filter((s) => s.value > 0).map((s) => `${s.label} ${s.value}`).join(", ");
const describe = (row: ChartRow, unit: string) => `${row.label}: ${row.value} ${unit}${row.segments && row.value > 0 ? ` (${parts(row.segments)})` : ""}`;
