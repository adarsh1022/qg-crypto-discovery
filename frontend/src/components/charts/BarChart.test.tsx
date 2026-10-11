import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { ChartRow } from "../../dashboardData";
import { BarChart } from "./BarChart";

afterEach(cleanup);

const rows: ChartRow[] = [
  { key: "a", label: "RSA 2048", value: 8, tone: "series1", detail: "(10 sightings)" },
  { key: "b", label: "EC P-256", value: 4, tone: "series1" },
  { key: "c", label: "Other (3 more)", value: 0, tone: "neutral" },
];
const fills = (item: HTMLElement) => Array.from(item.querySelectorAll<HTMLElement>(".bar-seg"));

describe("a single-series chart", () => {
  it("is a labelled figure with its title and subtitle, and each row states its label and value in text", () => {
    render(<BarChart title="Key algorithms" subtitle="Unique certificates." unit="certificates" rows={rows} empty="nothing" />);
    const figure = screen.getByRole("figure", { name: "Key algorithms" });
    expect(within(figure).getByText("Unique certificates.")).toBeTruthy();
    const list = within(figure).getByRole("list", { name: "Key algorithms (certificates)" });
    const items = within(list).getAllByRole("listitem");
    expect(items.map((i) => i.textContent)).toEqual(["RSA 20488 (10 sightings)", "EC P-2564", "Other (3 more)0"]);
  });

  it("scales bars to the largest row of this chart: the biggest fills the track, half is half, zero draws nothing", () => {
    render(<BarChart title="T" unit="u" rows={rows} empty="nothing" />);
    const [a, b, c] = screen.getAllByRole("listitem");
    expect(fills(a).map((f) => f.style.width)).toEqual(["100%"]);
    expect(fills(b).map((f) => f.style.width)).toEqual(["50%"]);
    expect(fills(c)).toHaveLength(0);
  });

  it("keeps a tiny non-zero value visible", () => {
    render(<BarChart title="T" unit="u" rows={[{ key: "x", label: "big", value: 1000, tone: "series1" }, { key: "y", label: "tiny", value: 1, tone: "series1" }]} empty="nothing" />);
    const tiny = screen.getAllByRole("listitem")[1];
    expect(parseFloat(fills(tiny)[0].style.width)).toBeGreaterThanOrEqual(1);          // 1 of 1000 is 0.1% of the track: drawn at a visible minimum
  });

  it("makes the bars decorative (hidden from assistive technology) and gives each a tooltip with the exact value", () => {
    render(<BarChart title="T" unit="certificates" rows={rows} empty="nothing" />);
    const tracks = document.querySelectorAll(".bar-track");
    expect(Array.from(tracks).every((t) => t.getAttribute("aria-hidden") === "true")).toBe(true);
    expect(tracks[0].getAttribute("title")).toBe("RSA 2048: 8 certificates");
  });

  it("has no legend for a single series", () => {
    render(<BarChart title="T" unit="u" rows={rows} legend={[{ key: "s", label: "Only", tone: "series1" }]} empty="nothing" />);
    expect(screen.queryByRole("list", { name: "Legend" })).toBeNull();
  });

  it("shows the status icon as decoration next to the text label, never instead of it", () => {
    render(<BarChart title="T" unit="u" rows={[{ key: "e", label: "Expired", value: 2, tone: "expired", icon: "✕" }]} empty="nothing" />);
    const item = screen.getByRole("listitem");
    expect(item.querySelector(".bar-icon")!.getAttribute("aria-hidden")).toBe("true");
    expect(item.textContent).toContain("Expired");
    expect(item.querySelector(".tone-expired")).toBeTruthy();
  });
});

describe("a stacked chart", () => {
  const stacked: ChartRow[] = [
    { key: "completed", label: "Completed", value: 6, tone: "series1", segments: [{ key: "filesystem", label: "Filesystem", value: 4, tone: "series1" }, { key: "tls", label: "TLS", value: 2, tone: "series2" }] },
    { key: "failed", label: "Failed", value: 3, tone: "series1", segments: [{ key: "filesystem", label: "Filesystem", value: 3, tone: "series1" }, { key: "tls", label: "TLS", value: 0, tone: "series2" }] },
  ];
  const legend = [{ key: "filesystem", label: "Filesystem", tone: "series1" as const }, { key: "tls", label: "TLS", tone: "series2" as const }];

  it("shows a legend for two series, the total, and the breakdown in words", () => {
    render(<BarChart title="Runs" unit="runs" rows={stacked} legend={legend} empty="nothing" />);
    const items = within(screen.getByRole("list", { name: "Legend" })).getAllByRole("listitem");
    expect(items.map((i) => i.textContent?.trim())).toEqual(["Filesystem", "TLS"]);
    const [completed, failed] = Array.from(document.querySelectorAll<HTMLElement>(".bar-row"));
    expect(completed.textContent).toContain("6");
    expect(completed.textContent).toContain("(Filesystem 4, TLS 2)");
    expect(failed.textContent).toContain("(Filesystem 3)");                       // a zero segment is not listed
  });

  it("draws segments in proportion, in series order, and leaves out empty ones", () => {
    render(<BarChart title="Runs" unit="runs" rows={stacked} legend={legend} empty="nothing" />);
    const [completed, failed] = Array.from(document.querySelectorAll<HTMLElement>(".bar-row"));
    expect(fills(completed).map((f) => [f.className.includes("tone-series1") ? "series1" : "series2", Math.round(parseFloat(f.style.width))])).toEqual([["series1", 67], ["series2", 33]]);
    expect(fills(failed).map((f) => Math.round(parseFloat(f.style.width)))).toEqual([50]);     // 3 of the largest total (6)
  });
});

describe("with nothing to show", () => {
  it("says so instead of drawing an empty chart, for no rows and for all-zero rows", () => {
    const { rerender } = render(<BarChart title="T" unit="u" rows={[]} empty="No data yet." />);
    expect(screen.getByText("No data yet.")).toBeTruthy();
    expect(screen.queryByRole("list", { name: /\(u\)/ })).toBeNull();
    rerender(<BarChart title="T" unit="u" rows={[{ key: "z", label: "Zero", value: 0, tone: "series1" }]} empty="Still nothing." />);
    expect(screen.getByText("Still nothing.")).toBeTruthy();
    expect(screen.queryByRole("listitem")).toBeNull();
  });
});
