import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

// Without an icon link the browser asks the dev server for /favicon.ico and logs a 404 error in the console on every page load.
describe("index.html", () => {
  const html = readFileSync(resolve(__dirname, "../index.html"), "utf8");

  it("declares an icon, so no /favicon.ico request is made", () => {
    expect(html).toMatch(/<link[^>]+rel="icon"[^>]*>/);
  });

  it("loads nothing from outside this machine", () => {
    expect(html).not.toMatch(/(src|href)="https?:\/\//);
  });
});
