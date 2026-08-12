import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { StatusPill, formatNumber, formatResultRange } from "./common";

describe("shared presentation helpers", () => {
  it("renders the status label and semantic tone", () => {
    const markup = renderToStaticMarkup(<StatusPill ok label="high" />);

    expect(markup).toContain("pill ok");
    expect(markup).toContain("high");
  });

  it("formats numeric and pagination values", () => {
    expect(formatNumber(1234)).toBe((1234).toLocaleString());
    expect(formatNumber(null)).toBe("0");
    expect(formatResultRange(50, 50, 73, 23)).toBe("显示 51-73");
    expect(formatResultRange(0, 50, 0, 0)).toBe("显示 0-0");
  });
});
