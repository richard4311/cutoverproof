import { describe, expect, it } from "vitest";

import {
  exportScanAsCSV,
  exportScanAsJSON,
  exportScanAsMarkdown,
  scanFiles,
} from "../src/scanner.js";

describe("untrusted output hardening", () => {
  it("neutralizes terminal controls and bidirectional overrides in paths", () => {
    const result = scanFiles([
      {
        path: "src/\u001b[31m\u009b\u202ecatalog.ts",
        content: "const content = google.content('v2.1');",
      },
    ]);

    expect(result.findings[0]?.file).toContain("\\u001b");
    expect(result.findings[0]?.file).toContain("\\u009b");
    expect(result.findings[0]?.file).toContain("\\u202e");
    for (const output of [
      exportScanAsJSON(result),
      exportScanAsMarkdown(result),
      exportScanAsCSV(result),
    ]) {
      expect(output).not.toContain("\u001b");
      expect(output).not.toContain("\u009b");
      expect(output).not.toContain("\u202e");
    }
  });

  it("escapes Markdown table delimiters, formatting, code, and HTML", () => {
    const result = scanFiles([
      {
        path: "src/*bad*|`catalog`.ts",
        content:
          "const content = google.content('v2.1'); // <img src=x onerror=alert(1)> | `break`",
      },
    ]);

    const markdown = exportScanAsMarkdown(result);

    expect(markdown).toContain("src/\\*bad\\*\\|\\`catalog\\`.ts");
    expect(markdown).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(markdown).toContain("\\|");
    expect(markdown).not.toContain("<img");
  });

  it("prefixes spreadsheet-formula cells while preserving valid CSV quoting", () => {
    const result = scanFiles([
      {
        path: '=HYPERLINK("example.invalid")-catalog.ts',
        content: "=google.content('v2.1');",
      },
    ]);

    const csv = exportScanAsCSV(result);

    expect(csv).toContain(
      '"\'=HYPERLINK(""example.invalid"")-catalog.ts"',
    );
    expect(csv).toContain('"\'=google.content(\'v2.1\');"');
    expect(csv.endsWith("\n")).toBe(true);
  });
});
