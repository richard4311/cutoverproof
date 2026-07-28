import { describe, expect, it } from "vitest";

import {
  exportScanAsCSV,
  exportScanAsCsv,
  exportScanAsJSON,
  exportScanAsJson,
  exportScanAsMarkdown,
  scanFiles,
  scanSourceFiles,
  type ScanFinding,
  type ScanInputFile,
} from "../src/scanner.js";

function scan(path: string, content: string) {
  return scanFiles([{ path, content }]);
}

function ruleIds(findings: ScanFinding[]) {
  return findings.map((finding) => finding.ruleId);
}

function findingFor(findings: ScanFinding[], ruleId: string) {
  return findings.find((finding) => finding.ruleId === ruleId);
}

describe("scanFiles", () => {
  it("returns a structured clean result for current Merchant API code", () => {
    const result = scan(
      "src/merchant.ts",
      [
        'import { ProductsServiceClient } from "@google-shopping/products";',
        "const price = { amountMicros: 19990000n, currencyCode: \"USD\" };",
        "await productsService.insertProduct({ parent, product });",
      ].join("\n"),
    );

    expect(result.riskScore).toBe(0);
    expect(result.riskLevel).toBe("none");
    expect(result.findings).toEqual([]);
    expect(result.summary).toMatchObject({
      totalFindings: 0,
      filesWithFindings: 0,
      highestSeverity: null,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
    });
    expect(result.stats).toMatchObject({
      inputFiles: 1,
      scannedFiles: 1,
      filesScanned: 1,
      skippedFiles: 0,
      highRiskFindings: 0,
      categoriesDetected: 0,
    });
    expect(result.recommendedActions[0]?.id).toBe("confirm-scan-coverage");
  });

  it("detects Node client construction, a resource method, and customBatch", () => {
    const result = scan(
      "src/catalog.ts",
      [
        "import { google } from 'googleapis';",
        "const content = google.content({ version: 'v2.1', auth });",
        "await content.products.list({ merchantId });",
        "await content.products.custombatch({ requestBody: batch });",
      ].join("\n"),
    );

    expect(ruleIds(result.findings)).toEqual(
      expect.arrayContaining([
        "node-content-client",
        "legacy-resource-method",
        "legacy-custom-batch",
      ]),
    );
    expect(
      result.findings.find(
        (finding) =>
          finding.ruleId === "legacy-resource-method" &&
          finding.title.includes("products.list"),
      ),
    ).toMatchObject({ file: "src/catalog.ts", line: 3, column: 15 });
    expect(result.riskLevel).toBe("high");
    expect(result.stats.highRiskFindings).toBeGreaterThanOrEqual(3);
    expect(result.recommendedActions.map((action) => action.id)).toEqual(
      expect.arrayContaining([
        "replace-content-surface",
        "map-resource-methods",
        "redesign-batching",
      ]),
    );
  });

  it("detects Python discovery and chained resource calls with CRLF lines", () => {
    const result = scan(
      "jobs/sync.py",
      [
        "from googleapiclient.discovery import build",
        "service = build('content', 'v2.1', credentials=creds)",
        "response = service.productstatuses().list(merchantId=merchant_id).execute()",
      ].join("\r\n"),
    );

    expect(findingFor(result.findings, "python-content-discovery")).toMatchObject(
      {
        language: "python",
        line: 2,
      },
    );
    expect(
      result.findings.find(
        (finding) =>
          finding.ruleId === "legacy-resource-method" &&
          finding.title.includes("productstatuses.list"),
      ),
    ).toMatchObject({ line: 3 });
  });

  it("detects multiline Node, Python, and Java legacy client construction", () => {
    const result = scanFiles([
      {
        path: "src/catalog.ts",
        content: [
          "const content = google",
          "  .content(",
          "    { version: 'v2.1', auth },",
          "  );",
        ].join("\n"),
      },
      {
        path: "jobs/sync.py",
        content: [
          "service = build(",
          "    'content',",
          "    'v2.1',",
          "    credentials=creds,",
          ")",
        ].join("\n"),
      },
      {
        path: "src/Catalog.java",
        content: [
          "ShoppingContent client = new ShoppingContent",
          "    .Builder(transport, json, init)",
          "    .build();",
        ].join("\n"),
      },
    ]);

    expect(findingFor(result.findings, "node-content-client")).toMatchObject({
      file: "src/catalog.ts",
      line: 1,
    });
    expect(findingFor(result.findings, "python-content-discovery")).toMatchObject({
      file: "jobs/sync.py",
      line: 1,
    });
    expect(
      findingFor(result.findings, "java-shopping-content-client"),
    ).toMatchObject({
      file: "src/Catalog.java",
      line: 1,
    });
  });

  it("detects Java clients, dependencies, methods, and legacy Price models", () => {
    const files: ScanInputFile[] = [
      {
        path: "pom.xml",
        content:
          "<artifactId>google-api-services-content</artifactId>\n<version>v2.1-rev20240101-2.0.0</version>",
      },
      {
        path: "src/Catalog.java",
        content: [
          "import com.google.api.services.content.ShoppingContent;",
          "import com.google.api.services.content.model.Price;",
          "ShoppingContent client = new ShoppingContent.Builder(transport, json, init).build();",
          "client.products().insert(merchantId, product).execute();",
          'Price price = new Price().setValue("12.34").setCurrency("USD");',
        ].join("\n"),
      },
    ];

    const result = scanFiles(files);
    expect(ruleIds(result.findings)).toEqual(
      expect.arrayContaining([
        "java-content-dependency",
        "java-shopping-content-client",
        "legacy-resource-method",
        "legacy-price-model-java",
        "legacy-price-shape",
      ]),
    );
    expect(result.stats.filesScanned).toBe(2);
    expect(result.summary.byCategory.price).toBeGreaterThanOrEqual(1);
  });

  it("detects PHP ShoppingContent services and custom batch methods", () => {
    const result = scan(
      "legacy/catalog.php",
      [
        "<?php",
        "$service = new Google_Service_ShoppingContent($client);",
        "$items = $service->products->listProducts($merchantId);",
        "$result = $service->products->customBatch($batch);",
        "$price = new Google_Service_ShoppingContent_Price();",
      ].join("\n"),
    );

    expect(ruleIds(result.findings)).toEqual(
      expect.arrayContaining([
        "php-shopping-content-client",
        "legacy-resource-method",
        "legacy-custom-batch",
        "legacy-price-model-php",
      ]),
    );
    expect(
      result.findings.find((finding) => finding.language === "php"),
    ).toBeTruthy();
  });

  it("detects Apps Script calls and its manifest dependency", () => {
    const result = scanFiles([
      {
        path: "appsscript.json",
        content: JSON.stringify(
          {
            dependencies: {
              enabledAdvancedServices: [
                {
                  userSymbol: "ShoppingContent",
                  serviceId: "content",
                  version: "v2.1",
                },
              ],
            },
          },
          null,
          2,
        ),
      },
      {
        path: "Code.gs",
        content:
          "const products = ShoppingContent.Products.list(merchantId, { maxResults: 250 });",
      },
    ]);

    expect(ruleIds(result.findings)).toEqual(
      expect.arrayContaining([
        "apps-script-content-manifest",
        "apps-script-shopping-content",
        "legacy-resource-method",
      ]),
    );
    expect(
      findingFor(result.findings, "apps-script-shopping-content"),
    ).toMatchObject({ language: "apps-script", file: "Code.gs", line: 1 });
  });

  it("detects absolute and relative raw Content API REST endpoints", () => {
    const result = scan(
      "scripts/request.sh",
      [
        'curl "https://shoppingcontent.googleapis.com/content/v2.1/123/products"',
        'path="/content/v2.1/123/productstatuses"',
      ].join("\n"),
    );

    expect(findingFor(result.findings, "content-api-rest-endpoint")).toMatchObject(
      { line: 1, category: "legacy-endpoint" },
    );
    expect(
      findingFor(result.findings, "content-api-relative-endpoint"),
    ).toMatchObject({ line: 2 });
  });

  it("flags REST batch endpoints and client customBatch calls", () => {
    const result = scan(
      "sync.js",
      [
        "const content = google.content('v2.1');",
        "await content.products.customBatch({ entries });",
        "fetch('https://shoppingcontent.googleapis.com/content/v2.1/123/products/batch');",
      ].join("\n"),
    );

    const batches = result.findings.filter(
      (finding) => finding.ruleId === "legacy-custom-batch",
    );
    expect(batches.some((finding) => finding.line === 2)).toBe(true);
    expect(batches.some((finding) => finding.line === 3)).toBe(true);
  });

  it("finds value/currency price shapes and unsafe decimal conversions", () => {
    const result = scan(
      "catalog.js",
      [
        "const content = google.content('v2.1');",
        "const product = {",
        "  price: {",
        "    value: '10.25',",
        "    currency: 'USD'",
        "  }",
        "};",
        "const micros = parseFloat(product.price.value) * 1000000;",
      ].join("\n"),
    );

    expect(findingFor(result.findings, "legacy-price-shape")).toMatchObject({
      line: 4,
      category: "price",
    });
    expect(findingFor(result.findings, "legacy-price-conversion")).toMatchObject({
      line: 8,
      severity: "high",
    });
    expect(
      result.recommendedActions.some(
        (action) => action.id === "prove-price-parity",
      ),
    ).toBe(true);
  });

  it("detects product ID delimiter assumptions in JS, Python, PHP, and literals", () => {
    const result = scanFiles([
      {
        path: "id.js",
        content:
          "const parts = productId.split(':');\nconst content = google.content('v2.1');",
      },
      {
        path: "id.py",
        content:
          "service = build('content', 'v2.1')\nparts = product_id.split(':')",
      },
      {
        path: "id.php",
        content:
          "$service = new Google_Service_ShoppingContent($client);\n$parts = explode(':', $productId);",
      },
      {
        path: "fixture.json",
        content: '{"id":"online:en:US:sku-42"}',
      },
    ]);

    const idFindings = result.findings.filter(
      (finding) => finding.ruleId === "legacy-product-id-delimiter",
    );
    expect(new Set(idFindings.map((finding) => finding.file))).toEqual(
      new Set(["fixture.json", "id.js", "id.php", "id.py"]),
    );
  });

  it("detects constructed delimiter identities in a legacy-context file", () => {
    const result = scan(
      "ids.ts",
      [
        "const content = google.content('v2.1');",
        "const id = `${channel}:${contentLanguage}:${targetCountry}:${offerId}`;",
      ].join("\n"),
    );

    expect(findingFor(result.findings, "legacy-product-id-delimiter")).toMatchObject(
      { line: 2 },
    );
  });

  it("detects Merchant API v1beta clients without treating stable v1 as beta", () => {
    const beta = scan(
      "merchant.py",
      [
        "from google.shopping.merchant_products_v1beta import ProductsServiceClient",
        "client = ProductsServiceClient()",
      ].join("\n"),
    );
    const stable = scan(
      "merchant.py",
      "from google.shopping.merchant_products_v1 import ProductsServiceClient",
    );
    const betaRest = scan(
      "request.ts",
      "fetch('https://merchantapi.googleapis.com/products/v1beta/accounts/123/products');",
    );

    expect(findingFor(beta.findings, "merchant-api-v1beta")).toMatchObject({
      category: "dependency",
      severity: "critical",
    });
    expect(beta.riskLevel).toBe("critical");
    expect(
      findingFor(betaRest.findings, "merchant-api-v1beta")?.severity,
    ).toBe("critical");
    expect(stable.findings).toEqual([]);
  });

  it("detects exact legacy dependencies while marking shared dependencies as audits", () => {
    const result = scanFiles([
      {
        path: "package.json",
        content: '{"dependencies":{"@googleapis/content":"^9.0.0"}}',
      },
      {
        path: "requirements.txt",
        content: "google-api-python-client==2.177.0",
      },
      {
        path: "composer.json",
        content: '{"require":{"google/apiclient-services":"^0.400"}}',
      },
    ]);

    expect(findingFor(result.findings, "node-content-dependency")?.severity).toBe(
      "high",
    );
    expect(
      findingFor(result.findings, "python-discovery-dependency")?.severity,
    ).toBe("low");
    expect(
      findingFor(result.findings, "php-discovery-dependency")?.severity,
    ).toBe("low");
  });

  it("never copies private keys, API keys, tokens, or query credentials into results", () => {
    const privateFragment = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC";
    const apiKey = "AIzaSyDUMMYSECRETKEY1234567890";
    const bearer = "ya29.a0ARrdaMVerySensitiveBearerToken";
    const result = scan(
      "credentials.json",
      [
        `{"private_key":"-----BEGIN PRIVATE KEY-----\\n${privateFragment}\\n-----END PRIVATE KEY-----"}`,
        `const apiKey = "${apiKey}";`,
        `const endpoint = "https://shoppingcontent.googleapis.com/content/v2.1/123/products?key=${apiKey}";`,
        `Authorization: Bearer ${bearer}`,
      ].join("\n"),
    );

    expect(result.summary.byCategory.credential).toBeGreaterThanOrEqual(3);
    expect(result.riskLevel).toBe("critical");
    expect(result.warnings.join(" ")).toMatch(/redacted/i);

    const serialized = [
      JSON.stringify(result),
      exportScanAsMarkdown(result),
      exportScanAsJSON(result),
      exportScanAsCSV(result),
    ].join("\n");
    expect(serialized).not.toContain(privateFragment);
    expect(serialized).not.toContain(apiKey);
    expect(serialized).not.toContain(bearer);
    expect(serialized).toContain("redacted");
  });

  it("redacts credentials from evidence belonging to a non-credential rule", () => {
    const apiKey = "AIzaSyDUMMYSECRETKEY1234567890";
    const result = scan(
      "request.js",
      `fetch("https://shoppingcontent.googleapis.com/content/v2.1/123/products?key=${apiKey}");`,
    );
    const endpoint = findingFor(result.findings, "content-api-rest-endpoint");

    expect(endpoint?.evidence).toContain("[REDACTED GOOGLE API KEY]");
    expect(endpoint?.evidence).not.toContain(apiKey);
  });

  it("applies default path, binary, custom, per-file, total, and file-count guards", () => {
    const result = scanFiles(
      [
        { path: "node_modules/legacy.js", content: "google.content('v2.1')" },
        { path: "src/ignored.js", content: "google.content('v2.1')" },
        { path: "src/binary.js", content: "hello\0world" },
        { path: "src/large.js", content: "x".repeat(20) },
        { path: "src/one.js", content: "const one = 1;" },
        { path: "src/two.js", content: "const two = 2;" },
      ],
      {
        excludePaths: ["ignored"],
        maxFileBytes: 16,
        maxTotalBytes: 20,
        maxFiles: 1,
      },
    );

    expect(result.skipped.map((file) => file.reason)).toEqual(
      expect.arrayContaining([
        "default-exclusion",
        "excluded-by-option",
        "binary",
        "max-file-size",
        "file-limit",
      ]),
    );
    expect(result.stats).toMatchObject({
      inputFiles: 6,
      scannedFiles: 1,
      filesScanned: 1,
      skippedFiles: 5,
    });
    expect(
      result.recommendedActions.some(
        (action) => action.id === "review-skipped-files",
      ),
    ).toBe(true);

    const totalGuard = scanFiles(
      [
        { path: "a.js", content: "1234567890" },
        { path: "b.js", content: "1234567890" },
      ],
      { maxFileBytes: 20, maxTotalBytes: 15 },
    );
    expect(totalGuard.skipped[0]).toMatchObject({
      path: "b.js",
      reason: "max-total-size",
    });
  });

  it("can disable default exclusions for a caller-prepared source set", () => {
    const result = scanFiles(
      [
        {
          path: "vendor/owned-adapter.js",
          content: "const content = google.content('v2.1');",
        },
      ],
      { includeDefaultExclusions: false },
    );

    expect(result.stats.scannedFiles).toBe(1);
    expect(findingFor(result.findings, "node-content-client")).toBeTruthy();
  });

  it("caps findings, exposes omissions, and keeps the highest-risk evidence", () => {
    const result = scanFiles(
      [
        {
          path: "catalog.js",
          content: [
            "const content = google.content('v2.1');",
            "content.products.list({ merchantId });",
            "content.products.get({ merchantId, productId });",
            "content.products.delete({ merchantId, productId });",
          ].join("\n"),
        },
      ],
      { maxFindings: 2 },
    );

    expect(result.findings).toHaveLength(2);
    expect(result.stats.findingsTruncated).toBe(true);
    expect(result.stats.omittedFindings).toBeGreaterThan(0);
    expect(result.warnings.join(" ")).toMatch(/omitted/i);
  });

  it("normalizes paths and produces identical results regardless of input order", () => {
    const first: ScanInputFile = {
      path: ".\\z\\catalog.py",
      content: "service = build('content', 'v2.1')",
    };
    const second: ScanInputFile = {
      path: "./a/catalog.ts",
      content: "const content = google.content('v2.1');",
    };

    const forward = scanFiles([first, second]);
    const reverse = scanSourceFiles([second, first]);

    expect(reverse).toEqual(forward);
    expect(forward.findings.map((finding) => finding.file)).toEqual(
      expect.arrayContaining(["a/catalog.ts", "z/catalog.py"]),
    );
  });

  it("is conservative around generic products.list calls without Content API context", () => {
    const result = scan(
      "store.ts",
      [
        "const products = database.collection('products');",
        "await products.list({ pageSize: 50 });",
        "const price = { value: 12, currency: 'USD' };",
      ].join("\n"),
    );

    expect(result.findings).toEqual([]);
  });

  it("does not label generic price handling as legacy without legacy context", () => {
    const result = scanFiles([
      {
        path: "store.ts",
        content:
          "const micros = parseFloat(product.price.value) * 1000000;\nconst currency = product.price.currency;",
      },
      {
        path: "Money.java",
        content:
          'Price price = new Price().setValue("12.34").setCurrency("USD");',
      },
    ]);

    expect(result.findings.filter((finding) => finding.category === "price")).toEqual(
      [],
    );
  });
});
describe("deterministic exporters", () => {
  const result = scanFiles([
    {
      path: "src/a|catalog.ts",
      content: [
        "const content = google.content('v2.1');",
        'content.products.list({ note: "a,b" });',
      ].join("\n"),
    },
  ]);

  it("exports deterministic Markdown with escaped table cells and actions", () => {
    const first = exportScanAsMarkdown(result);
    const second = exportScanAsMarkdown(result);

    expect(second).toBe(first);
    expect(first).toContain("# CutoverProof migration scan");
    expect(first).toContain("src/a\\|catalog.ts");
    expect(first).toContain("## Recommended actions");
    expect(first.endsWith("\n")).toBe(true);
  });

  it("exports canonical, parseable JSON with camel-case aliases", () => {
    const canonical = exportScanAsJSON(result);
    expect(exportScanAsJson(result)).toBe(canonical);
    expect(JSON.parse(canonical)).toEqual(result);
    expect(canonical).toBe(exportScanAsJSON(result));
    expect(canonical.endsWith("\n")).toBe(true);
  });

  it("exports valid quoted CSV with a stable header and camel-case alias", () => {
    const csv = exportScanAsCSV(result);
    const rows = csv.trimEnd().split("\n");

    expect(exportScanAsCsv(result)).toBe(csv);
    expect(rows[0]).toBe(
      '"id","severity","category","file","line","column","title","evidence","recommendation"',
    );
    expect(rows.length).toBe(result.findings.length + 1);
    expect(csv).toContain('"src/a|catalog.ts"');
    expect(csv).toContain('""a,b""');
    expect(csv.endsWith("\n")).toBe(true);
  });
});
