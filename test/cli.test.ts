import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  REVIEW_CTA,
  type CliIO,
  runCli,
} from "../src/cli.js";
import { CLI_VERSION } from "../src/version.js";

const temporaryRoots: string[] = [];

async function fixtureRoot(): Promise<string> {
  const root = await mkdtemp(resolve(tmpdir(), "cutoverproof-cli-"));
  temporaryRoots.push(root);
  return root;
}

function captureIO(): {
  io: CliIO;
  stdout: () => string;
  stderr: () => string;
} {
  let stdout = "";
  let stderr = "";
  return {
    io: {
      stdout: { write: (value) => (stdout += value) },
      stderr: { write: (value) => (stderr += value) },
    },
    stdout: () => stdout,
    stderr: () => stderr,
  };
}

afterEach(async () => {
  await Promise.all(
    temporaryRoots.splice(0).map((root) =>
      rm(root, { force: true, recursive: true }),
    ),
  );
});

describe("runCli", () => {
  it("defaults to Markdown and returns 1 for high-risk findings", async () => {
    const root = await fixtureRoot();
    await writeFile(
      resolve(root, "catalog.ts"),
      "const content = google.content({ version: 'v2.1', auth });\n",
      "utf8",
    );
    const capture = captureIO();

    const code = await runCli([], { cwd: root, io: capture.io });

    expect(code).toBe(1);
    expect(capture.stdout()).toContain("# CutoverProof migration scan");
    expect(capture.stdout().endsWith(`${REVIEW_CTA}\n`)).toBe(true);
    expect(capture.stderr()).toBe("");
  });

  it("keeps JSON stdout parseable and writes the CTA to stderr", async () => {
    const root = await fixtureRoot();
    await writeFile(
      resolve(root, "catalog.py"),
      "service = build('content', 'v2.1')\n",
      "utf8",
    );
    const capture = captureIO();

    const code = await runCli(["--format", "json"], {
      cwd: root,
      io: capture.io,
    });

    expect(code).toBe(1);
    expect(JSON.parse(capture.stdout()).riskLevel).toBe("high");
    expect(capture.stdout()).not.toContain("chatgpt.site");
    expect(capture.stderr()).toBe(`${REVIEW_CTA}\n`);
  });

  it("keeps CSV stdout pure and returns 0 for a clean scan", async () => {
    const root = await fixtureRoot();
    await writeFile(
      resolve(root, "merchant.ts"),
      "const amount = { amountMicros: 1000000n, currencyCode: 'USD' };\n",
      "utf8",
    );
    const capture = captureIO();

    const code = await runCli([".", "--format=csv"], {
      cwd: root,
      io: capture.io,
    });

    expect(code).toBe(0);
    expect(capture.stdout()).toBe(
      '"id","severity","category","file","line","column","title","evidence","recommendation"\n',
    );
    expect(capture.stdout()).not.toContain("chatgpt.site");
    expect(capture.stderr()).toBe(`${REVIEW_CTA}\n`);
  });

  it("returns 2 and identifies incomplete UTF-8 coverage", async () => {
    const root = await fixtureRoot();
    await writeFile(resolve(root, "bad.ts"), Buffer.from([0xc3, 0x28]));
    const capture = captureIO();

    const code = await runCli(["--format=json"], {
      cwd: root,
      io: capture.io,
    });

    expect(code).toBe(2);
    expect(() => JSON.parse(capture.stdout())).not.toThrow();
    expect(capture.stderr()).toContain("scan incomplete");
    expect(capture.stderr()).toContain("not valid UTF-8");
  });

  it("returns 2 for invalid usage and unreadable targets", async () => {
    const root = await fixtureRoot();
    const invalid = captureIO();
    const missing = captureIO();

    expect(
      await runCli(["--format", "yaml"], { cwd: root, io: invalid.io }),
    ).toBe(2);
    expect(invalid.stdout()).toBe("");
    expect(invalid.stderr()).toContain("Invalid format");

    expect(
      await runCli(["missing-directory"], { cwd: root, io: missing.io }),
    ).toBe(2);
    expect(missing.stdout()).toBe("");
    expect(missing.stderr()).toContain("scan could not start");
  });

  it("prints standalone help and version responses", async () => {
    const help = captureIO();
    const version = captureIO();

    expect(await runCli(["--help"], { io: help.io })).toBe(0);
    expect(help.stdout()).toContain("Usage:");
    expect(help.stdout()).toContain("Exit codes:");
    expect(help.stderr()).toBe("");

    expect(await runCli(["--version"], { io: version.io })).toBe(0);
    expect(version.stdout()).toBe(`${CLI_VERSION}\n`);
    expect(version.stderr()).toBe("");
  });

  it("supports -- before a path beginning with a dash", async () => {
    const root = await fixtureRoot();
    await writeFile(
      resolve(root, "-catalog.ts"),
      "const content = google.content('v2.1');\n",
      "utf8",
    );
    const capture = captureIO();

    const code = await runCli(["--", "-catalog.ts"], {
      cwd: root,
      io: capture.io,
    });

    expect(code).toBe(1);
    expect(capture.stdout()).toContain("-catalog.ts");
  });
});
