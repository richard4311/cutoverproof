import {
  access,
  mkdtemp,
  mkdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  sanitizeForTerminal,
  TraversalError,
  walkRepository,
} from "../src/traverse.js";

const temporaryRoots: string[] = [];

async function temporaryRepository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "cutoverproof-walk-"));
  temporaryRoots.push(root);
  return root;
}

afterEach(async () => {
  await Promise.all(
    temporaryRoots.splice(0).map((root) =>
      rm(root, { force: true, recursive: true }),
    ),
  );
});

describe("walkRepository", () => {
  it("returns normalized, sorted, root-relative UTF-8 files", async () => {
    const root = await temporaryRepository();
    await mkdir(resolve(root, "z"));
    await mkdir(resolve(root, "a"));
    await writeFile(resolve(root, "z", "last.py"), "print('z')\n", "utf8");
    await writeFile(resolve(root, "a", "first.ts"), "export {};\n", "utf8");
    await writeFile(resolve(root, "middle.js"), "void 0;\n", "utf8");

    const result = await walkRepository(root);

    expect(result.complete).toBe(true);
    expect(result.files.map((file) => file.path)).toEqual([
      "a/first.ts",
      "middle.js",
      "z/last.py",
    ]);
    expect(result.stats.filesRead).toBe(3);
    expect(result.stats.bytesRead).toBeGreaterThan(0);
  });

  it("prunes generated and credential-shaped files without reading them", async () => {
    const root = await temporaryRepository();
    await mkdir(resolve(root, ".git"));
    await mkdir(resolve(root, "node_modules"));
    await mkdir(resolve(root, "dist"));
    await writeFile(resolve(root, ".git", "config"), "secret", "utf8");
    await writeFile(
      resolve(root, "node_modules", "legacy.js"),
      "google.content('v2.1')",
      "utf8",
    );
    await writeFile(resolve(root, "dist", "bundle.js"), "legacy", "utf8");
    await writeFile(resolve(root, ".env.production"), "TOKEN=secret", "utf8");
    await writeFile(
      resolve(root, "merchant-service-account.json"),
      '{"private_key":"secret"}',
      "utf8",
    );
    await writeFile(resolve(root, ".npmrc"), "//registry/:_authToken=x", "utf8");
    await writeFile(resolve(root, "logo.png"), Buffer.from([0x89, 0x50, 0x4e]));
    await writeFile(resolve(root, "source.ts"), "export {};\n", "utf8");

    const result = await walkRepository(root);

    expect(result.complete).toBe(true);
    expect(result.files).toEqual([
      { path: "source.ts", content: "export {};\n" },
    ]);
    expect(result.issues.map((issue) => issue.reason)).toEqual(
      expect.arrayContaining([
        "excluded-directory",
        "excluded-file",
        "sensitive-file",
      ]),
    );
    expect(JSON.stringify(result)).not.toContain("TOKEN=secret");
    expect(JSON.stringify(result)).not.toContain("_authToken");
    expect(JSON.stringify(result)).not.toContain("private_key");
  });

  it("does not follow a directory symlink", async () => {
    const root = await temporaryRepository();
    const outside = await temporaryRepository();
    await writeFile(
      resolve(outside, "legacy.ts"),
      "google.content('v2.1');\n",
      "utf8",
    );
    try {
      await symlink(outside, resolve(root, "linked"), "junction");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") {
        return;
      }
      throw error;
    }

    const result = await walkRepository(root);

    expect(result.files).toEqual([]);
    expect(result.complete).toBe(true);
    expect(result.issues).toContainEqual(
      expect.objectContaining({ path: "linked", reason: "symlink" }),
    );
  });

  it("does not extract archives or execute source that requests network or subprocesses", async () => {
    const root = await temporaryRepository();
    const marker = resolve(root, "executed.txt");
    await writeFile(
      resolve(root, "malicious.cjs"),
      [
        'const fs = require("node:fs");',
        `fs.writeFileSync(${JSON.stringify(marker)}, "executed");`,
        'require("node:child_process").spawnSync("node", ["--version"]);',
        'fetch("https://example.invalid/");',
      ].join("\n"),
      "utf8",
    );
    await writeFile(
      resolve(root, "source.zip"),
      "const content = google.content('v2.1');",
      "utf8",
    );

    const result = await walkRepository(root);

    expect(result.files.map((file) => file.path)).toEqual(["malicious.cjs"]);
    expect(result.issues).toContainEqual(
      expect.objectContaining({ path: "source.zip", reason: "archive" }),
    );
    await expect(access(marker)).rejects.toThrow();
  });

  it("marks invalid UTF-8 and size limits as incomplete", async () => {
    const root = await temporaryRepository();
    await writeFile(resolve(root, "bad.ts"), Buffer.from([0xc3, 0x28]));
    await writeFile(resolve(root, "large.ts"), "12345", "utf8");

    const result = await walkRepository(root, { maxFileBytes: 4 });

    expect(result.complete).toBe(false);
    expect(result.files).toEqual([]);
    expect(result.issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: "bad.ts",
          reason: "invalid-utf8",
          incomplete: true,
        }),
        expect.objectContaining({
          path: "large.ts",
          reason: "max-file-size",
          incomplete: true,
        }),
      ]),
    );
  });

  it("enforces file, byte, and entry ceilings", async () => {
    const fileRoot = await temporaryRepository();
    await writeFile(resolve(fileRoot, "a.ts"), "a", "utf8");
    await writeFile(resolve(fileRoot, "b.ts"), "b", "utf8");
    const fileLimited = await walkRepository(fileRoot, { maxFiles: 1 });
    expect(fileLimited.complete).toBe(false);
    expect(fileLimited.issues).toContainEqual(
      expect.objectContaining({ reason: "file-limit", incomplete: true }),
    );

    const byteRoot = await temporaryRepository();
    await writeFile(resolve(byteRoot, "a.ts"), "123", "utf8");
    await writeFile(resolve(byteRoot, "b.ts"), "456", "utf8");
    const byteLimited = await walkRepository(byteRoot, { maxTotalBytes: 4 });
    expect(byteLimited.complete).toBe(false);
    expect(byteLimited.issues).toContainEqual(
      expect.objectContaining({ reason: "max-total-size", incomplete: true }),
    );

    const entryRoot = await temporaryRepository();
    await writeFile(resolve(entryRoot, "a.ts"), "a", "utf8");
    await writeFile(resolve(entryRoot, "b.ts"), "b", "utf8");
    const entryLimited = await walkRepository(entryRoot, { maxEntries: 1 });
    expect(entryLimited.complete).toBe(false);
    expect(entryLimited.issues).toContainEqual(
      expect.objectContaining({ reason: "entry-limit", incomplete: true }),
    );
  });

  it("rejects missing and root-symlink targets", async () => {
    const root = await temporaryRepository();
    await expect(
      walkRepository(resolve(root, "missing")),
    ).rejects.toBeInstanceOf(TraversalError);

    const target = await temporaryRepository();
    const link = resolve(root, "target-link");
    try {
      await symlink(target, link, "junction");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") {
        return;
      }
      throw error;
    }
    await expect(walkRepository(link)).rejects.toThrow(/cannot be a symlink/i);
  });
});

describe("sanitizeForTerminal", () => {
  it("neutralizes ANSI, C1, newlines, and bidirectional overrides", () => {
    const unsafe = "safe\u001b[31m\n\u009b31m\u202efile";
    const safe = sanitizeForTerminal(unsafe);

    expect(safe).toBe(
      "safe\\u001b[31m\\u000a\\u009b31m\\u202efile",
    );
    expect(safe).not.toContain("\u001b");
    expect(safe).not.toContain("\u009b");
    expect(safe).not.toContain("\u202e");
  });
});
