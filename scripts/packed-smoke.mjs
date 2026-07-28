import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const npmCli =
  process.env.npm_execpath ??
  resolve(dirname(process.execPath), "node_modules/npm/bin/npm-cli.js");

function runNode(args, cwd) {
  const result = spawnSync(process.execPath, args, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      NO_COLOR: "1",
    },
  });
  if (result.error) {
    throw result.error;
  }
  return result;
}

function runNpm(args, cwd) {
  return runNode([npmCli, ...args], cwd);
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

const temporaryRoot = await mkdtemp(join(tmpdir(), "cutoverproof-pack-"));
try {
  const packDirectory = resolve(temporaryRoot, "pack");
  const consumerDirectory = resolve(temporaryRoot, "consumer");
  await mkdir(packDirectory);
  await mkdir(consumerDirectory);

  const packed = runNpm(
    ["pack", "--json", "--pack-destination", packDirectory],
    packageRoot,
  );
  assert(packed.status === 0, `npm pack failed:\n${packed.stderr}`);
  const metadata = JSON.parse(packed.stdout)[0];
  const packedPaths = new Set(metadata.files.map((file) => file.path));
  for (const required of [
    "LICENSE",
    "README.md",
    "dist/cli.js",
    "dist/index.js",
    "dist/scanner.js",
    "dist/traverse.js",
    "package.json",
  ]) {
    assert(packedPaths.has(required), `Packed artifact is missing ${required}.`);
  }
  assert(
    ![...packedPaths].some(
      (path) =>
        path.startsWith("src/") ||
        path.startsWith("test/") ||
        path.startsWith("scripts/"),
    ),
    "Packed artifact contains development-only source or test files.",
  );
  for (const runtimeFile of [...packedPaths].filter(
    (path) => path.startsWith("dist/") && path.endsWith(".js"),
  )) {
    const runtimeSource = await readFile(resolve(packageRoot, runtimeFile), "utf8");
    assert(
      !/node:(?:child_process|cluster|dgram|dns|http|https|net|tls|worker_threads)/u.test(
        runtimeSource,
      ),
      `${runtimeFile} imports a network, process, or worker runtime.`,
    );
    assert(
      !/\b(?:eval|fetch|spawn|execFile|execSync)\s*\(/u.test(runtimeSource),
      `${runtimeFile} contains a forbidden execution or network primitive.`,
    );
  }

  const archive = resolve(packDirectory, metadata.filename);
  await writeFile(
    resolve(consumerDirectory, "package.json"),
    '{"name":"cutoverproof-smoke-consumer","private":true,"type":"module"}\n',
    "utf8",
  );
  const installed = runNpm(
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      archive,
    ],
    consumerDirectory,
  );
  assert(installed.status === 0, `Local package install failed:\n${installed.stderr}`);

  const fixture = resolve(consumerDirectory, "legacy.ts");
  await writeFile(
    fixture,
    "const content = google.content({ version: 'v2.1', auth });\n",
    "utf8",
  );
  const installedCli = resolve(
    consumerDirectory,
    "node_modules/cutoverproof/dist/cli.js",
  );
  const bin = runNpm(
    ["exec", "--offline", "--", "cutoverproof", "--version"],
    consumerDirectory,
  );
  assert(bin.status === 0, `Installed bin shim failed:\n${bin.stderr}`);
  assert(bin.stdout.trim() === "0.1.0", "Installed bin shim reported the wrong version.");

  const scan = runNode([installedCli, fixture, "--format", "json"], consumerDirectory);
  assert(scan.status === 1, `Packed CLI returned ${scan.status}, expected 1.`);
  const report = JSON.parse(scan.stdout);
  assert(
    report.riskLevel === "high" || report.riskLevel === "critical",
    "Packed CLI did not detect the legacy fixture.",
  );
  assert(
    !scan.stdout.includes("kingrichard4311.chatgpt.site"),
    "JSON stdout was contaminated by the review CTA.",
  );
  assert(
    scan.stderr.includes("Fixed $249 technical review"),
    "Machine-output CTA was not written to stderr.",
  );

  const installedPackage = JSON.parse(
    await readFile(
      resolve(consumerDirectory, "node_modules/cutoverproof/package.json"),
      "utf8",
    ),
  );
  assert(
    installedPackage.dependencies === undefined ||
      Object.keys(installedPackage.dependencies).length === 0,
    "Packed CLI has runtime dependencies.",
  );
  process.stdout.write(
    `Packed artifact smoke passed: ${metadata.filename} (${metadata.size} bytes)\n`,
  );
} finally {
  await rm(temporaryRoot, { force: true, recursive: true });
}
