#!/usr/bin/env node

import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import {
  exportScanAsCSV,
  exportScanAsJSON,
  exportScanAsMarkdown,
  scanFiles,
  type RiskLevel,
} from "./scanner.js";
import {
  sanitizeForTerminal,
  TraversalError,
  walkRepository,
} from "./traverse.js";
import { CLI_VERSION } from "./version.js";

export const REVIEW_CTA =
  "Fixed $249 technical review (no code changes): https://cutoverproof.rallylive.ca/reserve";

type OutputFormat = "csv" | "json" | "markdown";

export interface CliWriter {
  write(value: string): unknown;
}

export interface CliIO {
  stdout: CliWriter;
  stderr: CliWriter;
}

export interface RunCliOptions {
  cwd?: string;
  io?: CliIO;
}

interface ParsedArguments {
  command: "help" | "scan" | "version";
  format: OutputFormat;
  path: string;
}

class UsageError extends Error {
  override readonly name = "UsageError";
}

const HELP = `CutoverProof ${CLI_VERSION}

Offline static scanner for Google Content API for Shopping migration risks.

Usage:
  cutoverproof [path] [--format markdown|json|csv]
  cutoverproof --help
  cutoverproof --version

Arguments:
  path       Repository directory or source file to scan (default: .)

Options:
  --format   Report format (default: markdown)
  -h, --help
  -v, --version

Exit codes:
  0  Scan complete; no critical or high findings
  1  Scan complete; one or more critical or high findings
  2  Invalid usage, unreadable target, or incomplete scan
`;

function parseFormat(value: string | undefined): OutputFormat {
  if (value === "markdown" || value === "json" || value === "csv") {
    return value;
  }
  throw new UsageError(
    `Invalid format ${value === undefined ? "(missing)" : `"${sanitizeForTerminal(value)}"`}.`,
  );
}

function parseArguments(argv: readonly string[]): ParsedArguments {
  let format: OutputFormat = "markdown";
  let scanPath: string | undefined;
  let optionsEnded = false;

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index] ?? "";
    if (!optionsEnded && argument === "--") {
      optionsEnded = true;
      continue;
    }
    if (!optionsEnded && (argument === "--help" || argument === "-h")) {
      if (argv.length !== 1) {
        throw new UsageError("--help cannot be combined with other arguments.");
      }
      return { command: "help", format, path: "." };
    }
    if (!optionsEnded && (argument === "--version" || argument === "-v")) {
      if (argv.length !== 1) {
        throw new UsageError(
          "--version cannot be combined with other arguments.",
        );
      }
      return { command: "version", format, path: "." };
    }
    if (!optionsEnded && argument === "--format") {
      index += 1;
      format = parseFormat(argv[index]);
      continue;
    }
    if (!optionsEnded && argument.startsWith("--format=")) {
      format = parseFormat(argument.slice("--format=".length));
      continue;
    }
    if (!optionsEnded && argument.startsWith("-")) {
      throw new UsageError(`Unknown option "${sanitizeForTerminal(argument)}".`);
    }
    if (scanPath !== undefined) {
      throw new UsageError("Only one scan path may be provided.");
    }
    scanPath = argument;
  }

  return {
    command: "scan",
    format,
    path: scanPath ?? ".",
  };
}

function formatResult(
  format: OutputFormat,
  result: ReturnType<typeof scanFiles>,
): string {
  if (format === "json") {
    return exportScanAsJSON(result);
  }
  if (format === "csv") {
    return exportScanAsCSV(result);
  }
  return `${exportScanAsMarkdown(result).trimEnd()}\n\n---\n\n${REVIEW_CTA}\n`;
}

function hasHighRisk(level: RiskLevel): boolean {
  return level === "critical" || level === "high";
}

function defaultIO(): CliIO {
  return {
    stdout: process.stdout,
    stderr: process.stderr,
  };
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return sanitizeForTerminal(error.message);
  }
  return sanitizeForTerminal(String(error));
}

export async function runCli(
  argv: readonly string[],
  options: RunCliOptions = {},
): Promise<number> {
  const io = options.io ?? defaultIO();
  let parsed: ParsedArguments;
  try {
    parsed = parseArguments(argv);
  } catch (error) {
    io.stderr.write(`cutoverproof: ${errorMessage(error)}\n`);
    io.stderr.write("Run cutoverproof --help for usage.\n");
    return 2;
  }

  if (parsed.command === "help") {
    io.stdout.write(HELP);
    return 0;
  }
  if (parsed.command === "version") {
    io.stdout.write(`${CLI_VERSION}\n`);
    return 0;
  }

  try {
    const target = resolve(options.cwd ?? process.cwd(), parsed.path);
    const walked = await walkRepository(target);
    const result = scanFiles(walked.files);
    io.stdout.write(formatResult(parsed.format, result));
    if (parsed.format !== "markdown") {
      io.stderr.write(`${REVIEW_CTA}\n`);
    }

    if (!walked.complete) {
      const incomplete = walked.issues.filter((issue) => issue.incomplete);
      io.stderr.write(
        `cutoverproof: scan incomplete (${incomplete.length} blocking skip${incomplete.length === 1 ? "" : "s"}).\n`,
      );
      for (const issue of incomplete.slice(0, 20)) {
        io.stderr.write(
          `cutoverproof: ${issue.path}: ${sanitizeForTerminal(issue.detail)}\n`,
        );
      }
      if (incomplete.length > 20) {
        io.stderr.write(
          `cutoverproof: ${incomplete.length - 20} additional blocking skips omitted.\n`,
        );
      }
      return 2;
    }
    return hasHighRisk(result.riskLevel) ? 1 : 0;
  } catch (error) {
    const prefix =
      error instanceof TraversalError
        ? "scan could not start"
        : "unexpected scan failure";
    io.stderr.write(`cutoverproof: ${prefix}: ${errorMessage(error)}\n`);
    return 2;
  }
}

const entryPath = process.argv[1];
if (
  entryPath !== undefined &&
  import.meta.url === pathToFileURL(resolve(entryPath)).href
) {
  process.exitCode = await runCli(process.argv.slice(2));
}
