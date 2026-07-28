import { constants } from "node:fs";
import { lstat, open, readdir, realpath } from "node:fs/promises";
import {
  basename,
  isAbsolute,
  relative,
  resolve,
  sep,
} from "node:path";
import { TextDecoder } from "node:util";

import type { ScanInputFile } from "./scanner.js";

export const WALK_LIMITS = Object.freeze({
  maxFiles: 2_500,
  maxFileBytes: 2 * 1024 * 1024,
  maxTotalBytes: 25 * 1024 * 1024,
  maxEntries: 50_000,
});

export type TraversalSkipReason =
  | "archive"
  | "entry-limit"
  | "excluded-directory"
  | "excluded-file"
  | "file-limit"
  | "invalid-utf8"
  | "max-file-size"
  | "max-total-size"
  | "sensitive-file"
  | "symlink"
  | "unreadable"
  | "unsupported-entry";

export interface TraversalIssue {
  path: string;
  reason: TraversalSkipReason;
  detail: string;
  incomplete: boolean;
}

export interface WalkOptions {
  maxFiles?: number;
  maxFileBytes?: number;
  maxTotalBytes?: number;
  maxEntries?: number;
}

export interface WalkResult {
  root: string;
  files: ScanInputFile[];
  issues: TraversalIssue[];
  complete: boolean;
  stats: {
    entriesVisited: number;
    filesRead: number;
    bytesRead: number;
    entriesSkipped: number;
  };
}

const EXCLUDED_DIRECTORIES = new Set([
  ".cache",
  ".git",
  ".hg",
  ".next",
  ".nuxt",
  ".svn",
  ".venv",
  "__pycache__",
  "bin",
  "build",
  "cache",
  "coverage",
  "dist",
  "generated",
  "node_modules",
  "obj",
  "target",
  "vendor",
  "venv",
]);

const EXCLUDED_FILES = new Set([
  ".npmrc",
  ".pypirc",
  "bun.lock",
  "composer.lock",
  "package-lock.json",
  "pnpm-lock.yaml",
  "poetry.lock",
  "uv.lock",
  "yarn.lock",
]);

const ARCHIVE_EXTENSIONS = new Set([
  ".7z",
  ".bz2",
  ".ear",
  ".gz",
  ".jar",
  ".rar",
  ".tar",
  ".tgz",
  ".war",
  ".xz",
  ".zip",
]);

const BINARY_EXTENSIONS = new Set([
  ".avi",
  ".bin",
  ".bmp",
  ".class",
  ".dll",
  ".doc",
  ".docx",
  ".eot",
  ".exe",
  ".gif",
  ".ico",
  ".jpeg",
  ".jpg",
  ".mov",
  ".mp3",
  ".mp4",
  ".otf",
  ".pdf",
  ".png",
  ".pyc",
  ".so",
  ".tiff",
  ".ttf",
  ".webm",
  ".webp",
  ".woff",
  ".woff2",
  ".xls",
  ".xlsx",
]);

const UNSAFE_OUTPUT_CHARACTERS =
  /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/gu;

function positiveInteger(value: number | undefined, fallback: number): number {
  if (value === undefined || !Number.isFinite(value)) {
    return fallback;
  }
  return Math.max(1, Math.floor(value));
}

function escapeCodePoint(character: string): string {
  const codePoint = character.codePointAt(0) ?? 0;
  return codePoint <= 0xffff
    ? `\\u${codePoint.toString(16).padStart(4, "0")}`
    : `\\u{${codePoint.toString(16)}}`;
}

/**
 * Converts terminal controls and bidirectional overrides to visible escapes.
 * The returned text cannot contain an ANSI escape sequence.
 */
export function sanitizeForTerminal(value: string): string {
  return value.replace(UNSAFE_OUTPUT_CHARACTERS, escapeCodePoint);
}

function normalizeDisplayPath(value: string): string {
  const normalized = value.split(sep).join("/").replace(/\/+/g, "/");
  return sanitizeForTerminal(normalized.replace(/^\.\//, "") || ".");
}

function isSensitiveFile(name: string): boolean {
  const lower = name.toLowerCase();
  if (lower === ".env" || lower.startsWith(".env.")) {
    return true;
  }
  if (lower === ".npmrc" || lower === ".pypirc") {
    return true;
  }
  if (!lower.endsWith(".json")) {
    return false;
  }
  return (
    /(?:^|[-_.])credentials?(?:[-_.]|$)/u.test(lower) ||
    /(?:^|[-_.])service[-_.]?account(?:[-_.]|$)/u.test(lower) ||
    /(?:^|[-_.])client[-_.]?secret(?:[-_.]|$)/u.test(lower) ||
    /(?:^|[-_.])private[-_.]?key(?:[-_.]|$)/u.test(lower) ||
    /(?:^|[-_.])secrets?(?:[-_.]|$)/u.test(lower)
  );
}

function hasExtension(name: string, extensions: ReadonlySet<string>): boolean {
  const lower = name.toLowerCase();
  for (const extension of extensions) {
    if (lower.endsWith(extension)) {
      return true;
    }
  }
  return false;
}

function insideRoot(root: string, candidate: string): boolean {
  const child = relative(root, candidate);
  return (
    child === "" ||
    (!isAbsolute(child) && child !== ".." && !child.startsWith(`..${sep}`))
  );
}

function compareNames(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export class TraversalError extends Error {
  override readonly name = "TraversalError";
}

export async function walkRepository(
  inputPath: string,
  options: WalkOptions = {},
): Promise<WalkResult> {
  const limits = {
    maxFiles: positiveInteger(options.maxFiles, WALK_LIMITS.maxFiles),
    maxFileBytes: positiveInteger(
      options.maxFileBytes,
      WALK_LIMITS.maxFileBytes,
    ),
    maxTotalBytes: positiveInteger(
      options.maxTotalBytes,
      WALK_LIMITS.maxTotalBytes,
    ),
    maxEntries: positiveInteger(options.maxEntries, WALK_LIMITS.maxEntries),
  };
  const root = resolve(inputPath);
  let rootStat;
  try {
    rootStat = await lstat(root);
  } catch {
    throw new TraversalError(
      `Cannot read scan target: ${sanitizeForTerminal(inputPath)}`,
    );
  }
  if (rootStat.isSymbolicLink()) {
    throw new TraversalError("The scan target itself cannot be a symlink.");
  }
  if (!rootStat.isDirectory() && !rootStat.isFile()) {
    throw new TraversalError("The scan target must be a regular file or directory.");
  }

  let canonicalRoot: string;
  try {
    canonicalRoot = rootStat.isDirectory()
      ? await realpath(root)
      : await realpath(resolve(root, ".."));
  } catch {
    throw new TraversalError(
      `Cannot resolve scan target: ${sanitizeForTerminal(inputPath)}`,
    );
  }

  const files: ScanInputFile[] = [];
  const issues: TraversalIssue[] = [];
  let entriesVisited = 0;
  let bytesRead = 0;
  let aborted = false;

  const displayPath = (absolutePath: string): string => {
    if (rootStat.isFile()) {
      return normalizeDisplayPath(basename(absolutePath));
    }
    return normalizeDisplayPath(relative(root, absolutePath));
  };

  const addIssue = (
    absolutePath: string,
    reason: TraversalSkipReason,
    detail: string,
    incomplete: boolean,
  ): void => {
    issues.push({
      path: displayPath(absolutePath),
      reason,
      detail,
      incomplete,
    });
  };

  const visitFile = async (absolutePath: string): Promise<void> => {
    const name = basename(absolutePath);
    if (isSensitiveFile(name)) {
      addIssue(
        absolutePath,
        "sensitive-file",
        "Skipped by the local credential-file safety policy.",
        false,
      );
      return;
    }
    if (EXCLUDED_FILES.has(name.toLowerCase())) {
      addIssue(
        absolutePath,
        "excluded-file",
        "Skipped generated dependency metadata.",
        false,
      );
      return;
    }
    if (hasExtension(name, ARCHIVE_EXTENSIONS)) {
      addIssue(
        absolutePath,
        "archive",
        "Archive files are not opened or extracted.",
        false,
      );
      return;
    }
    if (hasExtension(name, BINARY_EXTENSIONS)) {
      addIssue(
        absolutePath,
        "excluded-file",
        "Known binary file type was not decoded.",
        false,
      );
      return;
    }
    if (files.length >= limits.maxFiles) {
      addIssue(
        absolutePath,
        "file-limit",
        `The ${limits.maxFiles}-file safety limit was reached.`,
        true,
      );
      aborted = true;
      return;
    }

    let canonicalFile: string;
    try {
      canonicalFile = await realpath(absolutePath);
    } catch {
      addIssue(
        absolutePath,
        "unreadable",
        "The file could not be resolved.",
        true,
      );
      return;
    }
    if (!insideRoot(canonicalRoot, canonicalFile)) {
      addIssue(
        absolutePath,
        "symlink",
        "The resolved file is outside the scan target.",
        false,
      );
      return;
    }

    let handle;
    try {
      const noFollow = constants.O_NOFOLLOW ?? 0;
      handle = await open(
        absolutePath,
        constants.O_RDONLY | noFollow,
      );
      const fileStat = await handle.stat();
      if (!fileStat.isFile()) {
        addIssue(
          absolutePath,
          "unsupported-entry",
          "Only regular files are read.",
          false,
        );
        return;
      }
      if (fileStat.size > limits.maxFileBytes) {
        addIssue(
          absolutePath,
          "max-file-size",
          `File exceeds the ${limits.maxFileBytes}-byte per-file limit.`,
          true,
        );
        return;
      }
      if (bytesRead + fileStat.size > limits.maxTotalBytes) {
        addIssue(
          absolutePath,
          "max-total-size",
          `File would exceed the ${limits.maxTotalBytes}-byte total limit.`,
          true,
        );
        return;
      }

      const buffer = await handle.readFile();
      if (buffer.byteLength > limits.maxFileBytes) {
        addIssue(
          absolutePath,
          "max-file-size",
          `File changed while reading and exceeds the ${limits.maxFileBytes}-byte limit.`,
          true,
        );
        return;
      }
      if (bytesRead + buffer.byteLength > limits.maxTotalBytes) {
        addIssue(
          absolutePath,
          "max-total-size",
          `File would exceed the ${limits.maxTotalBytes}-byte total limit.`,
          true,
        );
        return;
      }

      let content: string;
      try {
        content = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
      } catch {
        addIssue(
          absolutePath,
          "invalid-utf8",
          "File is not valid UTF-8 and was not decoded.",
          true,
        );
        return;
      }
      files.push({ path: displayPath(absolutePath), content });
      bytesRead += buffer.byteLength;
    } catch {
      addIssue(
        absolutePath,
        "unreadable",
        "The file could not be read.",
        true,
      );
    } finally {
      await handle?.close().catch(() => undefined);
    }
  };

  const visit = async (absolutePath: string, isRoot = false): Promise<void> => {
    if (aborted) {
      return;
    }
    if (!isRoot) {
      entriesVisited += 1;
      if (entriesVisited > limits.maxEntries) {
        addIssue(
          absolutePath,
          "entry-limit",
          `The ${limits.maxEntries}-entry traversal limit was reached.`,
          true,
        );
        aborted = true;
        return;
      }
    }

    let entryStat;
    try {
      entryStat = await lstat(absolutePath);
    } catch {
      addIssue(
        absolutePath,
        "unreadable",
        "The directory entry could not be inspected.",
        true,
      );
      return;
    }
    if (entryStat.isSymbolicLink()) {
      addIssue(
        absolutePath,
        "symlink",
        "Symbolic links are not followed.",
        false,
      );
      return;
    }
    if (entryStat.isFile()) {
      await visitFile(absolutePath);
      return;
    }
    if (!entryStat.isDirectory()) {
      addIssue(
        absolutePath,
        "unsupported-entry",
        "Only regular files and directories are scanned.",
        false,
      );
      return;
    }

    const directoryName = basename(absolutePath).toLowerCase();
    if (!isRoot && EXCLUDED_DIRECTORIES.has(directoryName)) {
      addIssue(
        absolutePath,
        "excluded-directory",
        "Skipped vendored, generated, cache, or build directory.",
        false,
      );
      return;
    }

    let entries;
    try {
      entries = await readdir(absolutePath, { withFileTypes: true });
    } catch {
      addIssue(
        absolutePath,
        "unreadable",
        "The directory could not be read.",
        true,
      );
      return;
    }
    entries.sort((left, right) => compareNames(left.name, right.name));
    for (const entry of entries) {
      await visit(resolve(absolutePath, entry.name));
      if (aborted) {
        break;
      }
    }
  };

  await visit(root, true);
  files.sort((left, right) => compareNames(left.path, right.path));
  issues.sort(
    (left, right) =>
      compareNames(left.path, right.path) ||
      compareNames(left.reason, right.reason),
  );

  return {
    root,
    files,
    issues,
    complete: !issues.some((issue) => issue.incomplete),
    stats: {
      entriesVisited,
      filesRead: files.length,
      bytesRead,
      entriesSkipped: issues.length,
    },
  };
}
