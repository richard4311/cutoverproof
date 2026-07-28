/**
 * CutoverProof's browser-only static scanner.
 *
 * The scanner deliberately accepts in-memory source files. It does not read
 * paths, execute source, make network requests, or depend on Node APIs.
 */

export const SCANNER_VERSION = "1.1.0";

export interface ScanInputFile {
  path: string;
  content: string;
}

/** Backwards-friendly name used by the upload UI. */
export type SourceFile = ScanInputFile;

export type FindingSeverity = "critical" | "high" | "medium" | "low";
export type RiskLevel = "none" | "low" | "medium" | "high" | "critical";

export type FindingCategory =
  | "credential"
  | "legacy-client"
  | "legacy-endpoint"
  | "legacy-method"
  | "batching"
  | "price"
  | "product-id"
  | "dependency";

export type SourceLanguage =
  | "apps-script"
  | "gradle"
  | "java"
  | "javascript"
  | "json"
  | "php"
  | "python"
  | "typescript"
  | "xml"
  | "text"
  | "unknown";

export interface ScanFinding {
  /** Stable for the same rule and source location. */
  id: string;
  ruleId: string;
  category: FindingCategory;
  severity: FindingSeverity;
  title: string;
  description: string;
  file: string;
  line: number;
  column: number;
  /** A single, bounded source line. Credential-like values are always redacted. */
  evidence: string;
  recommendation: string;
  language: SourceLanguage;
  tags: string[];
}

export type SkipReason =
  | "binary"
  | "default-exclusion"
  | "excluded-by-option"
  | "file-limit"
  | "invalid-input"
  | "max-file-size"
  | "max-total-size"
  | "unsupported-type";

export interface SkippedFile {
  path: string;
  reason: SkipReason;
  detail: string;
  bytes?: number;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ScanSummary {
  totalFindings: number;
  filesWithFindings: number;
  highestSeverity: FindingSeverity | null;
  bySeverity: SeverityCounts;
  byCategory: Record<string, number>;
  message: string;
}

export interface RecommendedAction {
  id: string;
  priority: "urgent" | "high" | "medium" | "low";
  title: string;
  description: string;
  relatedFindingIds: string[];
}

export interface ScanStats {
  inputFiles: number;
  scannedFiles: number;
  /** UI-friendly alias of scannedFiles. */
  filesScanned: number;
  skippedFiles: number;
  bytesScanned: number;
  highRiskFindings: number;
  categoriesDetected: number;
  findingsTruncated: boolean;
  omittedFindings: number;
}

export interface ScanResult {
  scannerVersion: string;
  riskScore: number;
  riskLevel: RiskLevel;
  summary: ScanSummary;
  findings: ScanFinding[];
  recommendedActions: RecommendedAction[];
  skipped: SkippedFile[];
  warnings: string[];
  stats: ScanStats;
}

export interface ScannerOptions {
  /** Maximum number of non-excluded files inspected. */
  maxFiles?: number;
  /** UTF-8 byte limit for any one file. */
  maxFileBytes?: number;
  /** UTF-8 byte limit across all inspected files. */
  maxTotalBytes?: number;
  /** Maximum number of findings returned. */
  maxFindings?: number;
  /** Disable only when the caller has already removed vendored/generated files. */
  includeDefaultExclusions?: boolean;
  /** Case-insensitive substrings or regular expressions matched against `/` paths. */
  excludePaths?: readonly (string | RegExp)[];
}

export const DEFAULT_SCAN_LIMITS = Object.freeze({
  maxFiles: 2_500,
  maxFileBytes: 2 * 1024 * 1024,
  maxTotalBytes: 25 * 1024 * 1024,
  maxFindings: 500,
});

interface ResolvedOptions {
  maxFiles: number;
  maxFileBytes: number;
  maxTotalBytes: number;
  maxFindings: number;
  includeDefaultExclusions: boolean;
  excludePaths: readonly (string | RegExp)[];
}

interface CandidateFinding extends Omit<ScanFinding, "id"> {
  identity?: string;
}

interface FileContext {
  path: string;
  content: string;
  lines: string[];
  language: SourceLanguage;
  legacyContext: boolean;
  merchantContext: boolean;
}

interface StaticRule {
  ruleId: string;
  category: FindingCategory;
  severity: FindingSeverity;
  title: string;
  description: string;
  recommendation: string;
  regex: RegExp;
  languages?: readonly SourceLanguage[];
  requiresLegacyContext?: boolean;
  tags: readonly string[];
}

const DEFAULT_EXCLUDED_DIRECTORIES = new Set([
  ".git",
  ".hg",
  ".next",
  ".nuxt",
  ".svn",
  ".venv",
  "__pycache__",
  "bin",
  "build",
  "coverage",
  "dist",
  "generated",
  "node_modules",
  "obj",
  "target",
  "vendor",
  "venv",
]);

const DEFAULT_EXCLUDED_FILES = new Set([
  "bun.lock",
  "composer.lock",
  "package-lock.json",
  "pnpm-lock.yaml",
  "poetry.lock",
  "uv.lock",
  "yarn.lock",
]);

const BINARY_EXTENSIONS = new Set([
  "7z",
  "avi",
  "bin",
  "bmp",
  "class",
  "dll",
  "doc",
  "docx",
  "eot",
  "exe",
  "gif",
  "gz",
  "ico",
  "jar",
  "jpeg",
  "jpg",
  "mov",
  "mp3",
  "mp4",
  "otf",
  "pdf",
  "png",
  "pyc",
  "so",
  "tar",
  "tiff",
  "ttf",
  "webm",
  "webp",
  "woff",
  "woff2",
  "xls",
  "xlsx",
  "zip",
]);

const LEGACY_RESOURCES = [
  "accounts",
  "accountshipping",
  "accountstatuses",
  "accounttax",
  "datafeeds",
  "datafeedstatuses",
  "liasettings",
  "localinventory",
  "orderreturns",
  "orders",
  "pos",
  "products",
  "productstatuses",
  "pubsubnotificationsettings",
  "quotas",
  "regionalinventory",
  "returnpolicyonline",
  "settlementreports",
] as const;

const LEGACY_METHODS = [
  "approve",
  "claim",
  "close",
  "custombatch",
  "delete",
  "get",
  "insert",
  "link",
  "list",
  "listproducts",
  "patch",
  "requestphoneverification",
  "returnrefundlineitem",
  "setlabels",
  "unclaim",
  "unlink",
  "update",
  "updatemerchantorderid",
  "updatestatus",
  "verifyphonenumber",
] as const;

const LEGACY_RESOURCE_METHOD = new RegExp(
  `\\b(${LEGACY_RESOURCES.join("|")})\\s*(?:\\(\\s*\\))?\\s*(?:\\.|->)\\s*(${LEGACY_METHODS.join(
    "|",
  )})\\s*\\(`,
  "gi",
);

const STATIC_RULES: readonly StaticRule[] = [
  {
    ruleId: "node-content-client",
    category: "legacy-client",
    severity: "high",
    title: "Legacy Node Content API client",
    description:
      "This constructs the Content API for Shopping client instead of a Merchant API service client.",
    recommendation:
      "Replace the Content API client with the relevant Merchant API service clients and map authentication, pagination, and errors.",
    regex: /\bgoogle\s*\.\s*content\s*\(/i,
    languages: ["javascript", "typescript"],
    tags: ["node", "content-api"],
  },
  {
    ruleId: "node-shopping-content-client",
    category: "legacy-client",
    severity: "high",
    title: "Legacy Node Content API discovery client",
    description:
      "This discovery call selects the Content API for Shopping service.",
    recommendation:
      "Create Merchant API service clients explicitly and verify each resource's new request and response shape.",
    regex: /\bgoogle\s*\.\s*shopping\s*\(\s*["']content["']/i,
    languages: ["javascript", "typescript"],
    tags: ["node", "content-api"],
  },
  {
    ruleId: "python-content-discovery",
    category: "legacy-client",
    severity: "high",
    title: "Legacy Python Content API discovery client",
    description:
      "This Python discovery client is built for the Content API v2/v2.1 surface.",
    recommendation:
      "Replace discovery calls with the appropriate Merchant API Python service clients and preserve retry and pagination behavior.",
    regex:
      /\b(?:discovery\s*\.\s*)?build\s*\(\s*["']content["']\s*,\s*["']v2(?:\.1)?["']/i,
    languages: ["python"],
    tags: ["python", "content-api"],
  },
  {
    ruleId: "java-shopping-content-client",
    category: "legacy-client",
    severity: "high",
    title: "Legacy Java ShoppingContent client",
    description:
      "This imports or constructs the Java Content API for Shopping client.",
    recommendation:
      "Replace ShoppingContent services and models with Merchant API clients and regenerate model mapping tests.",
    regex:
      /\bcom\.google\.api\.services\.content\b|\b(?:new\s+)?ShoppingContent\s*\.\s*Builder\b/i,
    languages: ["java", "gradle", "xml"],
    tags: ["java", "content-api"],
  },
  {
    ruleId: "php-shopping-content-client",
    category: "legacy-client",
    severity: "high",
    title: "Legacy PHP ShoppingContent service",
    description:
      "This references the PHP Content API for Shopping service or namespace.",
    recommendation:
      "Replace the ShoppingContent service and models with Merchant API equivalents, including page-token and error handling.",
    regex:
      /\bGoogle_(?:Service_)?ShoppingContent\b|\bGoogle\\Service\\ShoppingContent\b/i,
    languages: ["php"],
    tags: ["php", "content-api"],
  },
  {
    ruleId: "apps-script-shopping-content",
    category: "legacy-client",
    severity: "high",
    title: "Legacy Apps Script ShoppingContent service",
    description:
      "This uses the Apps Script advanced ShoppingContent service.",
    recommendation:
      "Replace this advanced-service call with a Merchant API integration and account for Apps Script authentication and quotas.",
    regex:
      /\bShoppingContent\s*\.\s*(?:Accounts|Accountshipping|Accountstatuses|Accounttax|Datafeeds|Datafeedstatuses|Liasettings|Localinventory|Orders|Products|Productstatuses|Regionalinventory)\b/i,
    languages: ["apps-script", "javascript", "typescript"],
    tags: ["apps-script", "content-api"],
  },
  {
    ruleId: "apps-script-content-manifest",
    category: "dependency",
    severity: "high",
    title: "Legacy Apps Script Content API dependency",
    description:
      "The Apps Script manifest enables the legacy Content API advanced service.",
    recommendation:
      "Remove the Content API advanced-service dependency after the replacement Merchant API path is verified.",
    regex: /["']serviceId["']\s*:\s*["']content["']/i,
    languages: ["json", "apps-script", "javascript"],
    tags: ["apps-script", "dependency"],
  },
  {
    ruleId: "content-api-rest-endpoint",
    category: "legacy-endpoint",
    severity: "high",
    title: "Legacy Content API REST endpoint",
    description:
      "This URL targets the Content API v2/v2.1 REST surface.",
    recommendation:
      "Map this request to its Merchant API service endpoint and verify resource names, fields, pagination, errors, and scopes.",
    regex:
      /https?:\/\/(?:(?:shoppingcontent|content)\.googleapis\.com|www\.googleapis\.com)\/content\/v2(?:\.1)?(?:\/|[?"'\s]|$)/i,
    tags: ["rest", "content-api"],
  },
  {
    ruleId: "content-api-relative-endpoint",
    category: "legacy-endpoint",
    severity: "high",
    title: "Legacy Content API relative REST path",
    description:
      "This path targets a v2/v2.1 Content API resource.",
    recommendation:
      "Replace the path with the correct Merchant API service endpoint and new resource name.",
    regex:
      /["'`]\/content\/v2(?:\.1)?\/(?:[^/"'`\s]+\/)?(?:accounts|datafeeds|products|productstatuses|orders)\b/i,
    tags: ["rest", "content-api"],
  },
  {
    ruleId: "node-content-dependency",
    category: "dependency",
    severity: "high",
    title: "Legacy @googleapis/content dependency",
    description:
      "This dependency packages the Content API for Shopping client.",
    recommendation:
      "Replace this dependency with supported Merchant API client packages and remove it only after legacy calls reach zero.",
    regex: /["']@googleapis\/content["']|@googleapis\/content(?:@|\s|$)/i,
    languages: ["json", "javascript", "typescript", "text"],
    tags: ["node", "dependency"],
  },
  {
    ruleId: "java-content-dependency",
    category: "dependency",
    severity: "high",
    title: "Legacy Java Content API dependency",
    description:
      "This build dependency supplies the generated Content API for Shopping Java client.",
    recommendation:
      "Replace this artifact with supported Merchant API libraries and pin an explicitly supported release.",
    regex: /\bgoogle-api-services-content\b/i,
    languages: ["gradle", "java", "xml", "text"],
    tags: ["java", "dependency"],
  },
  {
    ruleId: "python-content-dependency",
    category: "dependency",
    severity: "high",
    title: "Legacy Python Shopping Content dependency",
    description:
      "This package is tied to the legacy Shopping Content client surface.",
    recommendation:
      "Replace the package with supported Merchant API Python clients and lock the selected release.",
    regex: /\bgoogle-(?:cloud-)?shopping-content\b/i,
    languages: ["python", "text"],
    tags: ["python", "dependency"],
  },
  {
    ruleId: "python-discovery-dependency",
    category: "dependency",
    severity: "low",
    title: "Google API discovery dependency needs an audit",
    description:
      "google-api-python-client can host Content API discovery calls, but may also be used by unrelated Google APIs.",
    recommendation:
      "Trace this dependency's call sites; remove or retain it based on verified non-Content-API usage.",
    regex: /^\s*google-api-python-client(?:\s*[=<>~!].*)?$/i,
    languages: ["python", "text"],
    tags: ["python", "dependency", "audit"],
  },
  {
    ruleId: "php-discovery-dependency",
    category: "dependency",
    severity: "low",
    title: "Google PHP services dependency needs an audit",
    description:
      "google/apiclient-services may provide ShoppingContent classes, but can also serve unrelated Google APIs.",
    recommendation:
      "Trace instantiated services before removing or replacing this shared package.",
    regex: /["']google\/apiclient-services["']/i,
    languages: ["json", "php", "text"],
    tags: ["php", "dependency", "audit"],
  },
  {
    ruleId: "legacy-price-model-java",
    category: "price",
    severity: "medium",
    title: "Legacy Java Price model",
    description:
      "The Content API Price model stores decimal text in value/currency fields.",
    recommendation:
      "Map prices to integer amountMicros and currencyCode without floating-point rounding.",
    regex:
      /\bcom\.google\.api\.services\.content\.model\.Price\b|\bnew\s+Price\s*\(\s*\)\s*\.setValue\s*\(/i,
    languages: ["java"],
    requiresLegacyContext: true,
    tags: ["java", "price"],
  },
  {
    ruleId: "legacy-price-model-php",
    category: "price",
    severity: "medium",
    title: "Legacy PHP Price model",
    description:
      "The ShoppingContent Price model uses legacy value/currency fields.",
    recommendation:
      "Convert decimal price strings to integer amountMicros with an exact decimal routine, then map currencyCode.",
    regex:
      /\bGoogle_(?:Service_)?ShoppingContent_Price\b|\bShoppingContent\\Price\b/i,
    languages: ["php"],
    requiresLegacyContext: true,
    tags: ["php", "price"],
  },
] as const;

const SEVERITY_ORDER: Record<FindingSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

const SEVERITY_WEIGHT: Record<FindingSeverity, number> = {
  critical: 32,
  high: 18,
  medium: 8,
  low: 3,
};

const SEVERITY_SCORE_FLOOR: Record<FindingSeverity, number> = {
  critical: 80,
  high: 50,
  medium: 25,
  low: 10,
};

function positiveInteger(
  value: number | undefined,
  fallback: number,
): number {
  if (value === undefined || !Number.isFinite(value)) {
    return fallback;
  }
  return Math.max(1, Math.floor(value));
}

function resolveOptions(options: ScannerOptions): ResolvedOptions {
  return {
    maxFiles: positiveInteger(options.maxFiles, DEFAULT_SCAN_LIMITS.maxFiles),
    maxFileBytes: positiveInteger(
      options.maxFileBytes,
      DEFAULT_SCAN_LIMITS.maxFileBytes,
    ),
    maxTotalBytes: positiveInteger(
      options.maxTotalBytes,
      DEFAULT_SCAN_LIMITS.maxTotalBytes,
    ),
    maxFindings: positiveInteger(
      options.maxFindings,
      DEFAULT_SCAN_LIMITS.maxFindings,
    ),
    includeDefaultExclusions: options.includeDefaultExclusions !== false,
    excludePaths: options.excludePaths ?? [],
  };
}

const UNSAFE_OUTPUT_CHARACTERS =
  /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/gu;

function escapeOutputCharacter(character: string): string {
  const codePoint = character.codePointAt(0) ?? 0;
  return codePoint <= 0xffff
    ? `\\u${codePoint.toString(16).padStart(4, "0")}`
    : `\\u{${codePoint.toString(16)}}`;
}

function sanitizeOutputText(value: string): string {
  return value.replace(UNSAFE_OUTPUT_CHARACTERS, escapeOutputCharacter);
}

function normalizePath(path: string): string {
  const normalized = path.replace(/\\/g, "/").replace(/\/+/g, "/");
  return sanitizeOutputText(normalized.replace(/^\.\//, "") || "(unnamed)");
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function utf8ByteLength(value: string): number {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x80) {
      bytes += 1;
    } else if (code < 0x800) {
      bytes += 2;
    } else if (
      code >= 0xd800 &&
      code <= 0xdbff &&
      index + 1 < value.length &&
      value.charCodeAt(index + 1) >= 0xdc00 &&
      value.charCodeAt(index + 1) <= 0xdfff
    ) {
      bytes += 4;
      index += 1;
    } else {
      bytes += 3;
    }
  }
  return bytes;
}

function defaultExclusion(path: string): string | null {
  const lowerPath = path.toLowerCase();
  const parts = lowerPath.split("/");
  if (parts.some((part) => DEFAULT_EXCLUDED_DIRECTORIES.has(part))) {
    return "vendored, generated, cache, or build directory";
  }

  const basename = parts.at(-1) ?? lowerPath;
  if (DEFAULT_EXCLUDED_FILES.has(basename)) {
    return "lock file";
  }
  if (
    basename.endsWith(".map") ||
    basename.endsWith(".min.js") ||
    basename.endsWith(".min.css")
  ) {
    return "generated or minified asset";
  }

  const extension = basename.includes(".")
    ? (basename.split(".").at(-1) ?? "")
    : "";
  if (BINARY_EXTENSIONS.has(extension)) {
    return "known binary file type";
  }
  return null;
}

function optionExcludes(
  path: string,
  patterns: readonly (string | RegExp)[],
): boolean {
  const lowerPath = path.toLowerCase();
  return patterns.some((pattern) => {
    if (typeof pattern === "string") {
      return lowerPath.includes(normalizePath(pattern).toLowerCase());
    }
    pattern.lastIndex = 0;
    return pattern.test(path);
  });
}

function isProbablyBinary(content: string): boolean {
  if (content.includes("\0")) {
    return true;
  }
  const sampleLength = Math.min(content.length, 8_192);
  if (sampleLength === 0) {
    return false;
  }
  let controls = 0;
  for (let index = 0; index < sampleLength; index += 1) {
    const code = content.charCodeAt(index);
    if (
      (code >= 0 && code < 7) ||
      (code > 13 && code < 32) ||
      code === 0x7f
    ) {
      controls += 1;
    }
  }
  return controls / sampleLength > 0.1;
}

function languageFor(path: string): SourceLanguage {
  const lower = path.toLowerCase();
  const basename = lower.split("/").at(-1) ?? lower;
  if (basename === "pom.xml") return "xml";
  if (basename.endsWith(".gradle") || basename.endsWith(".gradle.kts")) {
    return "gradle";
  }
  if (
    basename === "requirements.txt" ||
    basename === "pyproject.toml" ||
    basename === "pipfile"
  ) {
    return "python";
  }
  if (basename === "composer.json" || basename === "package.json") return "json";
  const extension = basename.includes(".")
    ? (basename.split(".").at(-1) ?? "")
    : "";
  switch (extension) {
    case "gs":
      return "apps-script";
    case "java":
      return "java";
    case "js":
    case "cjs":
    case "mjs":
    case "jsx":
      return "javascript";
    case "json":
      return "json";
    case "php":
      return "php";
    case "py":
      return "python";
    case "ts":
    case "tsx":
    case "mts":
    case "cts":
      return "typescript";
    case "xml":
      return "xml";
    case "txt":
    case "toml":
    case "yaml":
    case "yml":
      return "text";
    default:
      return "unknown";
  }
}

function hasLegacyContext(content: string): boolean {
  return (
    /\bShoppingContent\b/i.test(content) ||
    /\bgoogle\s*\.\s*content\s*\(/i.test(content) ||
    /\bbuild\s*\(\s*["']content["']\s*,\s*["']v2(?:\.1)?["']/i.test(
      content,
    ) ||
    /(?:shoppingcontent|content)\.googleapis\.com\/content\/v2/i.test(content) ||
    /www\.googleapis\.com\/content\/v2/i.test(content) ||
    /@googleapis\/content\b/i.test(content) ||
    /google-api-services-content\b/i.test(content) ||
    /\bcom\.google\.api\.services\.content\b/i.test(content) ||
    /["']serviceId["']\s*:\s*["']content["']/i.test(content) ||
    /\b(?:content|service)\s*(?:\.|->)\s*(?:accounts|datafeeds|products|productstatuses)\b/i.test(
      content,
    )
  );
}

function hasMerchantContext(content: string): boolean {
  return (
    /\bmerchant\s*api\b/i.test(content) ||
    /\bmerchantapi\.googleapis\.com\b/i.test(content) ||
    /\bgoogle\.shopping\.[A-Za-z0-9_.]*_v1(?:beta)?\b/i.test(content) ||
    /\bcom\.google\.shopping\.merchant\b/i.test(content) ||
    /@google-shopping\//i.test(content)
  );
}

function redactSecrets(value: string): string {
  return value
    .replace(
      /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*$/gi,
      "[REDACTED PRIVATE KEY MATERIAL]",
    )
    .replace(/\bAIza[0-9A-Za-z_-]{16,}\b/g, "[REDACTED GOOGLE API KEY]")
    .replace(
      /(\bAuthorization\s*:\s*Bearer\s+)[A-Za-z0-9._~+/-]{8,}/gi,
      "$1[REDACTED]",
    )
    .replace(
      /((?:client_secret|private_key|api_key|access_token|refresh_token)\s*["']?\s*[:=]\s*["']?)[A-Za-z0-9._~+\\/-]{6,}/gi,
      "$1[REDACTED]",
    )
    .replace(
      /([?&](?:key|access_token|refresh_token)=)[A-Za-z0-9._~+/-]{6,}/gi,
      "$1[REDACTED]",
    );
}

function evidenceFor(line: string, sensitive = false): string {
  if (sensitive) {
    return "[Sensitive credential value redacted]";
  }
  const redacted = sanitizeOutputText(
    redactSecrets(line.trim().replace(/\s+/g, " ")),
  );
  if (redacted.length <= 240) {
    return redacted;
  }
  return `${redacted.slice(0, 237)}...`;
}

function firstColumn(line: string, regex: RegExp): number {
  regex.lastIndex = 0;
  const match = regex.exec(line);
  return (match?.index ?? 0) + 1;
}

function addCandidate(
  candidates: CandidateFinding[],
  seen: Set<string>,
  candidate: CandidateFinding,
): void {
  const key = [
    candidate.ruleId,
    candidate.file,
    candidate.line,
    candidate.column,
    candidate.identity ?? candidate.title,
  ].join("\u0000");
  if (!seen.has(key)) {
    seen.add(key);
    candidates.push(candidate);
  }
}

function regexAcrossFile(regex: RegExp): RegExp {
  const flags = new Set(regex.flags.replace(/[gy]/g, "").split(""));
  flags.add("g");
  flags.add("m");
  return new RegExp(regex.source, [...flags].join(""));
}

function sourceLocation(content: string, offset: number): {
  line: number;
  column: number;
} {
  let line = 1;
  let lineStart = 0;
  const boundedOffset = Math.max(0, Math.min(offset, content.length));
  for (let index = 0; index < boundedOffset; index += 1) {
    if (content.charCodeAt(index) === 10) {
      line += 1;
      lineStart = index + 1;
    }
  }
  return { line, column: boundedOffset - lineStart + 1 };
}

function evidenceForMatch(
  content: string,
  start: number,
  matchLength: number,
): string {
  const lineStart = content.lastIndexOf("\n", Math.max(0, start - 1)) + 1;
  const matchEnd = Math.min(content.length, start + Math.max(1, matchLength));
  const nextBreak = content.indexOf("\n", matchEnd);
  const lineEnd = nextBreak === -1 ? content.length : nextBreak;
  return evidenceFor(content.slice(lineStart, lineEnd));
}

function scanStaticRules(
  context: FileContext,
  candidates: CandidateFinding[],
  seen: Set<string>,
): void {
  for (const rule of STATIC_RULES) {
    if (rule.languages && !rule.languages.includes(context.language)) {
      continue;
    }
    if (rule.requiresLegacyContext && !context.legacyContext) {
      continue;
    }

    const pattern = regexAcrossFile(rule.regex);
    for (const match of context.content.matchAll(pattern)) {
      const offset = match.index ?? 0;
      const location = sourceLocation(context.content, offset);
      addCandidate(candidates, seen, {
        ruleId: rule.ruleId,
        category: rule.category,
        severity: rule.severity,
        title: rule.title,
        description: rule.description,
        file: context.path,
        line: location.line,
        column: location.column,
        evidence: evidenceForMatch(context.content, offset, match[0].length),
        recommendation: rule.recommendation,
        language: context.language,
        tags: [...rule.tags],
      });
    }
  }
}

function scanMerchantBeta(
  context: FileContext,
  candidates: CandidateFinding[],
  seen: Set<string>,
): void {
  if (!context.merchantContext) return;

  const betaPattern = /(?<![A-Za-z0-9])v1beta\b/i;
  for (let index = 0; index < context.lines.length; index += 1) {
    const line = context.lines[index];
    if (!betaPattern.test(line)) continue;
    addCandidate(candidates, seen, {
      ruleId: "merchant-api-v1beta",
      category: "dependency",
      severity: "critical",
      title: "Discontinued Merchant API v1beta use",
      description:
        "This integration targets the discontinued Merchant API v1beta surface and can no longer be treated as a supported cutover target.",
      file: context.path,
      line: index + 1,
      column: firstColumn(line, betaPattern),
      evidence: evidenceFor(line),
      recommendation:
        "Move to a currently supported stable Merchant API version immediately, then rerun request/response, pagination, error, and authentication contract fixtures.",
      language: context.language,
      tags: ["merchant-api", "v1beta", "dependency", "discontinued"],
    });
  }
}

function scanResourceMethods(
  context: FileContext,
  candidates: CandidateFinding[],
  seen: Set<string>,
): void {
  if (!context.legacyContext) return;

  for (let index = 0; index < context.lines.length; index += 1) {
    const line = context.lines[index];
    const methodPattern = new RegExp(LEGACY_RESOURCE_METHOD.source, "gi");
    for (const match of line.matchAll(methodPattern)) {
      const resource = match[1].toLowerCase();
      const method = match[2].toLowerCase();
      if (method === "custombatch") {
        continue;
      }
      addCandidate(candidates, seen, {
        ruleId: "legacy-resource-method",
        category: "legacy-method",
        severity: "high",
        title: `Legacy ${resource}.${method} call`,
        description:
          "This Content API resource/method signature needs an explicit Merchant API mapping; names and request shapes are not drop-in compatible.",
        file: context.path,
        line: index + 1,
        column: (match.index ?? 0) + 1,
        evidence: evidenceFor(line),
        recommendation:
          "Map this call to the corresponding Merchant API service, then cover request fields, response fields, pagination, and errors with fixtures.",
        language: context.language,
        tags: ["content-api", "resource-method", resource, method],
        identity: `${resource}.${method}`,
      });
    }
  }
}

function scanBatching(
  context: FileContext,
  candidates: CandidateFinding[],
  seen: Set<string>,
): void {
  const batchPattern =
    /\bcustom\s*batch\b|\bcustomBatch\b|\bcustombatch\b|\/custombatch\b|:custombatch\b|\/(?:accounts|products|productstatuses)\/batch\b/i;
  if (!context.legacyContext && !batchPattern.test(context.content)) return;

  for (let index = 0; index < context.lines.length; index += 1) {
    const line = context.lines[index];
    if (!batchPattern.test(line)) continue;
    addCandidate(candidates, seen, {
      ruleId: "legacy-custom-batch",
      category: "batching",
      severity: "high",
      title: "Content API customBatch usage",
      description:
        "Content API customBatch behavior has no drop-in Merchant API equivalent; partial failures, ordering, retry, and throughput assumptions need redesign.",
      file: context.path,
      line: index + 1,
      column: firstColumn(line, batchPattern),
      evidence: evidenceFor(line),
      recommendation:
        "Replace customBatch with bounded concurrent Merchant API calls, idempotent retries, per-entry result capture, and representative load tests.",
      language: context.language,
      tags: ["content-api", "batching", "custombatch"],
    });
  }
}

function scanPrices(
  context: FileContext,
  candidates: CandidateFinding[],
  seen: Set<string>,
): void {
  if (!context.legacyContext) return;

  const valuePattern =
    /(?:["']?value["']?\s*:|\bsetValue\s*\(|\bprice(?:\??\.)?value\b|\bprice\s*\[\s*["']value["']\s*\])/i;
  const currencyPattern =
    /(?:["']?currency["']?\s*:|\bsetCurrency\s*\(|\bprice(?:\??\.)?currency\b|\bprice\s*\[\s*["']currency["']\s*\])/i;
  const pricePattern =
    /\b(?:price|salePrice|costOfGoodsSold|unitPricingBaseMeasure)\b/i;
  const conversionPattern =
    /\b(?:parseFloat|parseInt|Number|Decimal|BigDecimal|float|double)\s*\([^)]*(?:price(?:\??\.)?value|price\s*\[\s*["']value["']\s*\]|getValue\s*\(\s*\))/i;
  const arithmeticPattern =
    /(?:price(?:\??\.)?value|price\s*\[\s*["']value["']\s*\])\s*(?:\*|\/|\+|-)\s*(?:10{2,}|1e[2-9])/i;

  for (let index = 0; index < context.lines.length; index += 1) {
    const line = context.lines[index];
    const conversionMatch =
      conversionPattern.test(line) || arithmeticPattern.test(line);
    if (conversionMatch) {
      const matchedPattern = conversionPattern.test(line)
        ? conversionPattern
        : arithmeticPattern;
      addCandidate(candidates, seen, {
        ruleId: "legacy-price-conversion",
        category: "price",
        severity: "high",
        title: "Legacy decimal price conversion",
        description:
          "This converts a Content API decimal value and may introduce rounding or unit errors when Merchant API amountMicros is required.",
        file: context.path,
        line: index + 1,
        column: firstColumn(line, matchedPattern),
        evidence: evidenceFor(line),
        recommendation:
          "Use exact decimal-to-micros conversion, emit an integer amountMicros, map currency to currencyCode, and test edge values.",
        language: context.language,
        tags: ["price", "amount-micros", "rounding"],
      });
    }

    if (!valuePattern.test(line)) continue;
    const start = Math.max(0, index - 4);
    const end = Math.min(context.lines.length, index + 5);
    const window = context.lines.slice(start, end).join("\n");
    if (
      !currencyPattern.test(window) ||
      !pricePattern.test(window)
    ) {
      continue;
    }
    addCandidate(candidates, seen, {
      ruleId: "legacy-price-shape",
      category: "price",
      severity: "medium",
      title: "Legacy price value/currency shape",
      description:
        "This price appears to use Content API value/currency fields rather than Merchant API amountMicros/currencyCode.",
      file: context.path,
      line: index + 1,
      column: firstColumn(line, valuePattern),
      evidence: evidenceFor(line),
      recommendation:
        "Map value to exact integer amountMicros and currency to currencyCode; add fixtures for decimals, negatives, and large values.",
      language: context.language,
      tags: ["price", "value-currency", "amount-micros"],
    });
  }
}

function scanProductIds(
  context: FileContext,
  candidates: CandidateFinding[],
  seen: Set<string>,
): void {
  const directPatterns = [
    /\b(?:product(?:_?id|Id|\.id)|product_id)\s*(?:\?\.)?\.\s*split\s*\(\s*["']:["']\s*\)/i,
    /\bexplode\s*\(\s*["']:["']\s*,\s*\$?product(?:_?id|Id)?\b/i,
    /\b(?:product(?:_?id|Id|\.id)|product_id)\s*(?:\?\.)?\.\s*replace\s*\(\s*\/\^?(?:online|local):/i,
    /["'`](?:online|local):[a-z]{2}:[A-Z]{2}:/i,
  ] as const;

  for (let index = 0; index < context.lines.length; index += 1) {
    const line = context.lines[index];
    let matched: RegExp | null = null;
    for (const pattern of directPatterns) {
      if (pattern.test(line)) {
        matched = pattern;
        break;
      }
    }

    const colonCount = (line.match(/:/g) ?? []).length;
    const identityParts =
      (
        line.match(
          /\b(?:channel|contentLanguage|language(?:Code)?|targetCountry|country|feedLabel|offerId|offer_id)\b/gi,
        ) ?? []
      ).length >= 2;
    const constructsDelimitedId =
      context.legacyContext && colonCount >= 2 && identityParts;

    if (!matched && !constructsDelimitedId) continue;
    addCandidate(candidates, seen, {
      ruleId: "legacy-product-id-delimiter",
      category: "product-id",
      severity: "medium",
      title: "Colon-delimited product ID assumption",
      description:
        "This code appears to parse or construct the Content API channel:language:country:offerId identity format.",
      file: context.path,
      line: index + 1,
      column: matched ? firstColumn(line, matched) : 1,
      evidence: evidenceFor(line),
      recommendation:
        "Treat Merchant API product names as opaque, centralize identity mapping, and test offer IDs containing delimiters or reserved characters.",
      language: context.language,
      tags: ["product-id", "delimiter", "resource-name"],
    });
  }
}

function scanCredentials(
  context: FileContext,
  candidates: CandidateFinding[],
  seen: Set<string>,
): void {
  const privateKeyPattern =
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|["']private_key["']\s*:/i;
  const googleApiKeyPattern = /\bAIza[0-9A-Za-z_-]{16,}\b/;
  const assignedCredentialPattern =
    /\b(?:client_secret|private_key|api_key|access_token|refresh_token)\b\s*["']?\s*[:=]\s*["'][^"']{8,}["']/i;
  const bearerPattern =
    /\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/-]{8,}/i;

  for (let index = 0; index < context.lines.length; index += 1) {
    const line = context.lines[index];
    let pattern: RegExp | null = null;
    let severity: FindingSeverity = "high";
    let title = "Potential hard-coded Google credential";

    if (privateKeyPattern.test(line)) {
      pattern = privateKeyPattern;
      severity = "critical";
      title = "Potential private key material";
    } else if (googleApiKeyPattern.test(line)) {
      pattern = googleApiKeyPattern;
    } else if (assignedCredentialPattern.test(line)) {
      pattern = assignedCredentialPattern;
    } else if (bearerPattern.test(line)) {
      pattern = bearerPattern;
      title = "Potential hard-coded bearer token";
    }

    if (!pattern) continue;
    addCandidate(candidates, seen, {
      ruleId:
        severity === "critical"
          ? "hardcoded-private-key"
          : "hardcoded-google-credential",
      category: "credential",
      severity,
      title,
      description:
        "Credential-like material appears in source. Its value is intentionally omitted from all scanner output.",
      file: context.path,
      line: index + 1,
      column: firstColumn(line, pattern),
      evidence: evidenceFor(line, true),
      recommendation:
        "Remove the value from source and history, rotate it, store the replacement in a secret manager, and verify least-privilege access.",
      language: context.language,
      tags: ["security", "credential", "redacted"],
    });
  }
}

function scanOneFile(
  path: string,
  content: string,
  candidates: CandidateFinding[],
  seen: Set<string>,
): void {
  const context: FileContext = {
    path,
    content,
    lines: content.split(/\r\n?|\n/),
    language: languageFor(path),
    legacyContext: hasLegacyContext(content),
    merchantContext: hasMerchantContext(content),
  };

  scanCredentials(context, candidates, seen);
  scanStaticRules(context, candidates, seen);
  scanMerchantBeta(context, candidates, seen);
  scanResourceMethods(context, candidates, seen);
  scanBatching(context, candidates, seen);
  scanPrices(context, candidates, seen);
  scanProductIds(context, candidates, seen);
}

function sortCandidates(candidates: CandidateFinding[]): CandidateFinding[] {
  return [...candidates].sort((left, right) => {
    const severity =
      SEVERITY_ORDER[right.severity] - SEVERITY_ORDER[left.severity];
    if (severity !== 0) return severity;
    const file = compareText(left.file, right.file);
    if (file !== 0) return file;
    if (left.line !== right.line) return left.line - right.line;
    if (left.column !== right.column) return left.column - right.column;
    const rule = compareText(left.ruleId, right.ruleId);
    if (rule !== 0) return rule;
    return compareText(left.identity ?? left.title, right.identity ?? right.title);
  });
}

function stableHash(value: string): string {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}

function finalizeFindings(
  candidates: CandidateFinding[],
  maxFindings: number,
): { findings: ScanFinding[]; omitted: number } {
  const sorted = sortCandidates(candidates);
  const selected = sorted.slice(0, maxFindings);
  const findings = selected.map((candidate) => {
    const { identity: _identity, ...finding } = candidate;
    const idSource = [
      finding.ruleId,
      finding.file,
      finding.line,
      finding.column,
      candidate.identity ?? finding.title,
    ].join("\u0000");
    return {
      ...finding,
      id: `finding-${stableHash(idSource)}`,
    };
  });
  return {
    findings,
    omitted: Math.max(0, sorted.length - selected.length),
  };
}

function calculateRisk(findings: readonly ScanFinding[]): {
  score: number;
  level: RiskLevel;
} {
  if (findings.length === 0) return { score: 0, level: "none" };
  const weighted = findings.reduce(
    (sum, finding) => sum + SEVERITY_WEIGHT[finding.severity],
    0,
  );
  const highest = findings.reduce<FindingSeverity>(
    (current, finding) =>
      SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[current]
        ? finding.severity
        : current,
    "low",
  );
  const score = Math.min(
    100,
    Math.max(weighted, SEVERITY_SCORE_FLOOR[highest]),
  );
  let level: RiskLevel;
  if (score >= 80) level = "critical";
  else if (score >= 50) level = "high";
  else if (score >= 25) level = "medium";
  else level = "low";
  return { score, level };
}

function buildSummary(
  findings: readonly ScanFinding[],
  skippedCount: number,
): ScanSummary {
  const bySeverity: SeverityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  const categoryCounts = new Map<string, number>();
  const files = new Set<string>();
  let highestSeverity: FindingSeverity | null = null;

  for (const finding of findings) {
    bySeverity[finding.severity] += 1;
    categoryCounts.set(
      finding.category,
      (categoryCounts.get(finding.category) ?? 0) + 1,
    );
    files.add(finding.file);
    if (
      highestSeverity === null ||
      SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[highestSeverity]
    ) {
      highestSeverity = finding.severity;
    }
  }

  const byCategory: Record<string, number> = {};
  for (const [category, count] of [...categoryCounts].sort(([left], [right]) =>
    compareText(left, right),
  )) {
    byCategory[category] = count;
  }

  let message: string;
  if (findings.length === 0) {
    message =
      skippedCount === 0
        ? "No known legacy Google Shopping migration patterns were found in the scanned files."
        : "No known legacy patterns were found in scanned files, but skipped files still require review.";
  } else {
    message = `${findings.length} migration finding${
      findings.length === 1 ? "" : "s"
    } across ${files.size} file${files.size === 1 ? "" : "s"}.`;
  }

  return {
    totalFindings: findings.length,
    filesWithFindings: files.size,
    highestSeverity,
    bySeverity,
    byCategory,
    message,
  };
}

function buildActions(
  findings: readonly ScanFinding[],
  skipped: readonly SkippedFile[],
): RecommendedAction[] {
  const actions: RecommendedAction[] = [];
  const byCategory = (categories: readonly FindingCategory[]) =>
    findings.filter((finding) => categories.includes(finding.category));
  const push = (
    id: string,
    priority: RecommendedAction["priority"],
    title: string,
    description: string,
    related: readonly ScanFinding[],
  ) => {
    if (related.length === 0) return;
    actions.push({
      id,
      priority,
      title,
      description,
      relatedFindingIds: related.map((finding) => finding.id),
    });
  };

  push(
    "rotate-credentials",
    "urgent",
    "Remove and rotate exposed credentials",
    "Purge credential material from source and history, rotate it, and move the replacement to managed secrets before migration work continues.",
    byCategory(["credential"]),
  );
  push(
    "replace-content-surface",
    "high",
    "Replace Content API clients and endpoints",
    "Inventory each legacy service construction and REST path, then select the corresponding Merchant API service and supported release.",
    byCategory(["legacy-client", "legacy-endpoint", "dependency"]),
  );
  push(
    "map-resource-methods",
    "high",
    "Build a resource-by-resource migration map",
    "For every legacy method, record the target service, new resource name, request/response mapping, pagination, errors, and parity fixture.",
    byCategory(["legacy-method"]),
  );
  push(
    "redesign-batching",
    "high",
    "Redesign and load-test batching",
    "Replace customBatch assumptions with bounded concurrency, idempotent retry policy, per-entry error capture, and throughput evidence.",
    byCategory(["batching"]),
  );
  push(
    "prove-price-parity",
    "high",
    "Prove exact price conversion",
    "Convert decimal values to integer micros without binary floating point and verify currencyCode plus boundary fixtures.",
    byCategory(["price"]),
  );
  push(
    "centralize-product-identity",
    "medium",
    "Stop parsing product names by delimiter",
    "Centralize product identity mapping, treat returned resource names as opaque, and cover delimiter-containing offer IDs.",
    byCategory(["product-id"]),
  );

  if (skipped.length > 0) {
    actions.push({
      id: "review-skipped-files",
      priority: skipped.some(
        (file) =>
          file.reason === "max-file-size" ||
          file.reason === "max-total-size" ||
          file.reason === "file-limit",
      )
        ? "medium"
        : "low",
      title: "Review scanner exclusions",
      description:
        "Confirm skipped files are generated, vendored, binary, or otherwise outside the integration; rescan focused source files when coverage is uncertain.",
      relatedFindingIds: [],
    });
  }

  if (findings.length === 0) {
    actions.unshift({
      id: "confirm-scan-coverage",
      priority: "low",
      title: "Confirm migration scan coverage",
      description:
        "Verify that entry points, dependency manifests, API wrappers, jobs, and Apps Script projects were included before treating this as a clean result.",
      relatedFindingIds: [],
    });
  }
  return actions;
}

/**
 * Scans in-memory files for known Content API for Shopping migration risks.
 * Inputs are sorted by normalized path so results do not depend on selection order.
 */
export function scanFiles(
  files: readonly ScanInputFile[],
  options: ScannerOptions = {},
): ScanResult {
  const resolved = resolveOptions(options);
  const normalizedFiles = files
    .map((file, index) => ({
      originalIndex: index,
      path:
        file && typeof file.path === "string"
          ? normalizePath(file.path)
          : `(invalid-${index + 1})`,
      content:
        file && typeof file.content === "string" ? file.content : null,
    }))
    .sort(
      (left, right) =>
        compareText(left.path, right.path) ||
        left.originalIndex - right.originalIndex,
    );

  const candidates: CandidateFinding[] = [];
  const seen = new Set<string>();
  const skipped: SkippedFile[] = [];
  let scannedFiles = 0;
  let bytesScanned = 0;

  for (const file of normalizedFiles) {
    if (file.content === null) {
      skipped.push({
        path: file.path,
        reason: "invalid-input",
        detail: "File content must be a string.",
      });
      continue;
    }

    if (optionExcludes(file.path, resolved.excludePaths)) {
      skipped.push({
        path: file.path,
        reason: "excluded-by-option",
        detail: "Path matched a caller-provided exclusion.",
      });
      continue;
    }

    if (resolved.includeDefaultExclusions) {
      const excluded = defaultExclusion(file.path);
      if (excluded !== null) {
        skipped.push({
          path: file.path,
          reason: "default-exclusion",
          detail: `Skipped ${excluded}.`,
        });
        continue;
      }
    }

    if (scannedFiles >= resolved.maxFiles) {
      skipped.push({
        path: file.path,
        reason: "file-limit",
        detail: `Scan limit is ${resolved.maxFiles} files.`,
      });
      continue;
    }

    const bytes = utf8ByteLength(file.content);
    if (bytes > resolved.maxFileBytes) {
      skipped.push({
        path: file.path,
        reason: "max-file-size",
        detail: `File exceeds the ${resolved.maxFileBytes} byte per-file limit.`,
        bytes,
      });
      continue;
    }
    if (bytesScanned + bytes > resolved.maxTotalBytes) {
      skipped.push({
        path: file.path,
        reason: "max-total-size",
        detail: `File would exceed the ${resolved.maxTotalBytes} byte total limit.`,
        bytes,
      });
      continue;
    }
    if (isProbablyBinary(file.content)) {
      skipped.push({
        path: file.path,
        reason: "binary",
        detail: "Content appears to be binary.",
        bytes,
      });
      continue;
    }

    scannedFiles += 1;
    bytesScanned += bytes;
    scanOneFile(file.path, file.content, candidates, seen);
  }

  const { findings, omitted } = finalizeFindings(
    candidates,
    resolved.maxFindings,
  );
  const risk = calculateRisk(findings);
  const warnings: string[] = [];
  if (findings.some((finding) => finding.category === "credential")) {
    warnings.push(
      "Potential credential material was detected. Values were redacted from findings and exports; remove and rotate them.",
    );
  }
  if (
    skipped.some(
      (file) =>
        file.reason === "max-file-size" ||
        file.reason === "max-total-size" ||
        file.reason === "file-limit",
    )
  ) {
    warnings.push(
      "One or more source files were not scanned because a safety limit was reached.",
    );
  }
  if (omitted > 0) {
    warnings.push(
      `${omitted} additional finding${omitted === 1 ? " was" : "s were"} omitted by the finding limit.`,
    );
  }

  return {
    scannerVersion: SCANNER_VERSION,
    riskScore: risk.score,
    riskLevel: risk.level,
    summary: buildSummary(findings, skipped.length),
    findings,
    recommendedActions: buildActions(findings, skipped),
    skipped,
    warnings,
    stats: {
      inputFiles: files.length,
      scannedFiles,
      filesScanned: scannedFiles,
      skippedFiles: skipped.length,
      bytesScanned,
      highRiskFindings: findings.filter(
        (finding) =>
          finding.severity === "critical" || finding.severity === "high",
      ).length,
      categoriesDetected: new Set(
        findings.map((finding) => finding.category),
      ).size,
      findingsTruncated: omitted > 0,
      omittedFindings: omitted,
    },
  };
}

/** Descriptive alias for callers that prefer an explicit source-oriented name. */
export const scanSourceFiles = scanFiles;

function markdownCell(value: unknown): string {
  return sanitizeOutputText(String(value))
    .replace(/\\/g, "\\\\")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\|/g, "\\|")
    .replace(/([`*_[\]])/g, "\\$1");
}

/** Creates a deterministic, secret-redacted Markdown report. */
export function exportScanAsMarkdown(result: ScanResult): string {
  const lines = [
    "# CutoverProof migration scan",
    "",
    `- Risk: **${result.riskScore}/100 (${result.riskLevel})**`,
    `- Findings: **${result.summary.totalFindings}** across **${result.summary.filesWithFindings}** files`,
    `- Coverage: **${result.stats.scannedFiles}/${result.stats.inputFiles}** files scanned`,
    `- Scanner: \`${result.scannerVersion}\``,
    "",
    markdownCell(result.summary.message),
    "",
    "## Findings",
    "",
  ];

  if (result.findings.length === 0) {
    lines.push("_No known legacy patterns found._", "");
  } else {
    lines.push(
      "| Severity | Category | File | Line | Finding | Evidence |",
      "| --- | --- | --- | ---: | --- | --- |",
    );
    for (const finding of result.findings) {
      lines.push(
        `| ${markdownCell(finding.severity)} | ${markdownCell(
          finding.category,
        )} | ${markdownCell(finding.file)} | ${finding.line} | ${markdownCell(
          finding.title,
        )} | ${markdownCell(finding.evidence)} |`,
      );
    }
    lines.push("");
  }

  lines.push("## Recommended actions", "");
  for (const action of result.recommendedActions) {
    lines.push(
      `- **${markdownCell(action.title)}** (${markdownCell(
        action.priority,
      )}): ${markdownCell(action.description)}`,
    );
  }
  if (result.recommendedActions.length === 0) {
    lines.push("_No actions generated._");
  }

  if (result.skipped.length > 0) {
    lines.push("", "## Skipped files", "");
    for (const file of result.skipped) {
      lines.push(
        `- ${markdownCell(file.path)} -- ${markdownCell(file.detail)}`,
      );
    }
  }

  if (result.warnings.length > 0) {
    lines.push("", "## Warnings", "");
    for (const warning of result.warnings) {
      lines.push(`- ${markdownCell(warning)}`);
    }
  }

  return `${lines.join("\n").trimEnd()}\n`;
}

function stableJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(stableJsonValue);
  }
  if (value && typeof value === "object") {
    const source = value as Record<string, unknown>;
    const target: Record<string, unknown> = {};
    for (const key of Object.keys(source).sort(compareText)) {
      const child = source[key];
      if (child !== undefined) {
        target[key] = stableJsonValue(child);
      }
    }
    return target;
  }
  return value;
}

/** Creates canonical-key-order JSON. No timestamp is added. */
export function exportScanAsJSON(
  result: ScanResult,
  indentation = 2,
): string {
  const spaces = Number.isFinite(indentation)
    ? Math.max(0, Math.min(10, Math.floor(indentation)))
    : 2;
  return `${JSON.stringify(stableJsonValue(result), null, spaces)}\n`;
}

function csvCell(value: unknown): string {
  const text = String(value ?? "");
  const formulaRisk = /^[\s\u200b\ufeff]*[=+\-@]/u.test(text);
  const safe = sanitizeOutputText(text);
  const guarded = formulaRisk ? `'${safe}` : safe;
  return `"${guarded.replace(/"/g, '""')}"`;
}

/** Creates one deterministic CSV row per finding. */
export function exportScanAsCSV(result: ScanResult): string {
  const rows: string[][] = [
    [
      "id",
      "severity",
      "category",
      "file",
      "line",
      "column",
      "title",
      "evidence",
      "recommendation",
    ],
    ...result.findings.map((finding) => [
      finding.id,
      finding.severity,
      finding.category,
      finding.file,
      String(finding.line),
      String(finding.column),
      finding.title,
      finding.evidence,
      finding.recommendation,
    ]),
  ];
  return `${rows.map((row) => row.map(csvCell).join(",")).join("\n")}\n`;
}

export const scanResultToMarkdown = exportScanAsMarkdown;
export const scanResultToJSON = exportScanAsJSON;
export const scanResultToCSV = exportScanAsCSV;
export const exportScanAsJson = exportScanAsJSON;
export const exportScanAsCsv = exportScanAsCSV;
