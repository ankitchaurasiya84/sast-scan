/**
 * sast-scan - Core Scanner Engine
 * Version: 2.0.0
 */

import rules, { SEVERITY } from "./rules.js";

// ─── Constants ────────────────────────────────────────────────────────────────

const SEVERITY_WEIGHT = {
  [SEVERITY.CRITICAL]: 5,
  [SEVERITY.HIGH]: 4,
  [SEVERITY.MEDIUM]: 3,
  [SEVERITY.LOW]: 2,
  [SEVERITY.INFO]: 1,
};

// ─── Utility Helpers ──────────────────────────────────────────────────────────

/**
 * Strips single-line and multi-line comments from JavaScript code.
 * Preserves line count so line numbers remain accurate.
 */
function stripComments(code) {
  let result = "";
  let i = 0;
  let inString = false;
  let stringChar = "";
  let inMultiLine = false;
  let inSingleLine = false;

  while (i < code.length) {
    const ch = code[i];
    const next = code[i + 1];

    if (inSingleLine) {
      if (ch === "\n") {
        inSingleLine = false;
        result += ch;
      } else {
        result += " ";
      }
      i++;
      continue;
    }

    if (inMultiLine) {
      if (ch === "*" && next === "/") {
        inMultiLine = false;
        result += "  ";
        i += 2;
      } else {
        result += ch === "\n" ? "\n" : " ";
        i++;
      }
      continue;
    }

    if (inString) {
      result += ch;
      if (ch === "\\" && next === stringChar) {
        result += next;
        i += 2;
        continue;
      }
      if (ch === stringChar) inString = false;
      i++;
      continue;
    }

    if ((ch === '"' || ch === "'" || ch === "`") && !inString) {
      inString = true;
      stringChar = ch;
      result += ch;
      i++;
      continue;
    }

    if (ch === "/" && next === "/") {
      inSingleLine = true;
      result += "  ";
      i += 2;
      continue;
    }

    if (ch === "/" && next === "*") {
      inMultiLine = true;
      result += "  ";
      i += 2;
      continue;
    }

    result += ch;
    i++;
  }

  return result;
}

/**
 * Extracts a short contextual snippet (surrounding lines) for a finding.
 */
function getContext(lines, lineIndex, contextSize = 2) {
  const start = Math.max(0, lineIndex - contextSize);
  const end = Math.min(lines.length - 1, lineIndex + contextSize);
  return lines.slice(start, end + 1).map((text, offset) => ({
    line: start + offset + 1,
    text,
    isVulnerable: start + offset === lineIndex,
  }));
}

// ─── Finding Class ────────────────────────────────────────────────────────────

class Finding {
  constructor({ rule, lineNumber, lineText, file, context }) {
    this.id = rule.id;
    this.category = rule.category;
    this.severity = rule.severity;
    this.message = rule.message;
    this.fix = rule.fix;
    this.cwe = rule.cwe || null;
    this.lineNumber = lineNumber;
    this.lineText = lineText.trim();
    this.file = file || null;
    this.context = context || [];
  }

  toJSON() {
    return {
      id: this.id,
      severity: this.severity,
      category: this.category,
      message: this.message,
      fix: this.fix,
      cwe: this.cwe,
      lineNumber: this.lineNumber,
      lineText: this.lineText,
      file: this.file,
      context: this.context,
    };
  }
}

// ─── ScanResult Class ─────────────────────────────────────────────────────────

class ScanResult {
  constructor(findings, meta) {
    this.findings = findings;
    this.meta = meta;
    this.summary = this._buildSummary();
  }

  _buildSummary() {
    const counts = {
      [SEVERITY.CRITICAL]: 0,
      [SEVERITY.HIGH]: 0,
      [SEVERITY.MEDIUM]: 0,
      [SEVERITY.LOW]: 0,
      [SEVERITY.INFO]: 0,
      total: this.findings.length,
    };
    for (const f of this.findings) counts[f.severity]++;
    return counts;
  }

  /**
   * Returns findings sorted by severity (critical first).
   */
  get sorted() {
    return [...this.findings].sort(
      (a, b) => SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity]
    );
  }

  /**
   * Filter findings by minimum severity level.
   * @param {string} minSeverity - Minimum severity to include.
   */
  filterBySeverity(minSeverity) {
    const min = SEVERITY_WEIGHT[minSeverity] ?? 0;
    return this.findings.filter((f) => SEVERITY_WEIGHT[f.severity] >= min);
  }

  /**
   * Filter findings by category.
   * @param {string} category
   */
  filterByCategory(category) {
    return this.findings.filter((f) => f.category === category);
  }

  /**
   * Returns a plain object suitable for JSON serialization.
   */
  toJSON() {
    return {
      meta: this.meta,
      summary: this.summary,
      findings: this.findings.map((f) => f.toJSON()),
    };
  }

  /**
   * Returns a formatted text report.
   */
  toText() {
    const lines = [
      "═══════════════════════════════════════",
      "        SAST-SCAN SECURITY REPORT      ",
      "═══════════════════════════════════════",
      `File    : ${this.meta.file || "inline code"}`,
      `Scanned : ${this.meta.scannedAt}`,
      `Lines   : ${this.meta.linesScanned}`,
      `Rules   : ${this.meta.rulesApplied}`,
      "───────────────────────────────────────",
      "SUMMARY",
      `  Critical : ${this.summary[SEVERITY.CRITICAL]}`,
      `  High     : ${this.summary[SEVERITY.HIGH]}`,
      `  Medium   : ${this.summary[SEVERITY.MEDIUM]}`,
      `  Low      : ${this.summary[SEVERITY.LOW]}`,
      `  Info     : ${this.summary[SEVERITY.INFO]}`,
      `  Total    : ${this.summary.total}`,
      "───────────────────────────────────────",
    ];

    if (this.findings.length === 0) {
      lines.push("✓ No vulnerabilities found.");
    } else {
      for (const f of this.sorted) {
        lines.push(`\n[${f.severity.toUpperCase()}] ${f.id} — ${f.category}`);
        lines.push(`  Message : ${f.message}`);
        if (f.cwe) lines.push(`  CWE     : ${f.cwe}`);
        lines.push(`  Line ${f.lineNumber}  : ${f.lineText}`);
        lines.push(`  Fix     : ${f.fix}`);
      }
    }

    lines.push("\n═══════════════════════════════════════");
    return lines.join("\n");
  }
}

// ─── Scanner Options ──────────────────────────────────────────────────────────

/**
 * @typedef {Object} ScanOptions
 * @property {string}   [file]            - Filename for reporting purposes.
 * @property {boolean}  [stripComments]   - Strip comments before scanning. Default: true.
 * @property {string[]} [ignoreRules]     - Array of rule IDs to skip.
 * @property {string}   [minSeverity]     - Minimum severity to report. Default: 'info'.
 * @property {boolean}  [includeContext]  - Include surrounding lines in findings. Default: true.
 * @property {number}   [contextLines]    - Number of context lines around each finding. Default: 2.
 * @property {Function} [onFinding]       - Callback called for each finding as it is discovered.
 */

// ─── Core Scan Function ───────────────────────────────────────────────────────

/**
 * Scans a string of source code for security vulnerabilities.
 *
 * @param {string}      code    - Source code to scan.
 * @param {ScanOptions} options - Optional configuration.
 * @returns {ScanResult}
 */
export function scanCode(code, options = {}) {
  if (typeof code !== "string") {
    throw new TypeError("scanCode: 'code' must be a string.");
  }

  const {
    file = null,
    stripComments: shouldStrip = true,
    ignoreRules = [],
    minSeverity = SEVERITY.INFO,
    includeContext = true,
    contextLines = 2,
    onFinding = null,
  } = options;

  const minWeight = SEVERITY_WEIGHT[minSeverity] ?? 1;
  const ignoreSet = new Set(ignoreRules);

  // Pre-process
  const processedCode = shouldStrip ? stripComments(code) : code;
  const lines = processedCode.split("\n");
  const rawLines = code.split("\n"); // for context display (unstripped)

  const applicableRules = rules.filter(
    (r) => !ignoreSet.has(r.id) && SEVERITY_WEIGHT[r.severity] >= minWeight
  );

  // Deduplicate by ruleId+lineNumber to avoid repeat matches on same line
  const seen = new Set();
  const findings = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const rule of applicableRules) {
      const key = `${rule.id}:${i}`;
      if (seen.has(key)) continue;
      if (rule.pattern.test(line)) {
        seen.add(key);
        const finding = new Finding({
          rule,
          lineNumber: i + 1,
          lineText: rawLines[i] || line,
          file,
          context: includeContext ? getContext(rawLines, i, contextLines) : [],
        });
        findings.push(finding);
        if (typeof onFinding === "function") onFinding(finding);
      }
    }
  }

  const result = new ScanResult(findings, {
    file,
    scannedAt: new Date().toISOString(),
    linesScanned: lines.length,
    rulesApplied: applicableRules.length,
  });

  return result;
}

/**
 * Convenience: scan and return plain array (backwards-compatible with v1 API).
 *
 * @param {string}      code
 * @param {ScanOptions} options
 * @returns {Object[]}
 */
export function scanCodeLegacy(code, options = {}) {
  const result = scanCode(code, options);
  if (result.findings.length === 0) {
    return [{ message: "No vulnerabilities found." }];
  }
  return result.findings.map((f) => ({
    message: `Vulnerability: ${f.message}`,
    fix: `Recommendation: ${f.fix}`,
    lineNumber: `Vulnerable Code Line (${f.lineNumber}): ${f.lineText}`,
    severity: f.severity,
    id: f.id,
    cwe: f.cwe,
    category: f.category,
  }));
}

export { SEVERITY, SEVERITY_WEIGHT, ScanResult, Finding, rules };
export default scanCode;