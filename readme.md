# 📜 sast-scan 🔍

[![npm version](https://img.shields.io/npm/v/sast-scan.svg)](https://www.npmjs.com/package/sast-scan)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Node.js ≥16](https://img.shields.io/badge/node-%3E%3D16-blue.svg)](https://nodejs.org)

**sast-scan** is a lightweight, extensible Static Application Security Testing (SAST) tool for JavaScript.
Paste or pipe your source code and get back structured findings with severity ratings, CWE references, fix recommendations, and line context — zero dependencies.

---

## What's New in v2.0

| Feature | v1 | v2 |
|---|---|---|
| Deduplicated rules | ✗ (180+ duplicates) | ✓ 35 unique, curated rules |
| CWE references | ✗ | ✓ on every rule |
| Severity levels | ✗ | ✓ critical / high / medium / low / info |
| Structured `ScanResult` object | ✗ | ✓ with `.sorted`, `.filterBySeverity()`, `.toText()`, `.toJSON()` |
| Comment stripping | ✗ | ✓ (prevents comment-based false positives) |
| `ignoreRules` / `minSeverity` options | ✗ | ✓ |
| Streaming `onFinding` callback | ✗ | ✓ |
| Per-finding line context | ✗ | ✓ |
| Backwards-compatible legacy API | — | ✓ `scanCodeLegacy()` |
| Test suite | ✗ | ✓ 22 tests, 0 deps |

---

## Installation

```sh
npm install sast-scan
```

---

## Quick Start

```js
import scanCode from 'sast-scan';

const result = scanCode(`
  const password = "hunter2";
  eval(userInput);
  element.innerHTML = req.body.content;
`);

console.log(result.summary);
// { critical: 2, high: 1, medium: 0, low: 0, info: 0, total: 3 }

console.log(result.toText());
// Prints a formatted security report to stdout
```

---

## API

### `scanCode(code, options?)` → `ScanResult`

The primary API. Scans a string of JavaScript source code.

```js
import { scanCode, SEVERITY } from 'sast-scan';

const result = scanCode(sourceCode, {
  file: 'src/app.js',           // filename for reporting (optional)
  minSeverity: SEVERITY.MEDIUM, // skip LOW and INFO findings
  ignoreRules: ['SAST-132'],    // skip specific rule IDs
  includeContext: true,          // include surrounding lines in findings
  contextLines: 2,               // how many lines of context to include
  onFinding: (finding) => {      // streaming callback per finding
    console.log(`Found: ${finding.id} at line ${finding.lineNumber}`);
  },
});
```

#### `ScanResult` properties

| Property | Type | Description |
|---|---|---|
| `.findings` | `Finding[]` | All findings in scan order |
| `.sorted` | `Finding[]` | Findings sorted by severity (critical first) |
| `.summary` | `Object` | Count per severity + total |
| `.meta` | `Object` | File, timestamp, lines scanned, rules applied |
| `.filterBySeverity(minSeverity)` | `Finding[]` | Findings at or above threshold |
| `.filterByCategory(category)` | `Finding[]` | Findings for one category |
| `.toText()` | `string` | Formatted plain-text report |
| `.toJSON()` | `Object` | JSON-serializable report object |

#### `Finding` properties

| Property | Type | Description |
|---|---|---|
| `.id` | `string` | Rule ID, e.g. `"SAST-001"` |
| `.severity` | `string` | `"critical"` `"high"` `"medium"` `"low"` `"info"` |
| `.category` | `string` | Vulnerability category |
| `.message` | `string` | Human-readable description |
| `.fix` | `string` | Recommended remediation |
| `.cwe` | `string\|null` | CWE identifier, e.g. `"CWE-79"` |
| `.lineNumber` | `number` | 1-indexed line number |
| `.lineText` | `string` | The vulnerable line (trimmed) |
| `.file` | `string\|null` | Filename if provided |
| `.context` | `Object[]` | Surrounding lines `{ line, text, isVulnerable }` |

---

### `scanCodeLegacy(code, options?)` → `Object[]`

Drop-in replacement for the v1 `scanCode()` API. Returns a plain array of `{ message, fix, lineNumber, severity, id, cwe, category }` objects.

```js
import { scanCodeLegacy } from 'sast-scan';

const results = scanCodeLegacy(code);
// [{ message: "Vulnerability: ...", fix: "Recommendation: ...", lineNumber: "..." }]
```

---

### Severity constants

```js
import { SEVERITY } from 'sast-scan';

SEVERITY.CRITICAL  // "critical"
SEVERITY.HIGH      // "high"
SEVERITY.MEDIUM    // "medium"
SEVERITY.LOW       // "low"
SEVERITY.INFO      // "info"
```

---

### Category constants

```js
import { CATEGORY } from 'sast-scan';

CATEGORY.INJECTION
CATEGORY.XSS
CATEGORY.CRYPTO
CATEGORY.AUTH
CATEGORY.COMMAND_INJECTION
CATEGORY.PATH_TRAVERSAL
// ... and more
```

---

## React Integration

```jsx
import React, { useState } from 'react';
import { scanCode, SEVERITY } from 'sast-scan';

export default function CodeScanner() {
  const [code, setCode] = useState('');
  const [result, setResult] = useState(null);

  const handleScan = () => {
    const scanResult = scanCode(code, {
      minSeverity: SEVERITY.INFO,
      includeContext: true,
    });
    setResult(scanResult);
  };

  return (
    <div>
      <textarea value={code} onChange={e => setCode(e.target.value)} />
      <button onClick={handleScan}>Scan</button>

      {result && (
        <div>
          <p>Found {result.summary.total} issues
             ({result.summary[SEVERITY.CRITICAL]} critical,
              {result.summary[SEVERITY.HIGH]} high)</p>

          {result.sorted.map((finding, i) => (
            <div key={i}>
              <strong>[{finding.severity.toUpperCase()}] {finding.id}</strong>
              <p>{finding.message}</p>
              <p>Line {finding.lineNumber}: <code>{finding.lineText}</code></p>
              <p>Fix: {finding.fix}</p>
              {finding.cwe && <p>CWE: {finding.cwe}</p>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
```

---

## Rule Reference

| ID | Severity | Category | Detects |
|---|---|---|---|
| SAST-001 | 🔴 Critical | Injection | `eval()` usage |
| SAST-002 | 🔴 Critical | Injection | `new Function()` |
| SAST-003 | 🔴 Critical | Injection | SQL string concatenation |
| SAST-004 | 🔴 Critical | Command Injection | `child_process.exec/execSync` |
| SAST-010 | 🟠 High | XSS | Unsafe `innerHTML` assignment |
| SAST-011 | 🟠 High | XSS | `document.write()` |
| SAST-012 | 🟠 High | XSS | Cookie value in `innerHTML` |
| SAST-013 | 🟡 Medium | XSS | React `dangerouslySetInnerHTML` |
| SAST-020 | 🟠 High | Cryptography | MD5 hashing |
| SAST-021 | 🟠 High | Cryptography | SHA-1 hashing |
| SAST-022 | 🟡 Medium | Cryptography | `Math.random()` for security |
| SAST-030 | 🔴 Critical | Auth & Secrets | Hardcoded credentials |
| SAST-031 | 🟠 High | Auth & Secrets | Weak JWT secret |
| SAST-032 | 🟠 High | Auth & Secrets | JWT `none` algorithm |
| SAST-040 | 🟡 Medium | Memory Safety | `new Buffer()` deprecated |
| SAST-041 | 🔵 Low | Memory Safety | Memory leak in `setInterval` |
| SAST-050 | 🟠 High | Path Traversal | User input in `path.join()` |
| SAST-051 | 🟠 High | Path Traversal | User input in `fs` operations |
| SAST-060 | 🟡 Medium | Open Redirect | User-controlled `res.redirect()` |
| SAST-061 | 🟡 Medium | Open Redirect | Unvalidated `window.location` assignment |
| SAST-070 | 🟡 Medium | Info Disclosure | Raw error sent to client |
| SAST-071 | 🟠 High | Info Disclosure | Password in API response |
| SAST-072 | 🔵 Low | Info Disclosure | Sensitive data in `console.log` |
| SAST-080 | 🟡 Medium | Network Security | HTTP (non-HTTPS) URL |
| SAST-081 | 🔵 Low | Network Security | `fetch()` without timeout |
| SAST-082 | 🟡 Medium | Network Security | `XMLHttpRequest` without CSRF |
| SAST-090 | 🟡 Medium | Insecure Storage | Sensitive data in `localStorage` |
| SAST-091 | 🟡 Medium | Insecure Storage | Sensitive data in `sessionStorage` |
| SAST-092 | 🟡 Medium | Insecure Storage | Untrusted data from `localStorage` |
| SAST-100 | 🟠 High | Prototype Pollution | `Object.assign` with user input |
| SAST-101 | 🟠 High | Prototype Pollution | Direct `__proto__` manipulation |
| SAST-110 | 🟠 High | Deserialization | Insecure deserialization libraries |
| SAST-120 | ℹ️ Info | Insecure Deps | `dotenv` without validation |
| SAST-130 | 🔵 Low | Code Quality | `alert()` usage |
| SAST-131 | 🔵 Low | Code Quality | Synchronous file reads |
| SAST-132 | ℹ️ Info | Code Quality | TODO/FIXME annotations |

---

## Running Tests

```sh
node tests/scanner.test.js
```

---

## License

MIT © 2026 Ankit Chaurasiya