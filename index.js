#!/usr/bin/env node
/**
 * sast-scan — Lightweight JavaScript SAST Tool
 * @version 2.0.0
 * @author  Ankit Chaurasiya
 * @license MIT
 *
 * Entry point — re-exports everything from the scanner core.
 */

export { default, scanCode, scanCodeLegacy, SEVERITY, SEVERITY_WEIGHT, ScanResult, Finding, rules } from "./src/scanner.js";
export { CATEGORY, rules as ruleDefinitions } from "./src/rules.js";

// --- CLI wrapper (when executed directly) ---------------------------------
import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";

async function scanFile(filePath) {
	try {
		const code = await fs.readFile(filePath, "utf8");
		const { default: _scan, scanCode } = await import("./src/scanner.js");
		const result = scanCode(code, { file: filePath });
		console.log(result.toText());
	} catch (err) {
		console.error(`Error reading ${filePath}:`, err.message || err);
	}
}

async function scanDirectory(dirPath) {
	const entries = await fs.readdir(dirPath, { withFileTypes: true });
	for (const e of entries) {
		const full = path.join(dirPath, e.name);
		if (e.isDirectory()) {
			await scanDirectory(full);
		} else if (e.isFile() && full.endsWith(".js")) {
			await scanFile(full);
		}
	}
}

async function runCLI(args) {
	if (!args || args.length === 0) {
		// read from stdin
		const chunks = [];
		for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
		const code = Buffer.concat(chunks).toString("utf8");
		const { scanCode } = await import("./src/scanner.js");
		const result = scanCode(code, { file: "stdin" });
		console.log(result.toText());
		return;
	}

	for (const p of args) {
		try {
			const stat = await fs.stat(p);
			if (stat.isDirectory()) {
				await scanDirectory(p);
			} else if (stat.isFile()) {
				await scanFile(p);
			} else {
				console.error(`Skipping unsupported path: ${p}`);
			}
		} catch (err) {
			console.error(`Cannot access ${p}:`, err.message || err);
		}
	}
}

const __filename = fileURLToPath(import.meta.url);
if (process.argv[1] === __filename) {
	const args = process.argv.slice(2);
	runCLI(args).catch((err) => {
		console.error(err);
		process.exit(2);
	});
}