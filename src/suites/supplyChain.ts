import { dirname, join, resolve } from 'node:path';
import { access, stat } from 'node:fs/promises';
import { runTrivy } from '../integrations/trivy.js';
import type { Finding, Severity, SuiteResult, Blocker } from '../types/index.js';

/** Severity-based score deductions. */
const DEDUCTIONS: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 10,
  low: 5,
  info: 0,
};

/**
 * Compute a score from 0-100 based on findings.
 * Starts at 100 and deducts based on severity. Minimum score is 0.
 */
function computeScore(findings: Finding[]): number {
  const totalDeduction = findings.reduce(
    (sum, f) => sum + (DEDUCTIONS[f.severity] ?? 0),
    0,
  );
  return Math.max(0, 100 - totalDeduction);
}

/**
 * Identify certification blockers: any critical supply-chain finding blocks cert.
 */
function findBlockers(findings: Finding[]): Blocker[] {
  return findings
    .filter((f) => f.severity === 'critical')
    .map((f) => ({
      findingId: f.id,
      gate: 'no-critical-supply-chain',
      reason: `Critical supply chain issue: ${f.title}`,
    }));
}

/**
 * Resolve the filesystem path to scan.
 *
 * Priority:
 * 1. Explicit scanPath option (from caller context)
 * 2. Directory containing the server command binary
 * 3. Current working directory as last resort
 */
const PROJECT_MARKERS = [
  'package.json',
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'pyproject.toml',
  'Cargo.toml',
] as const;

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function findProjectRoot(path: string): Promise<string> {
  let current = path;

  while (true) {
    for (const marker of PROJECT_MARKERS) {
      if (await fileExists(join(current, marker))) {
        return current;
      }
    }

    const parent = dirname(current);
    if (parent === current) {
      return path;
    }
    current = parent;
  }
}

export async function resolveScanPath(
  scanPath?: string,
  launchCommand?: string,
  launchArgs: string[] = [],
): Promise<string> {
  // Use explicit path if provided
  if (scanPath) {
    try {
      const info = await stat(scanPath);
      if (info.isDirectory()) return findProjectRoot(scanPath);
      // If it's a file, use its parent directory
      return findProjectRoot(dirname(scanPath));
    } catch {
      // Fall through to other options
    }
  }

  const candidateParts = [launchCommand, ...launchArgs].filter(
    (part): part is string => Boolean(part && part.trim().length > 0),
  );

  // Try to derive from the launch command and args.
  for (let i = candidateParts.length - 1; i >= 0; i--) {
    const part = candidateParts[i];
    const looksLikePath =
      part.startsWith('/') ||
      part.startsWith('./') ||
      part.startsWith('../') ||
      part.includes('/');

    if (!looksLikePath) {
      continue;
    }

    const resolvedPart = resolve(part);
    try {
      const info = await stat(resolvedPart);
      const baseDir = info.isDirectory() ? resolvedPart : dirname(resolvedPart);
      return findProjectRoot(baseDir);
    } catch {
      // Not a valid path, continue.
    }
  }

  return findProjectRoot(process.cwd());
}

interface SupplyChainOptions {
  scanPath?: string;
  launchCommand?: string;
  launchArgs?: string[];
  timeout?: number;
}

/**
 * Supply chain security suite using Trivy.
 *
 * Scans the server's filesystem for vulnerabilities, secrets, and
 * misconfigurations in dependencies and configuration files.
 */
export async function supplyChainSuite(
  options: SupplyChainOptions = {},
): Promise<SuiteResult> {
  const timeout = options.timeout ?? 120_000; // 2 minutes default for trivy
  const startTime = performance.now();

  const targetPath = await resolveScanPath(
    options.scanPath,
    options.launchCommand,
    options.launchArgs ?? [],
  );

  const { findings, rawOutput } = await runTrivy(targetPath, timeout);

  const durationMs = Math.round(performance.now() - startTime);
  const score = computeScore(findings);
  const certificationBlockers = findBlockers(findings);

  return {
    name: 'Supply Chain',
    findings,
    score,
    certificationBlockers,
    evidence: {
      rawOutput,
      artifacts: [
        {
          name: 'trivy-scan-result',
          type: 'json',
          content: rawOutput,
        },
      ],
      durationMs,
    },
  };
}
