import { dirname } from 'node:path';
import { stat } from 'node:fs/promises';
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
 * 1. Explicit scanPath option (from --scan-path or context)
 * 2. Directory containing the server command binary
 * 3. Current working directory as last resort
 */
async function resolveScanPath(
  scanPath?: string,
  serverCommand?: string,
): Promise<string> {
  // Use explicit path if provided
  if (scanPath) {
    try {
      const info = await stat(scanPath);
      if (info.isDirectory()) return scanPath;
      // If it's a file, use its parent directory
      return dirname(scanPath);
    } catch {
      // Fall through to other options
    }
  }

  // Try to derive from the server command
  if (serverCommand) {
    // For commands like "node /path/to/server.js" or "python3 /path/to/main.py"
    // extract the script path and use its directory
    const parts = serverCommand.split(/\s+/);
    // Check the last part (or the second part for interpreter commands)
    for (let i = parts.length - 1; i >= 0; i--) {
      const part = parts[i];
      if (part.startsWith('/') || part.startsWith('./') || part.startsWith('../')) {
        try {
          const info = await stat(part);
          return info.isDirectory() ? part : dirname(part);
        } catch {
          // Not a valid path, continue
        }
      }
    }

    // For a bare command, try the command itself (e.g. "npx" -> cwd)
    // Fall through to cwd
  }

  return process.cwd();
}

interface SupplyChainOptions {
  scanPath?: string;
  serverCommand?: string;
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

  const targetPath = await resolveScanPath(options.scanPath, options.serverCommand);

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
