import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { Finding, Severity } from '../types/index.js';

const execFileAsync = promisify(execFile);

interface TrivyResult {
  findings: Finding[];
  rawOutput: string;
}

/** Trivy severity strings mapped to our Severity type. */
const SEVERITY_MAP: Record<string, Severity> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  UNKNOWN: 'info',
};

function mapTrivySeverity(trivySeverity: string): Severity {
  return SEVERITY_MAP[trivySeverity.toUpperCase()] ?? 'info';
}

/**
 * Check whether Trivy is installed and accessible.
 */
export async function isTrivyInstalled(): Promise<boolean> {
  try {
    await execFileAsync('trivy', ['--version'], { timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
}

export async function isTrivyDatabaseReady(timeout: number = 10_000): Promise<boolean> {
  if (!(await isTrivyInstalled())) {
    return false;
  }

  const scanDir = await mkdtemp(join(tmpdir(), 'mcp-certify-trivy-check-'));
  try {
    await execFileAsync(
      'trivy',
      ['filesystem', '--skip-db-update', '--scanners', 'vuln', '--format', 'json', scanDir],
      {
        timeout,
        maxBuffer: 10 * 1024 * 1024,
      },
    );
    return true;
  } catch {
    return false;
  } finally {
    await rm(scanDir, { recursive: true, force: true }).catch(() => undefined);
  }
}

export async function warmTrivyDatabase(timeout: number = 300_000): Promise<void> {
  if (!(await isTrivyInstalled())) {
    throw new Error('Trivy is not installed');
  }

  const scanDir = await mkdtemp(join(tmpdir(), 'mcp-certify-trivy-warm-'));
  try {
    await execFileAsync(
      'trivy',
      ['filesystem', '--download-db-only', '--no-progress', scanDir],
      {
        timeout,
        maxBuffer: 20 * 1024 * 1024,
      },
    );
  } finally {
    await rm(scanDir, { recursive: true, force: true }).catch(() => undefined);
  }
}

/** Shape of a vulnerability entry in Trivy JSON output. */
interface TrivyVuln {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Severity?: string;
  Title?: string;
  Description?: string;
  PrimaryURL?: string;
}

/** Shape of a secret finding in Trivy JSON output. */
interface TrivySecret {
  RuleID?: string;
  Category?: string;
  Severity?: string;
  Title?: string;
  Match?: string;
  StartLine?: number;
  EndLine?: number;
}

/** Shape of a misconfiguration finding in Trivy JSON output. */
interface TrivyMisconfig {
  ID?: string;
  Type?: string;
  Severity?: string;
  Title?: string;
  Description?: string;
  Message?: string;
  Resolution?: string;
}

/** Shape of a result entry in Trivy JSON output. */
interface TrivyResultEntry {
  Target?: string;
  Type?: string;
  Vulnerabilities?: TrivyVuln[];
  Secrets?: TrivySecret[];
  Misconfigurations?: TrivyMisconfig[];
}

/** Top-level Trivy JSON output shape. */
interface TrivyOutput {
  Results?: TrivyResultEntry[];
}

/**
 * Parse Trivy JSON output into Finding objects.
 */
function parseTrivyOutput(jsonStr: string): Finding[] {
  const findings: Finding[] = [];
  let vulnCounter = 1;
  let secretCounter = 1;
  let misconfigCounter = 1;

  let output: TrivyOutput;
  try {
    output = JSON.parse(jsonStr) as TrivyOutput;
  } catch {
    findings.push({
      id: 'TRIVY-ERR-001',
      title: 'Failed to parse Trivy output',
      severity: 'medium',
      category: 'supply-chain-vuln',
      description: 'Could not parse Trivy JSON output.',
      evidence: jsonStr.slice(0, 2000),
      source: 'trivy',
    });
    return findings;
  }

  const results = output.Results ?? [];

  for (const result of results) {
    const target = result.Target ?? 'unknown';

    // Vulnerabilities
    if (Array.isArray(result.Vulnerabilities)) {
      for (const vuln of result.Vulnerabilities) {
        const id = `TRIVY-VULN-${String(vulnCounter).padStart(3, '0')}`;
        const severity = mapTrivySeverity(vuln.Severity ?? 'UNKNOWN');
        const fixInfo = vuln.FixedVersion
          ? ` (fix available: ${vuln.FixedVersion})`
          : ' (no fix available)';

        findings.push({
          id,
          title: vuln.Title ?? `${vuln.VulnerabilityID ?? 'Unknown vulnerability'} in ${vuln.PkgName ?? target}`,
          severity,
          category: 'supply-chain-vuln',
          description:
            (vuln.Description ?? `Vulnerability ${vuln.VulnerabilityID ?? ''} found in ${vuln.PkgName ?? 'unknown package'}`).slice(0, 1000) +
            (vuln.PkgName ? ` [${vuln.PkgName}@${vuln.InstalledVersion ?? '?'}${fixInfo}]` : ''),
          evidence: vuln.VulnerabilityID
            ? `${vuln.VulnerabilityID} - ${target}`
            : target,
          source: 'trivy',
          remediation: vuln.FixedVersion
            ? `Update ${vuln.PkgName ?? 'package'} to ${vuln.FixedVersion}`
            : vuln.PrimaryURL
              ? `See ${vuln.PrimaryURL}`
              : undefined,
        });
        vulnCounter++;
      }
    }

    // Secrets
    if (Array.isArray(result.Secrets)) {
      for (const secret of result.Secrets) {
        const id = `TRIVY-SECRET-${String(secretCounter).padStart(3, '0')}`;
        const severity = mapTrivySeverity(secret.Severity ?? 'HIGH');

        findings.push({
          id,
          title: secret.Title ?? `Secret detected: ${secret.RuleID ?? 'unknown'}`,
          severity,
          category: 'supply-chain-secret',
          description: `Secret found in ${target}${secret.StartLine ? ` at line ${secret.StartLine}` : ''}`,
          evidence: secret.Match ? secret.Match.slice(0, 200) : undefined,
          source: 'trivy',
          remediation: 'Remove the secret from source code and rotate the credential',
        });
        secretCounter++;
      }
    }

    // Misconfigurations
    if (Array.isArray(result.Misconfigurations)) {
      for (const misconfig of result.Misconfigurations) {
        const id = `TRIVY-MISCONFIG-${String(misconfigCounter).padStart(3, '0')}`;
        const severity = mapTrivySeverity(misconfig.Severity ?? 'MEDIUM');

        findings.push({
          id,
          title: misconfig.Title ?? `Misconfiguration: ${misconfig.ID ?? 'unknown'}`,
          severity,
          category: 'supply-chain-misconfig',
          description: misconfig.Description ?? misconfig.Message ?? `Misconfiguration ${misconfig.ID ?? ''} in ${target}`,
          evidence: misconfig.Message
            ? `${target}: ${misconfig.Message}`
            : target,
          source: 'trivy',
          remediation: misconfig.Resolution ?? undefined,
        });
        misconfigCounter++;
      }
    }
  }

  return findings;
}

/**
 * Run Trivy filesystem scan against a target path.
 *
 * If Trivy is not installed, returns a single info finding indicating
 * the scan was skipped.
 */
export async function runTrivy(
  targetPath: string,
  timeout: number,
): Promise<TrivyResult> {
  // Check installation
  if (!(await isTrivyInstalled())) {
    return {
      findings: [
        {
          id: 'TRIVY-000',
          title: 'Trivy not installed',
          severity: 'info',
          category: 'supply-chain-vuln',
          description:
            'trivy not installed, skipping supply chain scan. Install from https://aquasecurity.github.io/trivy/',
          source: 'trivy',
        },
      ],
      rawOutput: '',
    };
  }

  try {
    const { stdout, stderr } = await execFileAsync(
      'trivy',
      [
        'fs',
        '--format',
        'json',
        '--scanners',
        'vuln,secret,misconfig',
        targetPath,
      ],
      {
        timeout,
        maxBuffer: 50 * 1024 * 1024, // 50 MB -- trivy output can be large
      },
    );

    const rawOutput = stdout + (stderr ? `\n--- stderr ---\n${stderr}` : '');
    const findings = parseTrivyOutput(stdout);

    // If Trivy ran but found nothing, that's a good sign
    if (findings.length === 0) {
      findings.push({
        id: 'TRIVY-CLEAN',
        title: 'No supply chain issues found',
        severity: 'info',
        category: 'supply-chain-vuln',
        description: 'Trivy scan completed with no vulnerabilities, secrets, or misconfigurations.',
        source: 'trivy',
      });
    }

    return { findings, rawOutput };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    const isTimeout = message.includes('timed out') || message.includes('TIMEOUT');

    return {
      findings: [
        {
          id: 'TRIVY-ERR',
          title: isTimeout ? 'Trivy scan timed out' : 'Trivy scan failed',
          severity: 'medium',
          category: 'supply-chain-vuln',
          description: `Trivy failed: ${message}`,
          source: 'trivy',
          remediation: isTimeout
            ? 'Increase the timeout or reduce the scan scope'
            : 'Verify Trivy is correctly installed and the target path exists',
        },
      ],
      rawOutput: message,
    };
  }
}
