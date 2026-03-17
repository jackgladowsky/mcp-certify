import type { ServerTarget } from '../types.js';
import { applyAuthEnv } from '../auth/config.js';
import type { SuiteResult, SuiteContext, Finding, Blocker, Artifact } from '../types/index.js';
import { runInHarness } from '../runtime/harness.js';
import type { HarnessConfig } from '../runtime/harness.js';
import type { Scenario } from '../runtime/scenarios/types.js';
import { secretExfilScenario } from '../runtime/scenarios/secretExfil.js';
import { fileReadScenario } from '../runtime/scenarios/fileRead.js';
import { networkEgressScenario } from '../runtime/scenarios/networkEgress.js';
import { promptInjectionScenario } from '../runtime/scenarios/promptInjection.js';
import { resourceExfilScenario } from '../runtime/scenarios/resourceExfil.js';
import { assessRuntimeSupport, resolveRuntimeTarget } from '../runtime/support.js';

/** All runtime security scenarios in execution order. */
const ALL_SCENARIOS: Scenario[] = [
  secretExfilScenario,
  fileReadScenario,
  networkEgressScenario,
  promptInjectionScenario,
  resourceExfilScenario,
];

function makeCoverageUnavailableResult(
  startTime: number,
  coverageStatus: 'disabled' | 'unsupported_transport' | 'unsupported_launcher' | 'error',
  finding: Finding,
  rawOutput: string,
): SuiteResult {
  const blockers: Blocker[] =
    coverageStatus === 'disabled'
      ? []
      : [
          {
            findingId: finding.id,
            gate: 'runtime-coverage-unavailable',
            reason: `Runtime coverage unavailable: ${finding.title}`,
          },
        ];

  return {
    name: 'Runtime Security',
    findings: [finding],
    score: 0,
    certificationBlockers: blockers,
    evidence: {
      rawOutput,
      artifacts: [],
      durationMs: Math.round(performance.now() - startTime),
      coverage: {
        status: coverageStatus,
        detail: finding.description,
      },
    },
  };
}

/**
 * Runtime Security Suite
 *
 * Launches the MCP server in a sandboxed environment with canary files and
 * a network capture proxy, then runs attack scenarios to detect:
 *
 * - Secret file exfiltration (SSH keys, AWS creds, .env)
 * - Unauthorized file reads outside declared scope
 * - Outbound network egress to unapproved hosts
 * - Prompt injection / rug-pull in tool descriptions
 * - Sensitive data exposure through resources
 */
export async function runtimeSecuritySuite(
  target: ServerTarget,
  ctx: SuiteContext,
): Promise<SuiteResult> {
  const startTime = performance.now();

  // If sandbox mode is not enabled, return an info-level skip finding
  if (!ctx.options.sandbox) {
    return makeCoverageUnavailableResult(startTime, 'disabled', {
      id: 'RUNTIME-SKIP',
      title: 'Runtime security testing disabled',
      severity: 'info',
      category: 'runtime-coverage',
      description:
        'Runtime sandbox testing was not enabled. Use --sandbox to run the full runtime security harness.',
    }, 'Runtime testing disabled (use --sandbox)');
  }

  // Build harness config from server target
  const runtimeSupport = assessRuntimeSupport(target);
  if (runtimeSupport.status === 'unsupported_transport') {
    return makeCoverageUnavailableResult(startTime, 'unsupported_transport', {
      id: 'RUNTIME-NOCOMMAND',
      title: 'Runtime sandbox unsupported for HTTP targets',
      severity: 'medium',
      category: 'runtime-coverage',
      description: runtimeSupport.detail,
      remediation:
        'Run runtime analysis against a local stdio build of the server, or rely on the non-runtime suites for HTTP targets.',
    }, 'Server is HTTP-based; runtime sandbox coverage unavailable for this transport.');
  }

  if (runtimeSupport.status === 'unsupported_launcher') {
    return makeCoverageUnavailableResult(startTime, 'unsupported_launcher', {
      id: 'RUNTIME-LAUNCHER',
      title: 'Runtime sandbox unsupported for package-manager launchers',
      severity: 'medium',
      category: 'runtime-coverage',
      description: runtimeSupport.detail,
      remediation:
        'Run the built server directly (for example `node dist/index.js` or `python path/to/server.py`) before using --sandbox.',
    }, `Unsupported runtime launcher detected: ${runtimeSupport.launcher ?? 'unknown launcher'}`);
  }

  const runtimeTarget = resolveRuntimeTarget(target);
  if (!runtimeTarget?.command) {
    return makeCoverageUnavailableResult(startTime, 'error', {
      id: 'RUNTIME-ERROR',
      title: 'Runtime harness target resolution failed',
      severity: 'medium',
      category: 'runtime-coverage',
      description:
        'Runtime coverage was marked supported, but the launch command could not be resolved for harness execution.',
      remediation:
        'Run the built server directly from a stable local executable before relying on runtime coverage.',
    }, 'Harness target resolution failed.');
  }

  const harnessConfig: HarnessConfig = {
    command: runtimeTarget.command,
    args: runtimeTarget.args ?? [],
    env: applyAuthEnv(target.env, ctx.options.auth),
    timeout: ctx.timeout ?? 30_000,
  };

  try {
    const result = await runInHarness(harnessConfig, ALL_SCENARIOS, {
      allowHosts: ctx.options.allowHosts,
      denyHosts: ctx.options.denyHosts,
    });

    // Collect all findings from scenario results
    const allFindings: Finding[] = [];
    const evidenceLines: string[] = [];

    for (const [scenarioId, scenarioResult] of result.scenarioResults) {
      allFindings.push(...scenarioResult.findings);
      evidenceLines.push(`[${scenarioId}] ${scenarioResult.evidence}`);
    }

    // Add harness-level findings for canary leaks detected in raw output
    if (result.canaryLeaks.length > 0) {
      allFindings.push({
        id: 'RUNTIME-EXFIL-002',
        title: 'Canary tokens detected in server stderr',
        severity: 'critical',
        category: 'runtime-exfil',
        description: `${result.canaryLeaks.length} canary token(s) from seeded credential files appeared in server stderr.`,
        evidence: `Leaked tokens: ${result.canaryLeaks.length}`,
        remediation:
          'The server must not read or output user credential file contents.',
      });
    }

    // Generate certification blockers for critical/high findings
    const blockers: Blocker[] = [];
    for (const finding of allFindings) {
      if (finding.severity === 'critical') {
        blockers.push({
          findingId: finding.id,
          gate: 'runtime-critical',
          reason: `Critical runtime finding: ${finding.title}`,
        });
      } else if (
        finding.severity === 'high' &&
        (finding.category === 'runtime-network' ||
          finding.category === 'runtime-file' ||
          finding.category === 'runtime-injection' ||
          finding.category === 'runtime-resexfil')
      ) {
        blockers.push({
          findingId: finding.id,
          gate: 'runtime-high',
          reason: `High runtime finding: ${finding.title}`,
        });
      }
    }

    // Compute score
    const score = computeRuntimeScore(allFindings);

    // Build evidence artifacts
    const artifacts: Artifact[] = [];

    if (result.stderr) {
      artifacts.push({
        name: 'server-stderr',
        type: 'log',
        content: result.stderr.slice(0, 10_000),
      });
    }

    if (result.networkRequests.length > 0) {
      artifacts.push({
        name: 'network-requests',
        type: 'json',
        content: JSON.stringify(result.networkRequests, null, 2),
      });
    }

    if (result.filesAccessed.length > 0) {
      artifacts.push({
        name: 'files-accessed',
        type: 'json',
        content: JSON.stringify(result.filesAccessed, null, 2),
      });
    }

    return {
      name: 'Runtime Security',
      findings: allFindings,
      score,
      certificationBlockers: blockers,
      evidence: {
        rawOutput: evidenceLines.join('\n'),
        artifacts,
        durationMs: result.durationMs,
        coverage: {
          status: 'full',
        },
      },
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return makeCoverageUnavailableResult(startTime, 'error', {
      id: 'RUNTIME-ERROR',
      title: 'Runtime harness failed',
      severity: 'medium',
      category: 'runtime-coverage',
      description: `The runtime security harness encountered an error: ${msg}`,
      evidence: msg,
      remediation:
        'Fix the harness failure or run the server directly from a stable local build before relying on runtime coverage.',
    }, `Harness error: ${msg}`);
  }
}

/**
 * Compute a 0-100 score based on runtime findings.
 *
 * - Start at 100
 * - Each critical finding: -25 points
 * - Each high finding: -15 points
 * - Each medium finding: -5 points
 * - Floor at 0
 */
function computeRuntimeScore(findings: Finding[]): number {
  let score = 100;
  for (const f of findings) {
    switch (f.severity) {
      case 'critical':
        score -= 25;
        break;
      case 'high':
        score -= 15;
        break;
      case 'medium':
        score -= 5;
        break;
      case 'low':
        score -= 2;
        break;
      default:
        break;
    }
  }
  return Math.max(0, score);
}
