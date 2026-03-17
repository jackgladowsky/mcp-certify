import { connect } from './connect.js';
import { protocolSuite } from './suites/protocol.js';
import { authenticationSuite } from './suites/authentication.js';
import { securitySuite } from './suites/security.js';
import { functionalSuite } from './suites/functional.js';
import { performanceSuite } from './suites/performance.js';
import { supplyChainSuite } from './suites/supplyChain.js';
import { runtimeSecuritySuite } from './suites/runtimeSecurity.js';
import { manifestDiffSuite } from './suites/manifestDiff.js';
import { PROFILES } from './profiles/presets.js';
import { withTimeout } from './utils.js';
import type {
  ServerTarget,
  CertifyReport,
  RunOptions,
  SuiteResult,
  SuiteContext,
  Finding,
  Blocker,
  CertificationDecision,
} from './types.js';
import { DEFAULT_GATES } from './types.js';

const SUITE_WEIGHTS: Record<string, number> = {
  Protocol: 0.22,
  Authentication: 0.1,
  Security: 0.22,
  Functional: 0.12,
  Performance: 0.08,
  'Supply Chain': 0.14,
  'Runtime Security': 0.18,
  'Manifest Diff': 0.04,
};

const DEFAULT_SUITES = [
  'protocol',
  'security',
  'functional',
  'performance',
] as const;

function computeOverallScore(
  suites: SuiteResult[],
): { score: number; breakdown: { name: string; score: number }[] } {
  const breakdown = suites.map((s) => ({ name: s.name, score: s.score }));
  const totalWeight = suites.reduce(
    (sum, suite) => sum + (SUITE_WEIGHTS[suite.name] ?? 0.1),
    0,
  );

  if (totalWeight === 0) {
    return { score: 100, breakdown };
  }

  const score = suites.reduce((sum, suite) => {
    const weight = SUITE_WEIGHTS[suite.name] ?? 0.1;
    return sum + suite.score * (weight / totalWeight);
  }, 0);

  return { score: Math.round(score), breakdown };
}

function dedupeBlockers(blockers: Blocker[]): Blocker[] {
  const seen = new Set<string>();
  return blockers.filter((blocker) => {
    const key = `${blocker.findingId}:${blocker.gate}:${blocker.reason}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function buildThresholdBlockers(
  findings: Finding[],
  score: number,
  options: RunOptions,
): Blocker[] {
  if (!options.profile) return [];

  const profile = PROFILES[options.profile];
  if (!profile) return [];

  const blockers: Blocker[] = [];
  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const highCount = findings.filter((f) => f.severity === 'high').length;

  if (
    profile.failThresholds.minScore !== undefined &&
    score < profile.failThresholds.minScore
  ) {
    blockers.push({
      findingId: 'PROFILE-MIN-SCORE',
      gate: 'profile-min-score',
      reason: `Profile "${profile.name}" requires score >= ${profile.failThresholds.minScore}`,
    });
  }

  if (
    profile.failThresholds.maxCritical !== undefined &&
    criticalCount > profile.failThresholds.maxCritical
  ) {
    blockers.push({
      findingId: 'PROFILE-MAX-CRITICAL',
      gate: 'profile-max-critical',
      reason: `Profile "${profile.name}" allows at most ${profile.failThresholds.maxCritical} critical findings`,
    });
  }

  if (
    profile.failThresholds.maxHigh !== undefined &&
    highCount > profile.failThresholds.maxHigh
  ) {
    blockers.push({
      findingId: 'PROFILE-MAX-HIGH',
      gate: 'profile-max-high',
      reason: `Profile "${profile.name}" allows at most ${profile.failThresholds.maxHigh} high findings`,
    });
  }

  return blockers;
}

function evaluateGates(
  suites: SuiteResult[],
  score: number,
  options: RunOptions,
): Blocker[] {
  const allFindings: Finding[] = suites.flatMap((s) => s.findings);
  const blockers: Blocker[] = suites.flatMap((suite) => suite.certificationBlockers);

  for (const gate of DEFAULT_GATES) {
    blockers.push(...gate.evaluate(allFindings));
  }

  blockers.push(...buildThresholdBlockers(allFindings, score, options));
  return dedupeBlockers(blockers);
}

function mergeDefinedOptions(base: Partial<RunOptions>, overrides: RunOptions): RunOptions {
  return {
    callTools: overrides.callTools ?? base.callTools,
    timeout: overrides.timeout ?? base.timeout,
    profile: overrides.profile ?? base.profile,
    auth: overrides.auth ?? base.auth,
    policyPath: overrides.policyPath ?? base.policyPath,
    baselinePath: overrides.baselinePath ?? base.baselinePath,
    artifactsDir: overrides.artifactsDir ?? base.artifactsDir,
    failOn: overrides.failOn ?? base.failOn,
    sandbox: overrides.sandbox ?? base.sandbox,
    allowHosts: overrides.allowHosts ?? base.allowHosts,
    denyHosts: overrides.denyHosts ?? base.denyHosts,
  };
}

function selectSuiteIds(target: ServerTarget, options: RunOptions): string[] {
  const profile = options.profile ? PROFILES[options.profile] : undefined;
  if (options.profile && !profile) {
    throw new Error(`Unknown profile: ${options.profile}`);
  }

  if (profile) {
    const selected = [...profile.suites];
    if (options.auth && !selected.includes('authentication')) {
      selected.push('authentication');
    }
    return selected;
  }

  const selected: string[] = [...DEFAULT_SUITES];
  if (options.auth) {
    selected.push('authentication');
  }
  if (target.command) {
    selected.push('supplyChain');
  }
  if (options.baselinePath || options.artifactsDir) {
    selected.push('manifestDiff');
  }
  if (options.sandbox) {
    selected.push('runtime');
  }
  return selected;
}

export async function run(
  target: ServerTarget,
  incomingOptions: RunOptions = {},
): Promise<CertifyReport> {
  const profileDefaults = incomingOptions.profile
    ? PROFILES[incomingOptions.profile]?.options ?? {}
    : {};
  const options = mergeDefinedOptions(profileDefaults, incomingOptions);
  const timeout = options.timeout ?? target.timeout ?? 10000;
  const suiteIds = selectSuiteIds(target, options);

  const connectStart = performance.now();
  const { client } = await withTimeout(
    connect(target, { auth: options.auth }),
    timeout,
    'connect',
  );
  const connectDuration = Math.round(performance.now() - connectStart);

  const serverVersion = client.getServerVersion();
  const capabilities = client.getServerCapabilities();

  const ctx: SuiteContext = {
    capabilities: (capabilities as Record<string, unknown>) ?? {},
    connectDuration,
    options,
    timeout,
  };

  const suites: SuiteResult[] = [];

  try {
    if (suiteIds.includes('protocol')) {
      suites.push(await protocolSuite(client, ctx));
    }
    if (suiteIds.includes('authentication')) {
      suites.push(await authenticationSuite(target, client, ctx));
    }
    if (suiteIds.includes('security')) {
      suites.push(await securitySuite(client, ctx));
    }
    if (suiteIds.includes('functional')) {
      suites.push(await functionalSuite(client, ctx));
    }
    if (suiteIds.includes('performance')) {
      suites.push(await performanceSuite(client, ctx));
    }
    if (suiteIds.includes('manifestDiff')) {
      suites.push(await manifestDiffSuite(client, ctx));
    }
  } finally {
    try {
      await client.close();
    } catch {
      // Server may have already disconnected
    }
  }

  if (suiteIds.includes('supplyChain')) {
    suites.push(
      await supplyChainSuite({
        serverCommand: [target.command, ...(target.args ?? [])]
          .filter(Boolean)
          .join(' '),
        timeout,
      }),
    );
  }

  if (suiteIds.includes('runtime')) {
    suites.push(await runtimeSecuritySuite(target, ctx));
  }

  const { score, breakdown } = computeOverallScore(suites);
  const blockers = evaluateGates(suites, score, options);

  for (const suite of suites) {
    const derived = blockers.filter((b) =>
      suite.findings.some((f) => f.id === b.findingId),
    );
    suite.certificationBlockers = dedupeBlockers([
      ...suite.certificationBlockers,
      ...derived,
    ]);
  }

  let decision: CertificationDecision = blockers.length > 0 ? 'fail' : 'pass';

  if (options.failOn && decision === 'pass') {
    const severityOrder: Record<string, number> = {
      info: 0,
      low: 1,
      medium: 2,
      high: 3,
      critical: 4,
    };
    const threshold = severityOrder[options.failOn] ?? 0;
    const allFindings = suites.flatMap((s) => s.findings);
    const exceeds = allFindings.some(
      (f) => (severityOrder[f.severity] ?? 0) >= threshold,
    );
    if (exceeds) {
      decision = 'fail';
    }
  }

  const notes: string[] = [];
  if (target.url) {
    notes.push(
      'Remote target: Supply Chain is skipped because there is no local project tree to scan, and Runtime Security sandbox coverage is unavailable for HTTP targets.',
    );
  }

  return {
    server: serverVersion
      ? { name: serverVersion.name, version: serverVersion.version }
      : undefined,
    decision,
    blockers,
    suites,
    score,
    breakdown,
    timestamp: new Date().toISOString(),
    profile: options.profile,
    notes,
  };
}
