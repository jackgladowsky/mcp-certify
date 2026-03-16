import { connect } from './connect.js';
import { protocolSuite } from './suites/protocol.js';
import { securitySuite } from './suites/security.js';
import { functionalSuite } from './suites/functional.js';
import { performanceSuite } from './suites/performance.js';
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
  Protocol: 0.35,
  Security: 0.35,
  Functional: 0.2,
  Performance: 0.1,
};

function computeOverallScore(
  suites: SuiteResult[],
): { score: number; breakdown: { name: string; score: number }[] } {
  const breakdown = suites.map((s) => ({ name: s.name, score: s.score }));
  const score = suites.reduce((sum, suite) => {
    const weight = SUITE_WEIGHTS[suite.name] ?? 0.25;
    return sum + suite.score * weight;
  }, 0);
  return { score: Math.round(score), breakdown };
}

function evaluateGates(suites: SuiteResult[]): Blocker[] {
  const allFindings: Finding[] = suites.flatMap((s) => s.findings);
  const blockers: Blocker[] = [];
  for (const gate of DEFAULT_GATES) {
    blockers.push(...gate.evaluate(allFindings));
  }
  return blockers;
}

export async function run(
  target: ServerTarget,
  options: RunOptions = {},
): Promise<CertifyReport> {
  const timeout = options.timeout ?? target.timeout ?? 10000;
  const connectStart = performance.now();
  const { client } = await connect(target);
  const connectDuration = Math.round(performance.now() - connectStart);

  const serverVersion = client.getServerVersion();
  const capabilities = client.getServerCapabilities();

  const ctx: SuiteContext = {
    capabilities: (capabilities as Record<string, unknown>) ?? {},
    connectDuration,
    options,
    timeout,
  };

  const suites = [
    await protocolSuite(client, ctx),
    await securitySuite(client, ctx),
    await functionalSuite(client, ctx),
    await performanceSuite(client, ctx),
  ];

  try {
    await client.close();
  } catch {
    // Server may have already disconnected
  }

  const blockers = evaluateGates(suites);

  // Apply blocker info back to each suite
  for (const suite of suites) {
    suite.certificationBlockers = blockers.filter((b) =>
      suite.findings.some((f) => f.id === b.findingId),
    );
  }

  const { score, breakdown } = computeOverallScore(suites);

  // Determine decision: fail if any blockers, or if failOn override triggers
  let decision: CertificationDecision = blockers.length > 0 ? 'fail' : 'pass';

  // failOn override: check if any finding meets or exceeds the specified severity
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
  };
}
