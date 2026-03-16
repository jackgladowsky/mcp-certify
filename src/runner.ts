import { connect } from './connect.js';
import { protocolSuite } from './suites/protocol.js';
import { securitySuite } from './suites/security.js';
import { functionalSuite } from './suites/functional.js';
import { performanceSuite } from './suites/performance.js';
import type {
  ServerTarget,
  CertifyResult,
  RunOptions,
  SuiteResult,
  SuiteContext,
} from './types.js';

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

export async function run(
  target: ServerTarget,
  options: RunOptions = {},
): Promise<CertifyResult> {
  const connectStart = performance.now();
  const { client } = await connect(target);
  const connectDuration = Math.round(performance.now() - connectStart);

  const serverVersion = client.getServerVersion();
  const capabilities = client.getServerCapabilities();

  const ctx: SuiteContext = {
    capabilities: (capabilities as Record<string, unknown>) ?? {},
    connectDuration,
    options,
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

  const { score, breakdown } = computeOverallScore(suites);

  return {
    server: serverVersion
      ? { name: serverVersion.name, version: serverVersion.version }
      : undefined,
    suites,
    score,
    breakdown,
    timestamp: new Date().toISOString(),
  };
}
