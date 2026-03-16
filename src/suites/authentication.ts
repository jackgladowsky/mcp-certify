import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { describeAuthConfig, hasAuthConfig } from '../auth/config.js';
import { connect } from '../connect.js';
import type { ServerTarget, SuiteContext, SuiteResult, Finding } from '../types.js';
import { computeSuiteScore, withTimeout } from '../utils.js';

export async function authenticationSuite(
  target: ServerTarget,
  client: Client,
  ctx: SuiteContext,
): Promise<SuiteResult> {
  const findings: Finding[] = [];
  const start = performance.now();
  const auth = ctx.options.auth;

  if (!hasAuthConfig(auth)) {
    findings.push({
      id: 'AUTH-SKIP-001',
      title: 'No authentication configured',
      severity: 'info',
      category: 'authentication',
      description: 'Authentication checks skipped because no auth options were provided.',
    });

    return {
      name: 'Authentication',
      findings,
      score: 100,
      certificationBlockers: [],
      evidence: { artifacts: [], durationMs: Math.round(performance.now() - start) },
    };
  }

  findings.push({
    id: 'AUTH-001',
    title: 'Authentication configuration detected',
    severity: 'info',
    category: 'authentication',
    description: describeAuthConfig(auth),
  });

  findings.push({
    id: 'AUTH-002',
    title: 'Authenticated connection succeeded',
    severity: 'info',
    category: 'authentication',
    description: authenticatedAccessSummary(client),
  });

  try {
    const { client: unauthenticatedClient } = await withTimeout(
      connect(target, {
        auth,
        includeAuth: false,
      }),
      ctx.timeout,
      'unauthenticated connect',
    );

    try {
      await unauthenticatedClient.close();
    } catch {
      // Best effort cleanup.
    }

    findings.push({
      id: 'AUTH-003',
      title: auth?.required
        ? 'Server accepted unauthenticated access'
        : 'Server accepted unauthenticated access with auth configured',
      severity: auth?.required ? 'high' : 'low',
      category: 'authentication',
      description: auth?.required
        ? 'The server was reachable without credentials even though authentication was marked as required.'
        : 'The server was reachable without credentials. This may be intentional, but auth is not enforced at connect time.',
      remediation: auth?.required
        ? 'Reject unauthenticated connections before exposing MCP capabilities.'
        : 'If this server is meant to be private, enforce authentication before session initialization.',
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    findings.push({
      id: 'AUTH-003',
      title: 'Unauthenticated access rejected',
      severity: 'info',
      category: 'authentication',
      description: `Connection without credentials failed: ${message}`,
    });
  }

  return {
    name: 'Authentication',
    findings,
    score: computeSuiteScore(findings),
    certificationBlockers: [],
    evidence: {
      artifacts: [],
      durationMs: Math.round(performance.now() - start),
    },
  };
}

function authenticatedAccessSummary(client: Client): string {
  const info = client.getServerVersion();
  if (!info) {
    return 'Authenticated connection completed successfully';
  }

  return `Authenticated connection completed successfully for ${info.name} v${info.version}`;
}
