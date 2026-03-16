import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { SuiteResult, SuiteContext, Finding } from '../types.js';
import { computeSuiteScore, withTimeout } from '../utils.js';

export async function performanceSuite(
  client: Client,
  ctx: SuiteContext,
): Promise<SuiteResult> {
  const findings: Finding[] = [];
  const start = performance.now();

  // 1. Cold start time
  findings.push(coldStartFinding(ctx.connectDuration));

  // 2. tools/list latency
  const caps = client.getServerCapabilities();
  if (caps?.tools) {
    findings.push(
      await latencyFinding(
        'PERF-002',
        'tools/list latency',
        () => withTimeout(client.listTools(), ctx.timeout, 'tools/list (perf)'),
        1000,
      ),
    );
  }

  // 3. resources/list latency
  if (caps?.resources) {
    findings.push(
      await latencyFinding(
        'PERF-003',
        'resources/list latency',
        () => withTimeout(client.listResources(), ctx.timeout, 'resources/list (perf)'),
        1000,
      ),
    );
  }

  // 4. Ping latency
  findings.push(
    await latencyFinding(
      'PERF-004',
      'Ping latency',
      () => withTimeout(client.ping(), ctx.timeout, 'ping (perf)'),
      500,
    ),
  );

  // 5. Response size check (tools/list)
  if (caps?.tools) {
    findings.push(await responseSizeFinding(client, ctx));
  }

  const durationMs = Math.round(performance.now() - start);

  return {
    name: 'Performance',
    findings,
    score: computeSuiteScore(findings),
    certificationBlockers: [],
    evidence: { artifacts: [], durationMs },
  };
}

function coldStartFinding(durationMs: number): Finding {
  if (durationMs > 10_000) {
    return {
      id: 'PERF-001',
      title: 'Slow cold start',
      severity: 'medium',
      category: 'performance',
      description: `Server cold start took ${durationMs}ms (>10s threshold)`,
      evidence: `${durationMs}ms`,
      remediation: 'Optimize server startup; consider lazy-loading heavy dependencies',
    };
  }
  if (durationMs > 5_000) {
    return {
      id: 'PERF-001',
      title: 'Slow cold start',
      severity: 'low',
      category: 'performance',
      description: `Server cold start took ${durationMs}ms (>5s threshold)`,
      evidence: `${durationMs}ms`,
      remediation: 'Consider optimizing server startup time',
    };
  }
  return {
    id: 'PERF-001',
    title: 'Cold start time',
    severity: 'info',
    category: 'performance',
    description: `Server cold start completed in ${durationMs}ms`,
    evidence: `${durationMs}ms`,
  };
}

async function latencyFinding(
  id: string,
  name: string,
  fn: () => Promise<unknown>,
  warnThresholdMs: number,
): Promise<Finding> {
  const callStart = performance.now();
  try {
    await fn();
    const duration = Math.round(performance.now() - callStart);

    if (duration > warnThresholdMs * 3) {
      return {
        id,
        title: `Slow response: ${name}`,
        severity: 'low',
        category: 'performance',
        description: `${name} took ${duration}ms (>${warnThresholdMs * 3}ms threshold)`,
        evidence: `${duration}ms`,
        remediation: `Optimize ${name} to respond within ${warnThresholdMs}ms`,
      };
    }
    if (duration > warnThresholdMs) {
      return {
        id,
        title: `Slow response: ${name}`,
        severity: 'low',
        category: 'performance',
        description: `${name} took ${duration}ms (>${warnThresholdMs}ms threshold)`,
        evidence: `${duration}ms`,
      };
    }
    return {
      id,
      title: name,
      severity: 'info',
      category: 'performance',
      description: `${name}: ${duration}ms`,
      evidence: `${duration}ms`,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      id,
      title: `${name} failed`,
      severity: 'low',
      category: 'performance',
      description: `${name} call failed: ${msg}`,
      evidence: msg,
    };
  }
}

async function responseSizeFinding(client: Client, ctx: SuiteContext): Promise<Finding> {
  try {
    const result = await withTimeout(client.listTools(), ctx.timeout, 'tools/list (size)');
    const json = JSON.stringify(result);
    const bytes = new TextEncoder().encode(json).length;
    const kb = (bytes / 1024).toFixed(1);

    if (bytes > 1_000_000) {
      return {
        id: 'PERF-005',
        title: 'Large tools/list response',
        severity: 'medium',
        category: 'performance',
        description: `tools/list response is ${kb} KB (>1MB threshold)`,
        evidence: `${kb} KB (${bytes} bytes)`,
        remediation: 'Reduce tool descriptions or split into paginated responses',
      };
    }
    if (bytes > 100_000) {
      return {
        id: 'PERF-005',
        title: 'Large tools/list response',
        severity: 'low',
        category: 'performance',
        description: `tools/list response is ${kb} KB (>100KB threshold)`,
        evidence: `${kb} KB (${bytes} bytes)`,
      };
    }
    return {
      id: 'PERF-005',
      title: 'tools/list response size',
      severity: 'info',
      category: 'performance',
      description: `tools/list response size: ${kb} KB`,
      evidence: `${kb} KB`,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      id: 'PERF-005',
      title: 'tools/list response size check failed',
      severity: 'low',
      category: 'performance',
      description: `Could not measure response size: ${msg}`,
      evidence: msg,
    };
  }
}
