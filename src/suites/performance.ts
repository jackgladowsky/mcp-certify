import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { SuiteResult, SuiteContext, TestResult } from '../types.js';
import { runTest, computeSuiteScore } from '../utils.js';

export async function performanceSuite(
  client: Client,
  ctx: SuiteContext,
): Promise<SuiteResult> {
  const tests: TestResult[] = [];

  // 1. Cold start time
  tests.push(coldStartTest(ctx.connectDuration));

  // 2. tools/list latency
  const caps = client.getServerCapabilities();
  if (caps?.tools) {
    tests.push(await latencyTest('tools/list latency', () => client.listTools(), 1000));
  }

  // 3. resources/list latency
  if (caps?.resources) {
    tests.push(
      await latencyTest('resources/list latency', () => client.listResources(), 1000),
    );
  }

  // 4. Ping latency
  tests.push(await latencyTest('Ping latency', () => client.ping(), 500));

  // 5. Response size check (tools/list)
  if (caps?.tools) {
    tests.push(await responseSizeTest(client));
  }

  return {
    name: 'Performance',
    tests,
    score: computeSuiteScore(tests),
  };
}

function coldStartTest(durationMs: number): TestResult {
  let status: TestResult['status'] = 'pass';
  if (durationMs > 10_000) status = 'fail';
  else if (durationMs > 5_000) status = 'warn';

  return {
    name: 'Cold start time',
    status,
    message: `${durationMs}ms`,
    duration: durationMs,
  };
}

async function latencyTest(
  name: string,
  fn: () => Promise<unknown>,
  warnThresholdMs: number,
): Promise<TestResult> {
  return runTest(name, async () => {
    const start = performance.now();
    await fn();
    const duration = Math.round(performance.now() - start);

    let status: TestResult['status'] = 'pass';
    if (duration > warnThresholdMs * 3) status = 'fail';
    else if (duration > warnThresholdMs) status = 'warn';

    return { status, message: `${duration}ms`, duration };
  });
}

async function responseSizeTest(client: Client): Promise<TestResult> {
  return runTest('tools/list response size', async () => {
    const result = await client.listTools();
    const json = JSON.stringify(result);
    const bytes = new TextEncoder().encode(json).length;
    const kb = (bytes / 1024).toFixed(1);

    let status: TestResult['status'] = 'pass';
    if (bytes > 1_000_000) status = 'fail';
    else if (bytes > 100_000) status = 'warn';

    return { status, message: `${kb} KB` };
  });
}
