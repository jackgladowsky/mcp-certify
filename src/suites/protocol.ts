import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { SuiteResult, SuiteContext, TestResult } from '../types.js';
import { runTest, computeSuiteScore } from '../utils.js';

export async function protocolSuite(
  client: Client,
  ctx: SuiteContext,
): Promise<SuiteResult> {
  const tests: TestResult[] = [];

  // 1. Initialize handshake (already succeeded if we're here)
  tests.push(
    await runTest('Initialize handshake', async () => ({
      status: 'pass',
      message: `${ctx.connectDuration}ms`,
      duration: ctx.connectDuration,
    })),
  );

  // 2. Server info
  tests.push(
    await runTest('Server info present', async () => {
      const info = client.getServerVersion();
      if (!info) return { status: 'warn', message: 'No server info returned' };
      if (!info.name) return { status: 'warn', message: 'Server name missing' };
      return { status: 'pass', message: `${info.name} v${info.version}` };
    }),
  );

  // 3. Capabilities
  tests.push(
    await runTest('Capabilities declared', async () => {
      const caps = client.getServerCapabilities();
      if (!caps) return { status: 'warn', message: 'No capabilities declared' };
      const declared = Object.keys(caps).filter(
        (k) => (caps as Record<string, unknown>)[k],
      );
      if (declared.length === 0)
        return { status: 'warn', message: 'Empty capabilities' };
      return { status: 'pass', message: declared.join(', ') };
    }),
  );

  // 4. tools/list
  const caps = client.getServerCapabilities();
  if (caps?.tools) {
    tests.push(
      await runTest('tools/list returns valid response', async () => {
        const { tools } = await client.listTools();
        if (!Array.isArray(tools))
          return { status: 'fail', message: 'tools is not an array' };
        return { status: 'pass', message: `${tools.length} tool(s)` };
      }),
    );
  } else {
    tests.push({
      name: 'tools/list',
      status: 'skip',
      message: 'Tools capability not declared',
    });
  }

  // 5. resources/list
  if (caps?.resources) {
    tests.push(
      await runTest('resources/list returns valid response', async () => {
        const { resources } = await client.listResources();
        if (!Array.isArray(resources))
          return { status: 'fail', message: 'resources is not an array' };
        return { status: 'pass', message: `${resources.length} resource(s)` };
      }),
    );
  } else {
    tests.push({
      name: 'resources/list',
      status: 'skip',
      message: 'Resources capability not declared',
    });
  }

  // 6. prompts/list
  if (caps?.prompts) {
    tests.push(
      await runTest('prompts/list returns valid response', async () => {
        const { prompts } = await client.listPrompts();
        if (!Array.isArray(prompts))
          return { status: 'fail', message: 'prompts is not an array' };
        return { status: 'pass', message: `${prompts.length} prompt(s)` };
      }),
    );
  } else {
    tests.push({
      name: 'prompts/list',
      status: 'skip',
      message: 'Prompts capability not declared',
    });
  }

  // 7. Ping
  tests.push(
    await runTest('Ping responds', async () => {
      await client.ping();
      return { status: 'pass' };
    }),
  );

  return {
    name: 'Protocol',
    tests,
    score: computeSuiteScore(tests),
  };
}
