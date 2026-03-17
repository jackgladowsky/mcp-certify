import { describe, it, expect } from 'vitest';
import { run } from '../../src/runner.js';
import { resolve } from 'node:path';

const SAFE_SERVER = resolve(import.meta.dirname, '../../fixtures/servers/safe-server.ts');

describe('safe server', () => {
  it('certifies with decision pass', async () => {
    const result = await run(
      { command: 'npx', args: ['tsx', SAFE_SERVER] },
      { timeout: 20_000 },
    );
    expect(result.decision).toBe('pass');
    expect(result.blockers).toHaveLength(0);
  });

  it('scores >= 95', async () => {
    const result = await run(
      { command: 'npx', args: ['tsx', SAFE_SERVER] },
      { timeout: 20_000 },
    );
    expect(result.score).toBeGreaterThanOrEqual(95);
  });

  it('has no critical or high findings', async () => {
    const result = await run(
      { command: 'npx', args: ['tsx', SAFE_SERVER] },
      { timeout: 20_000 },
    );
    const allFindings = result.suites.flatMap((s) => s.findings);
    const bad = allFindings.filter(
      (f) => f.severity === 'critical' || f.severity === 'high',
    );
    expect(bad).toHaveLength(0);
  });

  it('runs protocol, security, functional, performance suites', async () => {
    const result = await run(
      { command: 'npx', args: ['tsx', SAFE_SERVER] },
      { timeout: 20_000 },
    );
    const suiteNames = result.suites.map((s) => s.name);
    expect(suiteNames).toContain('Protocol');
    expect(suiteNames).toContain('Security');
    expect(suiteNames).toContain('Functional');
    expect(suiteNames).toContain('Performance');
  });

  it('detects server info', async () => {
    const result = await run(
      { command: 'npx', args: ['tsx', SAFE_SERVER] },
      { timeout: 20_000 },
    );
    expect(result.server).toBeDefined();
    expect(result.server?.name).toBe('safe-reference-server');
  });

  it(
    'passes enterprise-strict when runtime launcher can be unwrapped',
    { timeout: 120_000 },
    async () => {
      const result = await run(
        { command: 'npx', args: ['tsx', SAFE_SERVER] },
        { timeout: 120_000, profile: 'enterprise-strict' },
      );
      expect(result.decision).toBe('pass');
      expect(result.blockers).toHaveLength(0);
      expect(
        result.suites.some((suite) => suite.name === 'Runtime Security'),
      ).toBe(true);
    },
  );
});
