import { describe, it, expect } from 'vitest';
import { run } from '../../src/runner.js';
import { resolve } from 'node:path';

const VULN_SERVER = resolve(import.meta.dirname, '../../fixtures/servers/vulnerable-server.ts');

describe('vulnerable server', () => {
  it('fails certification', async () => {
    const result = await run(
      { command: 'npx', args: ['tsx', VULN_SERVER] },
      { timeout: 20_000 },
    );
    expect(result.decision).toBe('fail');
    expect(result.blockers.length).toBeGreaterThan(0);
  });

  it('detects critical findings', async () => {
    const result = await run(
      { command: 'npx', args: ['tsx', VULN_SERVER] },
      { timeout: 20_000 },
    );
    const allFindings = result.suites.flatMap((s) => s.findings);
    const critical = allFindings.filter((f) => f.severity === 'critical');
    expect(critical.length).toBeGreaterThan(0);
  });

  it('catches <IMPORTANT> tag injection', async () => {
    const result = await run(
      { command: 'npx', args: ['tsx', VULN_SERVER] },
      { timeout: 20_000 },
    );
    const allFindings = result.suites.flatMap((s) => s.findings);
    const injection = allFindings.find(
      (f) => f.title.includes('<IMPORTANT>') && f.severity === 'critical',
    );
    expect(injection).toBeDefined();
  });

  it('catches zero-width character injection', async () => {
    const result = await run(
      { command: 'npx', args: ['tsx', VULN_SERVER] },
      { timeout: 20_000 },
    );
    const allFindings = result.suites.flatMap((s) => s.findings);
    const unicode = allFindings.find(
      (f) => f.title.includes('Zero-width') && f.severity === 'critical',
    );
    expect(unicode).toBeDefined();
  });

  it('catches dangerous tool name "execute"', async () => {
    const result = await run(
      { command: 'npx', args: ['tsx', VULN_SERVER] },
      { timeout: 20_000 },
    );
    const allFindings = result.suites.flatMap((s) => s.findings);
    const dangerous = allFindings.find(
      (f) => f.title.toLowerCase().includes('execute') && f.severity === 'medium',
    );
    expect(dangerous).toBeDefined();
  });

  it('catches SSH path exfiltration reference', async () => {
    const result = await run(
      { command: 'npx', args: ['tsx', VULN_SERVER] },
      { timeout: 20_000 },
    );
    const allFindings = result.suites.flatMap((s) => s.findings);
    const ssh = allFindings.find(
      (f) =>
        (f.title.toLowerCase().includes('ssh') ||
          f.description.toLowerCase().includes('ssh')) &&
        (f.severity === 'high' || f.severity === 'critical'),
    );
    expect(ssh).toBeDefined();
  });

  it('security suite scores 0', async () => {
    const result = await run(
      { command: 'npx', args: ['tsx', VULN_SERVER] },
      { timeout: 20_000 },
    );
    const security = result.suites.find((s) => s.name === 'Security');
    expect(security).toBeDefined();
    expect(security!.score).toBe(0);
  });

  it('protocol suite still passes (server is functional)', async () => {
    const result = await run(
      { command: 'npx', args: ['tsx', VULN_SERVER] },
      { timeout: 20_000 },
    );
    const protocol = result.suites.find((s) => s.name === 'Protocol');
    expect(protocol).toBeDefined();
    expect(protocol!.score).toBe(100);
  });
});
