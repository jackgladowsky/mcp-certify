import { describe, expect, it } from 'vitest';
import { resolve } from 'node:path';
import { resolveScanPath } from '../../src/suites/supplyChain.js';

describe('resolveScanPath', () => {
  it('resolves wrapped local launch commands to the server project root', async () => {
    const serverPath = resolve(
      import.meta.dirname,
      '../../fixtures/servers/safe-server.ts',
    );

    const scanPath = await resolveScanPath(undefined, 'npx', [
      'tsx',
      serverPath,
    ]);

    expect(scanPath).toBe(
      resolve(import.meta.dirname, '../../fixtures/servers'),
    );
  });

  it('resolves direct launch command to server project root', async () => {
    const serverPath = resolve(
      import.meta.dirname,
      '../../fixtures/servers/safe-server.ts',
    );

    const scanPath = await resolveScanPath(undefined, 'node', [serverPath]);

    expect(scanPath).toBe(
      resolve(import.meta.dirname, '../../fixtures/servers'),
    );
  });

  it('resolves explicit file paths to the containing project root', async () => {
    const serverPath = resolve(
      import.meta.dirname,
      '../../fixtures/servers/auth-required-server.ts',
    );

    const scanPath = await resolveScanPath(serverPath);

    expect(scanPath).toBe(
      resolve(import.meta.dirname, '../../fixtures/servers'),
    );
  });
});
