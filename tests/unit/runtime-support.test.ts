import { afterEach, describe, expect, it } from 'vitest';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  assessRuntimeSupport,
  resolveRuntimeTarget,
} from '../../src/runtime/support.js';

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe('runtime support', () => {
  it('unwraps package-manager launchers when the underlying command is installed locally', () => {
    const cwd = mkdtempSync(join(tmpdir(), 'mcp-certify-runtime-'));
    tempDirs.push(cwd);

    const binDir = join(cwd, 'node_modules', '.bin');
    mkdirSync(binDir, { recursive: true });
    const runnerPath = join(binDir, 'fake-runner');
    writeFileSync(runnerPath, '#!/bin/sh\nexit 0\n', 'utf-8');
    chmodSync(runnerPath, 0o755);

    const target = {
      command: 'npx',
      args: ['fake-runner', './server.js'],
    };

    const resolved = resolveRuntimeTarget(target, cwd);
    expect(resolved?.command).toBe(runnerPath);
    expect(resolved?.args).toEqual(['./server.js']);

    const support = assessRuntimeSupport(target, cwd);
    expect(support.status).toBe('supported');
    expect(support.detail).toContain('underlying command directly');
  });

  it('keeps unsupported launcher status when the wrapped command cannot be resolved', () => {
    const cwd = mkdtempSync(join(tmpdir(), 'mcp-certify-runtime-'));
    tempDirs.push(cwd);

    const target = {
      command: 'npx',
      args: ['missing-runner', './server.js'],
    };

    expect(resolveRuntimeTarget(target, cwd)).toBeUndefined();
    expect(assessRuntimeSupport(target, cwd).status).toBe(
      'unsupported_launcher',
    );
  });
});
