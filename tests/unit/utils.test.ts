import { describe, it, expect } from 'vitest';
import { computeSuiteScore, extractToolText } from '../../src/utils.js';
import { withTimeout } from '../../src/utils/timeout.js';
import type { Finding } from '../../src/types/index.js';

function makeFinding(severity: Finding['severity']): Finding {
  return {
    id: 'TEST',
    title: 'test',
    severity,
    category: 'test',
    description: 'test',
  };
}

describe('computeSuiteScore', () => {
  it('returns 100 for no findings', () => {
    expect(computeSuiteScore([])).toBe(100);
  });

  it('deducts 40 for critical', () => {
    expect(computeSuiteScore([makeFinding('critical')])).toBe(60);
  });

  it('deducts 20 for high', () => {
    expect(computeSuiteScore([makeFinding('high')])).toBe(80);
  });

  it('deducts 10 for medium', () => {
    expect(computeSuiteScore([makeFinding('medium')])).toBe(90);
  });

  it('deducts 5 for low', () => {
    expect(computeSuiteScore([makeFinding('low')])).toBe(95);
  });

  it('deducts 0 for info', () => {
    expect(computeSuiteScore([makeFinding('info')])).toBe(100);
  });

  it('floors at 0', () => {
    const findings = Array(5).fill(null).map(() => makeFinding('critical'));
    expect(computeSuiteScore(findings)).toBe(0);
  });

  it('sums deductions from mixed severities', () => {
    const findings = [makeFinding('critical'), makeFinding('high'), makeFinding('medium')];
    // 40 + 20 + 10 = 70 deducted
    expect(computeSuiteScore(findings)).toBe(30);
  });
});

describe('extractToolText', () => {
  it('returns description', () => {
    const texts = extractToolText({ name: 'foo', description: 'hello' });
    expect(texts).toContain('hello');
  });

  it('returns empty for tool with no description', () => {
    const texts = extractToolText({ name: 'foo' });
    expect(texts).toHaveLength(0);
  });

  it('extracts nested schema property descriptions', () => {
    const texts = extractToolText({
      name: 'foo',
      inputSchema: {
        type: 'object',
        properties: {
          bar: { type: 'string', description: 'nested desc' },
        },
      },
    });
    expect(texts).toContain('nested desc');
  });
});

describe('withTimeout', () => {
  it('resolves when promise finishes before timeout', async () => {
    const result = await withTimeout(Promise.resolve(42), 1000, 'test');
    expect(result).toBe(42);
  });

  it('rejects with timeout message when promise is too slow', async () => {
    const slow = new Promise((resolve) => setTimeout(resolve, 5000));
    await expect(withTimeout(slow, 50, 'slow-op')).rejects.toThrow(
      'slow-op timed out after 50ms',
    );
  });

  it('rejects with original error if promise fails before timeout', async () => {
    const failing = Promise.reject(new Error('boom'));
    await expect(withTimeout(failing, 5000, 'test')).rejects.toThrow('boom');
  });
});
