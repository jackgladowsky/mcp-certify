import type { TestResult, TestStatus, SuiteResult } from './types.js';

export async function runTest(
  name: string,
  fn: () => Promise<Partial<TestResult>>,
): Promise<TestResult> {
  const start = performance.now();
  try {
    const result = await fn();
    return {
      name,
      status: result.status ?? 'pass',
      message: result.message,
      details: result.details,
      duration: result.duration ?? Math.round(performance.now() - start),
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      name,
      status: 'error',
      message: msg,
      duration: Math.round(performance.now() - start),
    };
  }
}

export function computeSuiteScore(tests: TestResult[]): number {
  const scoreable = tests.filter((t) => t.status !== 'skip');
  if (scoreable.length === 0) return 100;
  const points = scoreable.reduce((sum, t) => {
    if (t.status === 'pass') return sum + 1;
    if (t.status === 'warn') return sum + 0.5;
    return sum;
  }, 0);
  return Math.round((points / scoreable.length) * 100);
}

export function extractToolText(tool: {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}): string[] {
  const texts: string[] = [];
  if (tool.description) texts.push(tool.description);

  // Walk inputSchema for nested descriptions
  if (tool.inputSchema) {
    walkSchema(tool.inputSchema, texts);
  }
  return texts;
}

function walkSchema(obj: Record<string, unknown>, texts: string[]): void {
  if (typeof obj !== 'object' || obj === null) return;
  if (typeof obj['description'] === 'string') {
    texts.push(obj['description'] as string);
  }
  if (typeof obj['properties'] === 'object' && obj['properties'] !== null) {
    for (const val of Object.values(obj['properties'] as Record<string, unknown>)) {
      if (typeof val === 'object' && val !== null) {
        walkSchema(val as Record<string, unknown>, texts);
      }
    }
  }
  if (typeof obj['items'] === 'object' && obj['items'] !== null) {
    walkSchema(obj['items'] as Record<string, unknown>, texts);
  }
}
