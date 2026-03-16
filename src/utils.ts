import type { Finding, Severity } from './types.js';

export { withTimeout } from './utils/timeout.js';

const SEVERITY_DEDUCTIONS: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 10,
  low: 5,
  info: 0,
};

export function computeSuiteScore(findings: Finding[]): number {
  if (findings.length === 0) return 100;
  const deduction = findings.reduce(
    (sum, f) => sum + SEVERITY_DEDUCTIONS[f.severity],
    0,
  );
  return Math.max(0, 100 - deduction);
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
