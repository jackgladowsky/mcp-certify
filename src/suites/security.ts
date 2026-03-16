import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { SuiteResult, SuiteContext, TestResult } from '../types.js';
import { computeSuiteScore, extractToolText } from '../utils.js';

interface Pattern {
  pattern: RegExp;
  severity: 'high' | 'medium';
  label: string;
}

interface Finding {
  tool: string;
  label: string;
  severity: 'high' | 'medium';
}

// -- Pattern definitions --

const HIDDEN_INSTRUCTION_PATTERNS: Pattern[] = [
  // XML-like injection tags
  { pattern: /<IMPORTANT>/i, severity: 'high', label: '<IMPORTANT> tag' },
  { pattern: /<system>/i, severity: 'high', label: '<system> tag' },
  { pattern: /<instructions?>/i, severity: 'high', label: '<instruction> tag' },
  { pattern: /<hidden>/i, severity: 'high', label: '<hidden> tag' },
  { pattern: /<secret>/i, severity: 'high', label: '<secret> tag' },
  // LLM manipulation directives
  {
    pattern: /ignore\s+(previous|above|all|prior|other)\s+(instructions?|context|rules)/i,
    severity: 'high',
    label: 'Instruction override attempt',
  },
  {
    pattern: /disregard\s+(previous|above|all|prior|other)/i,
    severity: 'high',
    label: 'Disregard directive',
  },
  {
    pattern: /override\s+(previous|default|existing)/i,
    severity: 'high',
    label: 'Override directive',
  },
  {
    pattern: /\bdo\s+not\s+(tell|reveal|show|mention|display)\b/i,
    severity: 'high',
    label: 'Concealment directive',
  },
  {
    pattern: /\bkeep\s+(this|it)\s+(secret|hidden|private|confidential)\b/i,
    severity: 'high',
    label: 'Secrecy directive',
  },
  {
    pattern: /\byou\s+(must|should|have\s+to|need\s+to)\s+(always|never)\b/i,
    severity: 'medium',
    label: 'Behavioral directive',
  },
];

const EXFILTRATION_PATTERNS: Pattern[] = [
  { pattern: /~\/\.ssh/i, severity: 'high', label: 'References SSH directory' },
  { pattern: /~\/\.aws/i, severity: 'high', label: 'References AWS credentials' },
  { pattern: /~\/\.gnupg/i, severity: 'high', label: 'References GPG directory' },
  { pattern: /\/etc\/passwd/i, severity: 'high', label: 'References /etc/passwd' },
  { pattern: /\/etc\/shadow/i, severity: 'high', label: 'References /etc/shadow' },
  { pattern: /\.env\b/, severity: 'medium', label: 'References .env file' },
  {
    pattern: /\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\b/i,
    severity: 'medium',
    label: 'References credential values',
  },
  {
    pattern: /https?:\/\/(?!example\.com|localhost|127\.0\.0\.1)[^\s"')]+/i,
    severity: 'medium',
    label: 'Contains external URL',
  },
];

const UNICODE_PATTERNS: Pattern[] = [
  {
    pattern: /[\u200B\u200C\u200D\u2060\uFEFF]/,
    severity: 'high',
    label: 'Zero-width characters',
  },
  {
    pattern: /[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]/,
    severity: 'high',
    label: 'Bidirectional text override',
  },
];

const DANGEROUS_TOOL_NAMES: { pattern: RegExp; label: string }[] = [
  { pattern: /^(exec(ute)?|eval|run[_-]?(command|shell|bash|script))$/i, label: 'Command execution' },
  { pattern: /^(shell|bash|sh|cmd|powershell|terminal)$/i, label: 'Shell access' },
  { pattern: /^(sudo|admin|root|escalate|elevate)$/i, label: 'Privilege escalation' },
];

// -- Scan functions --

interface ToolLike {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

function scanPatterns(tools: ToolLike[], patterns: Pattern[]): Finding[] {
  const findings: Finding[] = [];
  for (const tool of tools) {
    const texts = extractToolText(tool);
    for (const text of texts) {
      for (const { pattern, severity, label } of patterns) {
        if (pattern.test(text)) {
          findings.push({ tool: tool.name, label, severity });
        }
      }
    }
  }
  return findings;
}

function findingsToResult(name: string, findings: Finding[]): TestResult {
  if (findings.length === 0) {
    return { name, status: 'pass' };
  }
  const hasHigh = findings.some((f) => f.severity === 'high');
  return {
    name,
    status: hasHigh ? 'fail' : 'warn',
    message: `${findings.length} finding(s)`,
    details: findings.map((f) => `[${f.severity}] ${f.tool}: ${f.label}`).join('\n'),
  };
}

// -- Suite --

export async function securitySuite(
  client: Client,
  _ctx: SuiteContext,
): Promise<SuiteResult> {
  const tests: TestResult[] = [];

  // Get tools to scan
  let tools: ToolLike[] = [];
  const caps = client.getServerCapabilities();
  if (caps?.tools) {
    try {
      const result = await client.listTools();
      tools = result.tools as ToolLike[];
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        name: 'Security',
        tests: [{ name: 'List tools for scanning', status: 'error', message: msg }],
        score: 0,
      };
    }
  }

  if (tools.length === 0) {
    return {
      name: 'Security',
      tests: [{ name: 'No tools to scan', status: 'skip', message: 'Server has no tools' }],
      score: 100,
    };
  }

  // 1. Hidden instructions
  tests.push(
    findingsToResult(
      'Hidden instruction scan',
      scanPatterns(tools, HIDDEN_INSTRUCTION_PATTERNS),
    ),
  );

  // 2. Data exfiltration patterns
  tests.push(
    findingsToResult(
      'Data exfiltration patterns',
      scanPatterns(tools, EXFILTRATION_PATTERNS),
    ),
  );

  // 3. Unicode/invisible characters
  tests.push(
    findingsToResult(
      'Invisible character detection',
      scanPatterns(tools, UNICODE_PATTERNS),
    ),
  );

  // 4. Dangerous tool names
  {
    const findings: Finding[] = [];
    for (const tool of tools) {
      for (const { pattern, label } of DANGEROUS_TOOL_NAMES) {
        if (pattern.test(tool.name)) {
          findings.push({ tool: tool.name, label, severity: 'medium' });
        }
      }
    }
    tests.push(findingsToResult('Dangerous tool names', findings));
  }

  // 5. Input schema presence
  {
    const missing = tools.filter((t) => !t.inputSchema);
    if (missing.length === 0) {
      tests.push({ name: 'All tools have input schemas', status: 'pass' });
    } else {
      tests.push({
        name: 'Input schema presence',
        status: 'warn',
        message: `${missing.length} tool(s) missing input schema`,
        details: missing.map((t) => t.name).join(', '),
      });
    }
  }

  // 6. Description length anomaly (very long descriptions can hide instructions)
  {
    const suspicious = tools.filter(
      (t) => t.description && t.description.length > 500,
    );
    if (suspicious.length === 0) {
      tests.push({ name: 'Description length check', status: 'pass' });
    } else {
      const hasVeryLong = suspicious.some(
        (t) => t.description && t.description.length > 1000,
      );
      tests.push({
        name: 'Description length check',
        status: hasVeryLong ? 'warn' : 'pass',
        message: hasVeryLong
          ? `${suspicious.length} tool(s) with very long descriptions`
          : `${suspicious.length} tool(s) with long descriptions (>500 chars)`,
        details: suspicious
          .map((t) => `${t.name}: ${t.description?.length} chars`)
          .join(', '),
      });
    }
  }

  // 7. Cross-tool reference detection (tool shadowing indicator)
  {
    const toolNames = new Set(tools.map((t) => t.name.toLowerCase()));
    const findings: Finding[] = [];
    for (const tool of tools) {
      const texts = extractToolText(tool);
      for (const text of texts) {
        const lower = text.toLowerCase();
        for (const otherName of toolNames) {
          if (
            otherName !== tool.name.toLowerCase() &&
            otherName.length > 3 &&
            lower.includes(otherName)
          ) {
            findings.push({
              tool: tool.name,
              label: `References tool "${otherName}" in description`,
              severity: 'medium',
            });
          }
        }
      }
    }
    tests.push(findingsToResult('Cross-tool reference check', findings));
  }

  return {
    name: 'Security',
    tests,
    score: computeSuiteScore(tests),
  };
}
