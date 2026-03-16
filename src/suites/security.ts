import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { SuiteResult, SuiteContext, Finding, Severity } from '../types.js';
import { computeSuiteScore, extractToolText, withTimeout } from '../utils.js';

interface Pattern {
  pattern: RegExp;
  severity: Severity;
  label: string;
}

// -- Pattern definitions --

const HIDDEN_INSTRUCTION_PATTERNS: Pattern[] = [
  // XML-like injection tags
  { pattern: /<IMPORTANT>/i, severity: 'critical', label: '<IMPORTANT> tag' },
  { pattern: /<system>/i, severity: 'critical', label: '<system> tag' },
  { pattern: /<instructions?>/i, severity: 'critical', label: '<instruction> tag' },
  { pattern: /<hidden>/i, severity: 'critical', label: '<hidden> tag' },
  { pattern: /<secret>/i, severity: 'critical', label: '<secret> tag' },
  // LLM manipulation directives
  {
    pattern: /ignore\s+(previous|above|all|prior|other)\s+(instructions?|context|rules)/i,
    severity: 'critical',
    label: 'Instruction override attempt',
  },
  {
    pattern: /disregard\s+(previous|above|all|prior|other)/i,
    severity: 'critical',
    label: 'Disregard directive',
  },
  {
    pattern: /override\s+(previous|default|existing)/i,
    severity: 'critical',
    label: 'Override directive',
  },
  {
    pattern: /\bdo\s+not\s+(tell|reveal|show|mention|display)\b/i,
    severity: 'critical',
    label: 'Concealment directive',
  },
  {
    pattern: /\bkeep\s+(this|it)\s+(secret|hidden|private|confidential)\b/i,
    severity: 'critical',
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
    severity: 'critical',
    label: 'Zero-width characters',
  },
  {
    pattern: /[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]/,
    severity: 'critical',
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

function scanPatterns(
  tools: ToolLike[],
  patterns: Pattern[],
  idPrefix: string,
  category: string,
): Finding[] {
  const findings: Finding[] = [];
  let counter = 0;
  for (const tool of tools) {
    const texts = extractToolText(tool);
    for (const text of texts) {
      for (const { pattern, severity, label } of patterns) {
        if (pattern.test(text)) {
          counter++;
          findings.push({
            id: `${idPrefix}-${String(counter).padStart(3, '0')}`,
            title: label,
            severity,
            category,
            description: `Tool "${tool.name}": ${label}`,
            evidence: `Matched pattern in tool text`,
            source: tool.name,
          });
        }
      }
    }
  }
  return findings;
}

// -- Suite --

export async function securitySuite(
  client: Client,
  ctx: SuiteContext,
): Promise<SuiteResult> {
  const findings: Finding[] = [];
  const start = performance.now();

  // Get tools to scan
  let tools: ToolLike[] = [];
  const caps = client.getServerCapabilities();
  if (caps?.tools) {
    try {
      const result = await withTimeout(client.listTools(), ctx.timeout, 'tools/list (security)');
      tools = result.tools as ToolLike[];
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      findings.push({
        id: 'SEC-ERR-001',
        title: 'Failed to list tools for security scan',
        severity: 'high',
        category: 'security',
        description: `Could not retrieve tools for scanning: ${msg}`,
        evidence: msg,
      });
      const durationMs = Math.round(performance.now() - start);
      return {
        name: 'Security',
        findings,
        score: computeSuiteScore(findings),
        certificationBlockers: [],
        evidence: { artifacts: [], durationMs },
      };
    }
  }

  if (tools.length === 0) {
    findings.push({
      id: 'SEC-SKIP-001',
      title: 'No tools to scan',
      severity: 'info',
      category: 'security',
      description: 'Server exposes no tools; security scan skipped',
    });
    const durationMs = Math.round(performance.now() - start);
    return {
      name: 'Security',
      findings,
      score: computeSuiteScore(findings),
      certificationBlockers: [],
      evidence: { artifacts: [], durationMs },
    };
  }

  // 1. Hidden instructions (critical severity)
  const injectFindings = scanPatterns(tools, HIDDEN_INSTRUCTION_PATTERNS, 'SEC-INJECT', 'security');
  if (injectFindings.length > 0) {
    findings.push(...injectFindings);
  } else {
    findings.push({
      id: 'SEC-INJECT-000',
      title: 'Hidden instruction scan clean',
      severity: 'info',
      category: 'security',
      description: 'No hidden instruction patterns detected in tool descriptions',
    });
  }

  // 2. Data exfiltration patterns (high severity)
  const exfilFindings = scanPatterns(tools, EXFILTRATION_PATTERNS, 'SEC-EXFIL', 'security');
  if (exfilFindings.length > 0) {
    findings.push(...exfilFindings);
  } else {
    findings.push({
      id: 'SEC-EXFIL-000',
      title: 'Data exfiltration scan clean',
      severity: 'info',
      category: 'security',
      description: 'No data exfiltration patterns detected',
    });
  }

  // 3. Unicode/invisible characters (critical severity)
  const unicodeFindings = scanPatterns(tools, UNICODE_PATTERNS, 'SEC-UNICODE', 'security');
  if (unicodeFindings.length > 0) {
    findings.push(...unicodeFindings);
  } else {
    findings.push({
      id: 'SEC-UNICODE-000',
      title: 'Invisible character scan clean',
      severity: 'info',
      category: 'security',
      description: 'No invisible or bidirectional characters detected',
    });
  }

  // 4. Dangerous tool names
  {
    let counter = 0;
    for (const tool of tools) {
      for (const { pattern, label } of DANGEROUS_TOOL_NAMES) {
        if (pattern.test(tool.name)) {
          counter++;
          findings.push({
            id: `SEC-NAME-${String(counter).padStart(3, '0')}`,
            title: `Dangerous tool name: ${tool.name}`,
            severity: 'medium',
            category: 'security',
            description: `Tool "${tool.name}" matches dangerous pattern: ${label}`,
            source: tool.name,
            remediation: 'Rename tool to be more specific about its functionality',
          });
        }
      }
    }
    if (counter === 0) {
      findings.push({
        id: 'SEC-NAME-000',
        title: 'Tool name check clean',
        severity: 'info',
        category: 'security',
        description: 'No dangerous tool names detected',
      });
    }
  }

  // 5. Input schema presence
  {
    const missing = tools.filter((t) => !t.inputSchema);
    if (missing.length === 0) {
      findings.push({
        id: 'SEC-SCHEMA-000',
        title: 'All tools have input schemas',
        severity: 'info',
        category: 'security',
        description: 'Every tool declares an input schema',
      });
    } else {
      for (let i = 0; i < missing.length; i++) {
        findings.push({
          id: `SEC-SCHEMA-${String(i + 1).padStart(3, '0')}`,
          title: `Missing input schema: ${missing[i].name}`,
          severity: 'medium',
          category: 'security',
          description: `Tool "${missing[i].name}" has no input schema, allowing arbitrary input`,
          source: missing[i].name,
          remediation: 'Add an inputSchema with type "object" to define expected parameters',
        });
      }
    }
  }

  // 6. Description length anomaly (very long descriptions can hide instructions)
  {
    const suspicious = tools.filter(
      (t) => t.description && t.description.length > 500,
    );
    if (suspicious.length === 0) {
      findings.push({
        id: 'SEC-DESC-000',
        title: 'Description length check clean',
        severity: 'info',
        category: 'security',
        description: 'No abnormally long tool descriptions detected',
      });
    } else {
      for (let i = 0; i < suspicious.length; i++) {
        const len = suspicious[i].description?.length ?? 0;
        findings.push({
          id: `SEC-DESC-${String(i + 1).padStart(3, '0')}`,
          title: `Long description: ${suspicious[i].name}`,
          severity: 'low',
          category: 'security',
          description: `Tool "${suspicious[i].name}" has a ${len}-char description that may hide instructions`,
          source: suspicious[i].name,
          evidence: `Description length: ${len} characters`,
        });
      }
    }
  }

  // 7. Cross-tool reference detection (tool shadowing indicator)
  {
    const toolNames = new Set(tools.map((t) => t.name.toLowerCase()));
    let counter = 0;
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
            counter++;
            findings.push({
              id: `SEC-XREF-${String(counter).padStart(3, '0')}`,
              title: `Cross-tool reference in ${tool.name}`,
              severity: 'low',
              category: 'security',
              description: `Tool "${tool.name}" references tool "${otherName}" in its description`,
              source: tool.name,
              remediation: 'Avoid referencing other tools in descriptions to prevent shadowing',
            });
          }
        }
      }
    }
    if (counter === 0) {
      findings.push({
        id: 'SEC-XREF-000',
        title: 'Cross-tool reference check clean',
        severity: 'info',
        category: 'security',
        description: 'No cross-tool references detected in descriptions',
      });
    }
  }

  const durationMs = Math.round(performance.now() - start);

  return {
    name: 'Security',
    findings,
    score: computeSuiteScore(findings),
    certificationBlockers: [],
    evidence: { artifacts: [], durationMs },
  };
}
