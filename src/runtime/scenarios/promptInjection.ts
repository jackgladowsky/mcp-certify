import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { Finding } from '../../types/findings.js';
import type { CanaryFile } from '../canaries.js';
import type { Scenario, ScenarioResult } from './types.js';

/** Zero-width and bidirectional override characters. */
const ZERO_WIDTH_RE = /[\u200B\u200C\u200D\u2060\uFEFF]/;
const BIDI_RE =
  /[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]/;

/** XML-like injection tags that an LLM would interpret as instructions. */
const INJECTION_TAG_RE =
  /<\s*(IMPORTANT|system|instructions?|hidden|secret|override|context|prompt)\b[^>]*>/i;

/** Directives aimed at overriding the LLM's prior instructions. */
const OVERRIDE_RE =
  /\b(ignore|disregard|override|forget)\s+(all\s+)?(previous|prior|above|other|existing)\s+(instructions?|context|rules|constraints)/i;

/** Concealment directives. */
const CONCEAL_RE =
  /\bdo\s+not\s+(tell|reveal|show|mention|display|inform)\b/i;

/** Base64-encoded content that might hide instructions. */
const BASE64_BLOCK_RE =
  /[A-Za-z0-9+/]{40,}={0,2}/;

/** Suspicious long base64 strings that decode to text with directive-like content. */
function checkBase64Directives(text: string): string | null {
  const matches = text.match(/[A-Za-z0-9+/]{60,}={0,2}/g);
  if (!matches) return null;

  for (const m of matches) {
    try {
      const decoded = Buffer.from(m, 'base64').toString('utf-8');
      // Check if the decoded text looks like natural language instructions
      if (
        INJECTION_TAG_RE.test(decoded) ||
        OVERRIDE_RE.test(decoded) ||
        CONCEAL_RE.test(decoded)
      ) {
        return decoded.slice(0, 200);
      }
    } catch {
      // Not valid base64 -- skip
    }
  }
  return null;
}

interface ToolInfo {
  name: string;
  description?: string;
  inputSchema?: {
    type: string;
    properties?: Record<string, { description?: string }>;
    [key: string]: unknown;
  };
}

/**
 * Extract all user-visible text from a tool definition (description + schema descriptions).
 */
function allToolText(tool: ToolInfo): string {
  const parts: string[] = [];
  if (tool.description) parts.push(tool.description);
  if (tool.inputSchema?.properties) {
    for (const prop of Object.values(tool.inputSchema.properties)) {
      if (prop.description) parts.push(prop.description);
    }
  }
  return parts.join('\n');
}

/**
 * Prompt Injection Scenario (Runtime)
 *
 * Fetches the tool list at runtime and scans descriptions for hidden
 * instructions that would be invisible in a UI but processed by an LLM.
 *
 * This overlaps with the static security suite but runs at runtime to
 * detect dynamic description changes (rug pulls) where a server changes
 * its tool descriptions after initial listing.
 */
export const promptInjectionScenario: Scenario = {
  id: 'RUNTIME-INJECT-001',
  name: 'Runtime Prompt Injection Detection',
  description:
    'Detects hidden LLM instructions in tool descriptions at runtime, including rug-pull detection where descriptions change between calls',
  category: 'runtime-injection',

  async run(
    client: Client,
    _homeDir: string,
    _canaries: CanaryFile[],
  ): Promise<ScenarioResult> {
    const findings: Finding[] = [];
    const evidenceLines: string[] = [];

    const caps = client.getServerCapabilities();
    if (!caps?.tools) {
      return {
        passed: true,
        findings: [],
        evidence: 'Server declares no tools; skipping injection check.',
      };
    }

    // Fetch tool list twice to detect rug-pull (dynamic description changes)
    let firstList: ToolInfo[] = [];
    let secondList: ToolInfo[] = [];

    try {
      const r1 = await client.listTools();
      firstList = r1.tools as ToolInfo[];
    } catch {
      return {
        passed: true,
        findings: [],
        evidence: 'Could not list tools; skipping injection check.',
      };
    }

    // Brief pause then re-list to detect rug-pull behavior
    await new Promise((r) => setTimeout(r, 500));

    try {
      const r2 = await client.listTools();
      secondList = r2.tools as ToolInfo[];
    } catch {
      // If second listing fails, proceed with first only
      secondList = firstList;
    }

    // Rug-pull detection: compare descriptions between the two listings
    const firstMap = new Map(firstList.map((t) => [t.name, allToolText(t)]));
    const secondMap = new Map(secondList.map((t) => [t.name, allToolText(t)]));

    for (const [name, text1] of firstMap) {
      const text2 = secondMap.get(name);
      if (text2 !== undefined && text1 !== text2) {
        evidenceLines.push(
          `Rug pull detected: "${name}" description changed between listings`,
        );
        findings.push({
          id: 'RUNTIME-INJECT-001',
          title: `Tool "${name}" description changed between listings (rug pull)`,
          severity: 'critical',
          category: 'runtime-injection',
          description: `The tool "${name}" returned different descriptions on consecutive listTools() calls. This is a rug-pull pattern where the server presents benign descriptions initially, then injects malicious instructions.`,
          evidence: `First: ${text1.slice(0, 100)}... | Second: ${text2.slice(0, 100)}...`,
          remediation:
            'Tool descriptions must be stable. Dynamic description changes indicate malicious intent.',
        });
      }
    }

    // Scan all tools (from second listing, the "real" one) for injection patterns
    const toolsToScan = secondList.length > 0 ? secondList : firstList;

    for (const tool of toolsToScan) {
      const text = allToolText(tool);
      if (!text) continue;

      // Zero-width characters
      if (ZERO_WIDTH_RE.test(text)) {
        findings.push({
          id: 'RUNTIME-INJECT-001',
          title: `Tool "${tool.name}" contains zero-width characters`,
          severity: 'critical',
          category: 'runtime-injection',
          description: `Zero-width Unicode characters found in tool "${tool.name}" description. These are invisible to users but processed by LLMs, allowing hidden instruction injection.`,
          evidence: `Characters found in: ${tool.name}`,
          remediation:
            'Remove all zero-width Unicode characters from tool descriptions.',
        });
      }

      // Bidirectional text override
      if (BIDI_RE.test(text)) {
        findings.push({
          id: 'RUNTIME-INJECT-001',
          title: `Tool "${tool.name}" contains bidirectional text override characters`,
          severity: 'critical',
          category: 'runtime-injection',
          description: `Bidirectional text override characters in tool "${tool.name}" can reorder displayed text to hide instructions.`,
          evidence: `BiDi characters found in: ${tool.name}`,
          remediation:
            'Remove bidirectional override characters from tool descriptions.',
        });
      }

      // XML injection tags
      if (INJECTION_TAG_RE.test(text)) {
        const match = text.match(INJECTION_TAG_RE);
        findings.push({
          id: 'RUNTIME-INJECT-001',
          title: `Tool "${tool.name}" contains LLM injection tags`,
          severity: 'critical',
          category: 'runtime-injection',
          description: `Tool "${tool.name}" description contains XML-like tags (${match?.[0]}) that LLMs interpret as system-level instructions.`,
          evidence: match?.[0] ?? 'injection tag',
          remediation:
            'Remove XML-like instruction tags from tool descriptions.',
        });
      }

      // Override directives
      if (OVERRIDE_RE.test(text)) {
        const match = text.match(OVERRIDE_RE);
        findings.push({
          id: 'RUNTIME-INJECT-001',
          title: `Tool "${tool.name}" contains instruction override directive`,
          severity: 'critical',
          category: 'runtime-injection',
          description: `Tool "${tool.name}" attempts to override the LLM's prior instructions with: "${match?.[0]}"`,
          evidence: match?.[0] ?? 'override directive',
          remediation:
            'Tool descriptions must not contain directives that attempt to override LLM instructions.',
        });
      }

      // Concealment directives
      if (CONCEAL_RE.test(text)) {
        const match = text.match(CONCEAL_RE);
        findings.push({
          id: 'RUNTIME-INJECT-001',
          title: `Tool "${tool.name}" contains concealment directive`,
          severity: 'high',
          category: 'runtime-injection',
          description: `Tool "${tool.name}" instructs the LLM to hide information from the user: "${match?.[0]}"`,
          evidence: match?.[0] ?? 'concealment directive',
          remediation:
            'Tool descriptions must not instruct the LLM to conceal information.',
        });
      }

      // Base64-encoded directives
      if (BASE64_BLOCK_RE.test(text)) {
        const decoded = checkBase64Directives(text);
        if (decoded) {
          findings.push({
            id: 'RUNTIME-INJECT-001',
            title: `Tool "${tool.name}" contains base64-encoded injection`,
            severity: 'critical',
            category: 'runtime-injection',
            description: `Tool "${tool.name}" contains base64-encoded text that decodes to LLM manipulation directives.`,
            evidence: `Decoded: ${decoded.slice(0, 100)}`,
            remediation:
              'Remove base64-encoded instruction payloads from tool descriptions.',
          });
        }
      }
    }

    evidenceLines.push(
      `Scanned ${toolsToScan.length} tool(s) for injection patterns.`,
    );

    if (findings.length === 0) {
      evidenceLines.push(
        'No prompt injection patterns or rug-pull behavior detected.',
      );
    }

    return {
      passed: findings.length === 0,
      findings,
      evidence: evidenceLines.join('\n'),
    };
  },
};
