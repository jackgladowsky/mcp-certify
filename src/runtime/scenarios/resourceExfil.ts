import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { Finding } from '../../types/findings.js';
import type { CanaryFile } from '../canaries.js';
import { checkCanaryLeaks } from '../canaries.js';
import type { Scenario, ScenarioResult } from './types.js';

const SOFT_DATA_PATTERNS: Array<{ label: string; pattern: RegExp }> = [
  {
    label: 'Email address',
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
  },
  {
    label: 'US phone number',
    pattern: /\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/,
  },
];

const SENSITIVE_DATA_PATTERNS: Array<{ label: string; pattern: RegExp }> = [
  {
    label: 'SSN-like pattern',
    pattern: /\b\d{3}-\d{2}-\d{4}\b/,
  },
  {
    label: 'Credit card number',
    pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/,
  },
  {
    label: 'AWS access key',
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
  },
  {
    label: 'Private key header',
    pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/,
  },
];

/**
 * Resource Exfiltration Scenario
 *
 * Reads all declared MCP resources and checks:
 * 1. Whether resource content contains any canary tokens (credential leak)
 * 2. Whether resource content contains PII patterns
 */
export const resourceExfilScenario: Scenario = {
  id: 'RUNTIME-RESEXFIL-001',
  name: 'Resource Data Exfiltration',
  description:
    'Checks if server resources expose sensitive data, canary tokens, or PII',
  category: 'runtime-resexfil',

  async run(
    client: Client,
    _homeDir: string,
    canaries: CanaryFile[],
  ): Promise<ScenarioResult> {
    const findings: Finding[] = [];
    const evidenceLines: string[] = [];

    const caps = client.getServerCapabilities();
    if (!caps?.resources) {
      return {
        passed: true,
        findings: [],
        evidence:
          'Server declares no resources capability; skipping resource exfil check.',
      };
    }

    // List available resources
    let resources: Array<{ uri: string; name: string }> = [];
    try {
      const result = await client.listResources();
      resources = result.resources;
    } catch {
      return {
        passed: true,
        findings: [],
        evidence: 'Could not list resources; skipping resource exfil check.',
      };
    }

    if (resources.length === 0) {
      return {
        passed: true,
        findings: [],
        evidence: 'No resources declared; skipping resource exfil check.',
      };
    }

    evidenceLines.push(`Found ${resources.length} resource(s) to inspect.`);

    // Read each resource
    for (const resource of resources.slice(0, 20)) {
      let contentText = '';

      try {
        const result = await client.readResource({ uri: resource.uri });
        if (result.contents && Array.isArray(result.contents)) {
          for (const item of result.contents) {
            if ('text' in item && typeof item.text === 'string') {
              contentText += item.text + '\n';
            }
            if ('blob' in item && typeof item.blob === 'string') {
              // Try to decode base64 blob to check for text content
              try {
                const decoded = Buffer.from(item.blob, 'base64').toString(
                  'utf-8',
                );
                contentText += decoded + '\n';
              } catch {
                // Binary blob -- skip text analysis
              }
            }
          }
        }
      } catch {
        evidenceLines.push(`Could not read resource: ${resource.uri}`);
        continue;
      }

      if (!contentText) continue;

      // Check for canary token leaks
      const leaked = checkCanaryLeaks(contentText, canaries);
      if (leaked.length > 0) {
        findings.push({
          id: 'RUNTIME-RESEXFIL-001',
          title: `Resource "${resource.name}" contains canary credential data`,
          severity: 'critical',
          category: 'runtime-resexfil',
          description: `The resource "${resource.uri}" contains ${leaked.length} canary token(s) from seeded credential files, indicating the server is exposing user secrets through its resource interface.`,
          evidence: `Resource: ${resource.uri}, tokens: ${leaked.length}`,
          remediation:
            'Resources must not expose user credential files. Ensure resources only return data the server is authorized to share.',
        });
      }

      // Check for PII patterns
      const softMatches: string[] = [];
      for (const { label, pattern } of SOFT_DATA_PATTERNS) {
        if (pattern.test(contentText)) {
          softMatches.push(label);
        }
      }

      const sensitiveMatches: string[] = [];
      for (const { label, pattern } of SENSITIVE_DATA_PATTERNS) {
        if (pattern.test(contentText)) {
          sensitiveMatches.push(label);
        }
      }

      if (sensitiveMatches.length > 0) {
        findings.push({
          id: 'RUNTIME-RESEXFIL-001',
          title: `Resource "${resource.name}" contains sensitive data patterns`,
          severity: 'high',
          category: 'runtime-resexfil',
          description: `The resource "${resource.uri}" contains patterns matching: ${sensitiveMatches.join(', ')}. This data may be unintentionally exposed.`,
          evidence: `Sensitive data types: ${sensitiveMatches.join(', ')}`,
          remediation:
            'Resources should sanitize or redact sensitive data patterns before returning content.',
        });
      }

      if (softMatches.length > 0) {
        findings.push({
          id: 'RUNTIME-RESEXFIL-001-SOFT',
          title: `Resource "${resource.name}" contains contact-style data`,
          severity: 'low',
          category: 'runtime-resexfil',
          description: `The resource "${resource.uri}" contains patterns matching: ${softMatches.join(', ')}. Review whether this data is expected to be public.`,
          evidence: `Soft data types: ${softMatches.join(', ')}`,
          remediation:
            'Confirm that resource content only exposes contact information that is intended to be shared.',
        });
      }
    }

    if (findings.length === 0) {
      evidenceLines.push(
        'No canary leaks or PII patterns detected in resources.',
      );
    } else {
      evidenceLines.push(
        `Found ${findings.length} issue(s) across resources.`,
      );
    }

    return {
      passed: findings.length === 0,
      findings,
      evidence: evidenceLines.join('\n'),
    };
  },
};
