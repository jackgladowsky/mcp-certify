import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { Finding } from '../../types/findings.js';
import type { CanaryFile } from '../canaries.js';
import { checkCanaryAccess, checkCanaryLeaks } from '../canaries.js';
import type { Scenario, ScenarioResult } from './types.js';

/**
 * Extracts text from CallTool result content items.
 */
function extractContentText(
  content: Array<{ type: string; text?: string }>,
): string {
  return content
    .filter((c): c is { type: 'text'; text: string } => c.type === 'text' && typeof c.text === 'string')
    .map((c) => c.text)
    .join('\n');
}

/**
 * Secret Exfiltration Scenario
 *
 * Tests whether an MCP server attempts to access sensitive files that were
 * seeded as canary traps in the sandboxed HOME directory.
 *
 * - Calls each available tool with benign inputs
 * - After execution, checks if any canary files were accessed (via atime)
 * - Scans tool outputs for canary tokens (data exfiltration via output)
 */
export const secretExfilScenario: Scenario = {
  id: 'RUNTIME-EXFIL-001',
  name: 'Secret File Exfiltration',
  description:
    'Detects if the MCP server reads sensitive credential files (SSH keys, AWS creds, .env) from the user HOME directory',
  category: 'runtime-exfil',

  async run(
    client: Client,
    homeDir: string,
    canaries: CanaryFile[],
  ): Promise<ScenarioResult> {
    const findings: Finding[] = [];
    const evidenceLines: string[] = [];
    let allOutputText = '';

    // Discover tools
    const caps = client.getServerCapabilities();
    if (!caps?.tools) {
      return {
        passed: true,
        findings: [],
        evidence: 'Server declares no tools capability; skipping exfil check.',
      };
    }

    let tools: Array<{ name: string; inputSchema?: { type: string; properties?: Record<string, unknown> } }> = [];
    try {
      const result = await client.listTools();
      tools = result.tools;
    } catch {
      return {
        passed: true,
        findings: [],
        evidence: 'Could not list tools; skipping exfil check.',
      };
    }

    // Call each tool with empty / minimal arguments to trigger any startup behavior
    for (const tool of tools.slice(0, 10)) {
      try {
        const result = await client.callTool(
          { name: tool.name, arguments: {} },
        );
        if ('content' in result && Array.isArray(result.content)) {
          const text = extractContentText(
            result.content as Array<{ type: string; text?: string }>,
          );
          allOutputText += text + '\n';
        }
      } catch {
        // Tool errors are expected with empty args -- we just want to trigger behavior
      }
    }

    // Check 1: Were any canary files accessed?
    const accessed = await checkCanaryAccess(homeDir, canaries);
    if (accessed.length > 0) {
      const detail = accessed.join(', ');
      evidenceLines.push(`Canary files accessed: ${detail}`);
      findings.push({
        id: 'RUNTIME-EXFIL-001',
        title: 'Server accessed sensitive credential files',
        severity: 'critical',
        category: 'runtime-exfil',
        description: `The MCP server read the following sensitive files during tool execution: ${detail}`,
        evidence: detail,
        remediation:
          'The server should not access user credential files. Remove file system access to ~/.ssh, ~/.aws, ~/.gnupg, and similar directories.',
      });
    }

    // Check 2: Did any canary tokens appear in tool outputs?
    const leaked = checkCanaryLeaks(allOutputText, canaries);
    if (leaked.length > 0) {
      evidenceLines.push(
        `Canary tokens found in tool output: ${leaked.length} token(s)`,
      );
      findings.push({
        id: 'RUNTIME-EXFIL-001',
        title: 'Server leaked canary credential data in tool output',
        severity: 'critical',
        category: 'runtime-exfil',
        description: `Canary tokens planted in sensitive files were found in tool output, indicating the server read and returned credential data. Tokens leaked: ${leaked.length}`,
        evidence: leaked.map((t) => t.slice(0, 20) + '...').join(', '),
        remediation:
          'The server must not read or return user credential file contents.',
      });
    }

    if (findings.length === 0) {
      evidenceLines.push(
        'No canary files were accessed and no tokens were leaked.',
      );
    }

    return {
      passed: findings.length === 0,
      findings,
      evidence: evidenceLines.join('\n'),
    };
  },
};
