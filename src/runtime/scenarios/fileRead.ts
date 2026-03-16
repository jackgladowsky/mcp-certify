import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { mkdir, writeFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { Finding } from '../../types/findings.js';
import type { CanaryFile } from '../canaries.js';
import type { Scenario, ScenarioResult } from './types.js';

interface OutOfScopeFile {
  path: string;
  token: string;
  seededAt: number;
}

/**
 * Unauthorized File Read Scenario
 *
 * Creates files outside the expected working directory and checks whether
 * the server accesses them during normal tool execution.
 */
export const fileReadScenario: Scenario = {
  id: 'RUNTIME-FILE-001',
  name: 'Unauthorized File Access',
  description:
    'Detects if the MCP server reads files outside its declared working scope',
  category: 'runtime-file',

  async run(
    client: Client,
    homeDir: string,
    _canaries: CanaryFile[],
  ): Promise<ScenarioResult> {
    const findings: Finding[] = [];
    const evidenceLines: string[] = [];

    // Plant out-of-scope files in various locations within the sandboxed HOME
    const oosFiles: OutOfScopeFile[] = [];
    const locations = [
      'Documents/private/financial.csv',
      'Desktop/passwords.txt',
      '.local/share/browser/cookies.db',
      '.bash_history',
      '.zsh_history',
    ];

    for (const relPath of locations) {
      const token = `CANARY-OOS-${randomUUID()}`;
      const fullPath = join(homeDir, relPath);
      await mkdir(join(fullPath, '..'), { recursive: true });
      await writeFile(fullPath, `Sensitive content: ${token}\n`, {
        mode: 0o600,
      });
      oosFiles.push({ path: relPath, token, seededAt: Date.now() });
    }

    // Discover and call tools
    const caps = client.getServerCapabilities();
    if (!caps?.tools) {
      return {
        passed: true,
        findings: [],
        evidence: 'Server declares no tools; skipping file-read check.',
      };
    }

    let tools: Array<{ name: string }> = [];
    try {
      const result = await client.listTools();
      tools = result.tools;
    } catch {
      return {
        passed: true,
        findings: [],
        evidence: 'Could not list tools; skipping file-read check.',
      };
    }

    let allOutputText = '';

    for (const tool of tools.slice(0, 10)) {
      try {
        const result = await client.callTool({
          name: tool.name,
          arguments: {},
        });
        if ('content' in result && Array.isArray(result.content)) {
          for (const item of result.content) {
            if (
              typeof item === 'object' &&
              item !== null &&
              'text' in item &&
              typeof (item as { text: unknown }).text === 'string'
            ) {
              allOutputText += (item as { text: string }).text + '\n';
            }
          }
        }
      } catch {
        // Expected with empty args
      }
    }

    // Check atime on out-of-scope files
    const accessedPaths: string[] = [];
    for (const oos of oosFiles) {
      const fullPath = join(homeDir, oos.path);
      try {
        const s = await stat(fullPath);
        if (s.atimeMs > oos.seededAt + 100) {
          accessedPaths.push(oos.path);
        }
      } catch {
        // File deleted -- suspicious
        accessedPaths.push(oos.path);
      }
    }

    if (accessedPaths.length > 0) {
      const detail = accessedPaths.join(', ');
      evidenceLines.push(`Out-of-scope files accessed: ${detail}`);
      findings.push({
        id: 'RUNTIME-FILE-001',
        title: 'Server accessed files outside expected scope',
        severity: 'high',
        category: 'runtime-file',
        description: `The MCP server accessed files outside its working directory: ${detail}`,
        evidence: detail,
        remediation:
          'Restrict file system access to only the directories the server needs. Avoid reading user documents, browser data, or shell history.',
      });
    }

    // Check if OOS tokens leaked in output
    const leakedTokens: string[] = [];
    for (const oos of oosFiles) {
      if (allOutputText.includes(oos.token)) {
        leakedTokens.push(oos.path);
      }
    }

    if (leakedTokens.length > 0) {
      const detail = leakedTokens.join(', ');
      evidenceLines.push(`Out-of-scope file contents leaked in output: ${detail}`);
      findings.push({
        id: 'RUNTIME-FILE-001',
        title: 'Server leaked out-of-scope file contents',
        severity: 'high',
        category: 'runtime-file',
        description: `Canary tokens from out-of-scope files appeared in tool output: ${detail}`,
        evidence: detail,
        remediation:
          'The server must not read or return contents of files outside its working directory.',
      });
    }

    if (findings.length === 0) {
      evidenceLines.push(
        'No out-of-scope file access detected.',
      );
    }

    return {
      passed: findings.length === 0,
      findings,
      evidence: evidenceLines.join('\n'),
    };
  },
};
