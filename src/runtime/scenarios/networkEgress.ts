import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { Finding } from '../../types/findings.js';
import type { CanaryFile } from '../canaries.js';
import { checkCanaryLeaks } from '../canaries.js';
import type { CaptureSession } from '../networkCapture.js';
import { extractDestinations } from '../networkCapture.js';
import type { Scenario, ScenarioResult, ScenarioOptions } from './types.js';

/** Hosts that are generally safe / expected for a local MCP server. */
const DEFAULT_SAFE_HOSTS = new Set([
  'localhost',
  '127.0.0.1',
  '::1',
  '0.0.0.0',
]);

/**
 * Network Egress Scenario
 *
 * Tests whether the MCP server makes unauthorized outbound network requests
 * during normal tool execution.
 *
 * Uses the capture proxy to observe HTTP/HTTPS traffic and scans server
 * stdout/stderr for embedded URLs.
 */
export const networkEgressScenario: Scenario = {
  id: 'RUNTIME-NET-001',
  name: 'Unauthorized Network Egress',
  description:
    'Detects if the MCP server makes outbound network requests to non-approved hosts',
  category: 'runtime-network',

  async run(
    client: Client,
    _homeDir: string,
    canaries: CanaryFile[],
    capture?: CaptureSession,
    options?: ScenarioOptions,
  ): Promise<ScenarioResult> {
    const findings: Finding[] = [];
    const evidenceLines: string[] = [];

    // Discover and call tools
    const caps = client.getServerCapabilities();
    if (!caps?.tools) {
      return {
        passed: true,
        findings: [],
        evidence: 'Server declares no tools; skipping network egress check.',
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
        evidence: 'Could not list tools; skipping network egress check.',
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

    // Analyze captured network events
    const events = capture?.events ?? [];
    const destinations = extractDestinations(events, allOutputText);

    // Build safe host set from defaults + user-allowed hosts
    const safeHosts = new Set(DEFAULT_SAFE_HOSTS);
    if (options?.allowHosts) {
      for (const h of options.allowHosts) safeHosts.add(h);
    }

    // Filter to non-safe hosts
    const suspiciousHosts = destinations.filter((h) => !safeHosts.has(h));

    if (suspiciousHosts.length > 0) {
      const detail = suspiciousHosts.join(', ');
      evidenceLines.push(`Outbound connections to: ${detail}`);
      findings.push({
        id: 'RUNTIME-NET-001',
        title: 'Server made outbound network requests to external hosts',
        severity: 'high',
        category: 'runtime-network',
        description: `The MCP server contacted external hosts during tool execution: ${detail}. This could indicate data exfiltration or unauthorized API calls.`,
        evidence: detail,
        remediation:
          'MCP servers should not make outbound network requests unless explicitly required by the tool functionality. Declare network requirements and restrict egress to approved hosts.',
      });
    }

    // Check if any canary data was sent in request bodies
    if (events.length > 0) {
      const allBodies = events
        .map((e) => e.body ?? '')
        .filter((b) => b.length > 0)
        .join('\n');

      const leakedInNetwork = checkCanaryLeaks(allBodies, canaries);
      if (leakedInNetwork.length > 0) {
        evidenceLines.push(
          `Canary tokens found in outbound request bodies: ${leakedInNetwork.length}`,
        );
        findings.push({
          id: 'RUNTIME-NET-001',
          title: 'Server exfiltrated canary data over network',
          severity: 'critical',
          category: 'runtime-network',
          description: `Canary tokens from seeded credential files were found in outbound HTTP request bodies. This is strong evidence of data exfiltration.`,
          evidence: `${leakedInNetwork.length} canary token(s) found in request bodies`,
          remediation:
            'The server is transmitting user credentials over the network. This behavior must be eliminated.',
        });
      }
    }

    // Log capture stats
    evidenceLines.push(
      `Proxy captured ${events.length} network event(s), ${suspiciousHosts.length} suspicious host(s).`,
    );

    if (findings.length === 0) {
      evidenceLines.push('No unauthorized network egress detected.');
    }

    return {
      passed: findings.length === 0,
      findings,
      evidence: evidenceLines.join('\n'),
    };
  },
};
