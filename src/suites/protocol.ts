import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { SuiteResult, SuiteContext, Finding } from '../types.js';
import { computeSuiteScore, withTimeout } from '../utils.js';

export async function protocolSuite(
  client: Client,
  ctx: SuiteContext,
): Promise<SuiteResult> {
  const findings: Finding[] = [];
  const start = performance.now();

  // 1. Initialize handshake (already succeeded if we're here)
  findings.push({
    id: 'PROTO-001',
    title: 'Initialize handshake',
    severity: 'info',
    category: 'protocol',
    description: `MCP handshake completed in ${ctx.connectDuration}ms`,
    evidence: `Connect duration: ${ctx.connectDuration}ms`,
  });

  // 2. Server info
  const info = client.getServerVersion();
  if (!info) {
    findings.push({
      id: 'PROTO-002',
      title: 'Server info missing',
      severity: 'medium',
      category: 'protocol',
      description: 'Server did not return version information during initialization',
      remediation: 'Return name and version in the server info response',
    });
  } else if (!info.name) {
    findings.push({
      id: 'PROTO-002',
      title: 'Server name missing',
      severity: 'medium',
      category: 'protocol',
      description: 'Server returned version info but name field is empty',
      remediation: 'Include a server name in the initialization response',
    });
  } else {
    findings.push({
      id: 'PROTO-002',
      title: 'Server info present',
      severity: 'info',
      category: 'protocol',
      description: `Server identified as ${info.name} v${info.version}`,
    });
  }

  // 3. Capabilities
  const caps = client.getServerCapabilities();
  if (!caps) {
    findings.push({
      id: 'PROTO-003',
      title: 'No capabilities declared',
      severity: 'high',
      category: 'protocol',
      description: 'Server did not declare any capabilities during initialization',
      remediation: 'Declare capabilities (tools, resources, prompts) in the server response',
    });
  } else {
    const declared = Object.keys(caps).filter(
      (k) => (caps as Record<string, unknown>)[k],
    );
    if (declared.length === 0) {
      findings.push({
        id: 'PROTO-003',
        title: 'Empty capabilities',
        severity: 'medium',
        category: 'protocol',
        description: 'Server declared capabilities object but all values are falsy',
        remediation: 'Enable at least one capability (tools, resources, or prompts)',
      });
    } else {
      findings.push({
        id: 'PROTO-003',
        title: 'Capabilities declared',
        severity: 'info',
        category: 'protocol',
        description: `Server declares: ${declared.join(', ')}`,
      });
    }
  }

  // 4. tools/list
  if (caps?.tools) {
    try {
      const { tools } = await withTimeout(client.listTools(), ctx.timeout, 'tools/list');
      if (!Array.isArray(tools)) {
        findings.push({
          id: 'PROTO-004',
          title: 'tools/list returns invalid response',
          severity: 'high',
          category: 'protocol',
          description: 'tools/list did not return an array for the tools field',
          remediation: 'Return { tools: [...] } from the tools/list handler',
        });
      } else {
        findings.push({
          id: 'PROTO-004',
          title: 'tools/list returns valid response',
          severity: 'info',
          category: 'protocol',
          description: `tools/list returned ${tools.length} tool(s)`,
        });
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      findings.push({
        id: 'PROTO-004',
        title: 'tools/list failed',
        severity: 'high',
        category: 'protocol',
        description: `tools/list call failed: ${msg}`,
        evidence: msg,
      });
    }
  }

  // 5. resources/list
  if (caps?.resources) {
    try {
      const { resources } = await withTimeout(client.listResources(), ctx.timeout, 'resources/list');
      if (!Array.isArray(resources)) {
        findings.push({
          id: 'PROTO-005',
          title: 'resources/list returns invalid response',
          severity: 'high',
          category: 'protocol',
          description: 'resources/list did not return an array for the resources field',
          remediation: 'Return { resources: [...] } from the resources/list handler',
        });
      } else {
        findings.push({
          id: 'PROTO-005',
          title: 'resources/list returns valid response',
          severity: 'info',
          category: 'protocol',
          description: `resources/list returned ${resources.length} resource(s)`,
        });
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      findings.push({
        id: 'PROTO-005',
        title: 'resources/list failed',
        severity: 'high',
        category: 'protocol',
        description: `resources/list call failed: ${msg}`,
        evidence: msg,
      });
    }
  }

  // 6. prompts/list
  if (caps?.prompts) {
    try {
      const { prompts } = await withTimeout(client.listPrompts(), ctx.timeout, 'prompts/list');
      if (!Array.isArray(prompts)) {
        findings.push({
          id: 'PROTO-006',
          title: 'prompts/list returns invalid response',
          severity: 'high',
          category: 'protocol',
          description: 'prompts/list did not return an array for the prompts field',
          remediation: 'Return { prompts: [...] } from the prompts/list handler',
        });
      } else {
        findings.push({
          id: 'PROTO-006',
          title: 'prompts/list returns valid response',
          severity: 'info',
          category: 'protocol',
          description: `prompts/list returned ${prompts.length} prompt(s)`,
        });
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      findings.push({
        id: 'PROTO-006',
        title: 'prompts/list failed',
        severity: 'high',
        category: 'protocol',
        description: `prompts/list call failed: ${msg}`,
        evidence: msg,
      });
    }
  }

  // 7. Ping
  try {
    await withTimeout(client.ping(), ctx.timeout, 'ping');
    findings.push({
      id: 'PROTO-007',
      title: 'Ping responds',
      severity: 'info',
      category: 'protocol',
      description: 'Server responded to ping request',
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    findings.push({
      id: 'PROTO-007',
      title: 'Ping failed',
      severity: 'medium',
      category: 'protocol',
      description: `Server did not respond to ping: ${msg}`,
      evidence: msg,
    });
  }

  const durationMs = Math.round(performance.now() - start);

  return {
    name: 'Protocol',
    findings,
    score: computeSuiteScore(findings),
    certificationBlockers: [],
    evidence: {
      artifacts: [],
      durationMs,
    },
  };
}
