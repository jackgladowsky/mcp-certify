import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { SuiteResult, SuiteContext, Finding } from '../types.js';
import { computeSuiteScore, withTimeout } from '../utils.js';

type ListedTool = Awaited<ReturnType<Client['listTools']>>['tools'][number];
type ListedResource = Awaited<ReturnType<Client['listResources']>>['resources'][number];
type ListedPrompt = Awaited<ReturnType<Client['listPrompts']>>['prompts'][number];
type ListedResourceTemplate = Awaited<
  ReturnType<Client['listResourceTemplates']>
>['resourceTemplates'][number];

function pushUniqueIdFinding(
  findings: Finding[],
  id: string,
  title: string,
  duplicates: string[],
  remediation: string,
): void {
  if (duplicates.length === 0) {
    findings.push({
      id,
      title: `${title} are unique`,
      severity: 'info',
      category: 'protocol',
      description: `No duplicate ${title.toLowerCase()} detected`,
    });
    return;
  }

  findings.push({
    id,
    title: `Duplicate ${title.toLowerCase()}`,
    severity: 'high',
    category: 'protocol',
    description: `Duplicate ${title.toLowerCase()} found: ${duplicates.join(', ')}`,
    remediation,
  });
}

function findDuplicates(values: string[]): string[] {
  const seen = new Set<string>();
  const duplicates = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) {
      duplicates.add(value);
    } else {
      seen.add(value);
    }
  }
  return [...duplicates];
}

function validateToolMetadata(tools: ListedTool[], findings: Finding[]): void {
  const names = tools.map((tool) => tool.name);
  pushUniqueIdFinding(
    findings,
    'PROTO-008',
    'Tool names',
    findDuplicates(names),
    'Each tool should have a unique name in tools/list.',
  );

  const invalidSchemas = tools
    .filter((tool) => tool.inputSchema.type !== 'object')
    .map((tool) => tool.name);
  if (invalidSchemas.length === 0) {
    findings.push({
      id: 'PROTO-009',
      title: 'Tool schemas are protocol-shaped',
      severity: 'info',
      category: 'protocol',
      description: 'All listed tools expose object-shaped input schemas',
    });
  } else {
    findings.push({
      id: 'PROTO-009',
      title: 'Tool schema shape mismatch',
      severity: 'high',
      category: 'protocol',
      description: `Tools with non-object input schemas: ${invalidSchemas.join(', ')}`,
      remediation: 'Return object-shaped inputSchema definitions for all tools.',
    });
  }

  const unnamedDescriptions = tools
    .filter((tool) => !tool.description || tool.description.trim().length === 0)
    .map((tool) => tool.name);
  if (unnamedDescriptions.length === 0) {
    findings.push({
      id: 'PROTO-010',
      title: 'Tool descriptions present',
      severity: 'info',
      category: 'protocol',
      description: 'All listed tools provide non-empty descriptions',
    });
  } else {
    findings.push({
      id: 'PROTO-010',
      title: 'Tool descriptions missing',
      severity: 'medium',
      category: 'protocol',
      description: `Tools with empty descriptions: ${unnamedDescriptions.join(', ')}`,
      remediation: 'Provide descriptions for all tools exposed in tools/list.',
    });
  }
}

function validateResourceMetadata(
  resources: ListedResource[],
  findings: Finding[],
): void {
  pushUniqueIdFinding(
    findings,
    'PROTO-011',
    'Resource URIs',
    findDuplicates(resources.map((resource) => resource.uri)),
    'Each resource should have a unique URI in resources/list.',
  );

  const missingNames = resources
    .filter((resource) => !resource.name || resource.name.trim().length === 0)
    .map((resource) => resource.uri);
  if (missingNames.length === 0) {
    findings.push({
      id: 'PROTO-012',
      title: 'Resource names present',
      severity: 'info',
      category: 'protocol',
      description: 'All listed resources provide names',
    });
  } else {
    findings.push({
      id: 'PROTO-012',
      title: 'Resource names missing',
      severity: 'medium',
      category: 'protocol',
      description: `Resources with empty names: ${missingNames.join(', ')}`,
      remediation: 'Provide a stable display name for each listed resource.',
    });
  }
}

function validatePromptMetadata(prompts: ListedPrompt[], findings: Finding[]): void {
  pushUniqueIdFinding(
    findings,
    'PROTO-013',
    'Prompt names',
    findDuplicates(prompts.map((prompt) => prompt.name)),
    'Each prompt should have a unique name in prompts/list.',
  );

  const invalidArguments = prompts
    .filter((prompt) =>
      (prompt.arguments ?? []).some(
        (argument) => !argument.name || argument.name.trim().length === 0,
      ),
    )
    .map((prompt) => prompt.name);
  if (invalidArguments.length === 0) {
    findings.push({
      id: 'PROTO-014',
      title: 'Prompt argument metadata valid',
      severity: 'info',
      category: 'protocol',
      description: 'Prompt arguments have stable names when declared',
    });
  } else {
    findings.push({
      id: 'PROTO-014',
      title: 'Prompt argument metadata invalid',
      severity: 'medium',
      category: 'protocol',
      description: `Prompts with unnamed arguments: ${invalidArguments.join(', ')}`,
      remediation: 'Ensure every declared prompt argument has a non-empty name.',
    });
  }
}

function validateResourceTemplateMetadata(
  templates: ListedResourceTemplate[],
  findings: Finding[],
): void {
  pushUniqueIdFinding(
    findings,
    'PROTO-015',
    'Resource template URIs',
    findDuplicates(templates.map((template) => template.uriTemplate)),
    'Each resource template should have a unique uriTemplate.',
  );
}

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
        validateToolMetadata(tools, findings);
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
        validateResourceMetadata(resources, findings);
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

  if (caps?.resources) {
    try {
      const { resourceTemplates } = await withTimeout(
        client.listResourceTemplates(),
        ctx.timeout,
        'resources/templates/list',
      );
      if (!Array.isArray(resourceTemplates)) {
        findings.push({
          id: 'PROTO-015',
          title: 'resources/templates/list returns invalid response',
          severity: 'high',
          category: 'protocol',
          description:
            'resources/templates/list did not return an array for the resourceTemplates field',
          remediation:
            'Return { resourceTemplates: [...] } from the resources/templates/list handler',
        });
      } else {
        findings.push({
          id: 'PROTO-015A',
          title: 'resources/templates/list returns valid response',
          severity: 'info',
          category: 'protocol',
          description: `resources/templates/list returned ${resourceTemplates.length} template(s)`,
        });
        validateResourceTemplateMetadata(resourceTemplates, findings);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      findings.push({
        id: 'PROTO-015',
        title: 'resources/templates/list failed',
        severity: 'medium',
        category: 'protocol',
        description: `resources/templates/list call failed: ${msg}`,
        evidence: msg,
        remediation:
          'If the server advertises resources capability, ensure resource template listing is either supported or intentionally empty.',
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
        validatePromptMetadata(prompts, findings);
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
