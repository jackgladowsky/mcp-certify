import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { SuiteResult, SuiteContext, Finding } from '../types.js';
import { computeSuiteScore, withTimeout } from '../utils.js';

interface ToolLike {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export async function functionalSuite(
  client: Client,
  ctx: SuiteContext,
): Promise<SuiteResult> {
  const findings: Finding[] = [];
  const start = performance.now();
  const caps = client.getServerCapabilities();

  // Get tools
  let tools: ToolLike[] = [];
  if (caps?.tools) {
    try {
      const result = await withTimeout(client.listTools(), ctx.timeout, 'tools/list (functional)');
      tools = result.tools as ToolLike[];
    } catch {
      // Already covered in protocol suite
    }
  }

  // 1. All tools have descriptions
  if (tools.length > 0) {
    const noDesc = tools.filter((t) => !t.description || t.description.trim() === '');
    if (noDesc.length === 0) {
      findings.push({
        id: 'FUNC-001',
        title: 'All tools have descriptions',
        severity: 'info',
        category: 'functional',
        description: 'Every tool provides a description',
      });
    } else {
      for (let i = 0; i < noDesc.length; i++) {
        findings.push({
          id: `FUNC-001-${String(i + 1).padStart(3, '0')}`,
          title: `Missing description: ${noDesc[i].name}`,
          severity: 'low',
          category: 'functional',
          description: `Tool "${noDesc[i].name}" has no description`,
          source: noDesc[i].name,
          remediation: 'Add a clear description explaining what the tool does',
        });
      }
    }
  }

  // 2. Input schemas are valid JSON Schema
  if (tools.length > 0) {
    const schemaFindings = validateInputSchemas(tools);
    findings.push(...schemaFindings);
  }

  // 3. Required fields are declared
  if (tools.length > 0) {
    const reqFindings = checkRequiredFields(tools);
    findings.push(...reqFindings);
  }

  // 4. Tool name quality
  if (tools.length > 0) {
    const nameFindings = checkToolNames(tools);
    findings.push(...nameFindings);
  }

  // 5. Tool calling (opt-in, may have side effects)
  if (ctx.options.callTools && tools.length > 0) {
    for (const tool of tools.slice(0, 5)) {
      const callFindings = await testToolCall(client, tool, ctx);
      findings.push(...callFindings);
    }
  }

  if (findings.length === 0) {
    findings.push({
      id: 'FUNC-SKIP-001',
      title: 'No tools to test',
      severity: 'info',
      category: 'functional',
      description: 'Server has no tools to validate',
    });
  }

  const durationMs = Math.round(performance.now() - start);

  return {
    name: 'Functional',
    findings,
    score: computeSuiteScore(findings),
    certificationBlockers: [],
    evidence: { artifacts: [], durationMs },
  };
}

function validateInputSchemas(tools: ToolLike[]): Finding[] {
  const findings: Finding[] = [];
  let counter = 0;

  for (const tool of tools) {
    const schema = tool.inputSchema;
    if (!schema) continue;

    if (schema['type'] !== 'object') {
      counter++;
      findings.push({
        id: `FUNC-002-${String(counter).padStart(3, '0')}`,
        title: `Invalid input schema: ${tool.name}`,
        severity: 'medium',
        category: 'functional',
        description: `Tool "${tool.name}" inputSchema type is "${schema['type']}", expected "object"`,
        source: tool.name,
        remediation: 'Set inputSchema.type to "object"',
      });
    }
  }

  if (counter === 0) {
    findings.push({
      id: 'FUNC-002',
      title: 'Input schemas are valid',
      severity: 'info',
      category: 'functional',
      description: 'All tool input schemas use type "object"',
    });
  }

  return findings;
}

function checkRequiredFields(tools: ToolLike[]): Finding[] {
  const findings: Finding[] = [];
  let counter = 0;

  for (const tool of tools) {
    const schema = tool.inputSchema;
    if (!schema || schema['type'] !== 'object') continue;

    const properties = schema['properties'] as Record<string, unknown> | undefined;
    const required = schema['required'] as string[] | undefined;

    if (properties && Object.keys(properties).length > 0 && !required) {
      counter++;
      findings.push({
        id: `FUNC-003-${String(counter).padStart(3, '0')}`,
        title: `Missing required array: ${tool.name}`,
        severity: 'info',
        category: 'functional',
        description: `Tool "${tool.name}" has properties but no "required" array`,
        source: tool.name,
      });
    }

    if (required && properties) {
      for (const field of required) {
        if (!(field in properties)) {
          counter++;
          findings.push({
            id: `FUNC-003-${String(counter).padStart(3, '0')}`,
            title: `Orphaned required field: ${tool.name}.${field}`,
            severity: 'medium',
            category: 'functional',
            description: `Tool "${tool.name}": required field "${field}" is not defined in properties`,
            source: tool.name,
            remediation: `Add "${field}" to the properties object or remove it from required`,
          });
        }
      }
    }
  }

  if (counter === 0) {
    findings.push({
      id: 'FUNC-003',
      title: 'Required fields properly declared',
      severity: 'info',
      category: 'functional',
      description: 'All tools have consistent required field declarations',
    });
  }

  return findings;
}

function checkToolNames(tools: ToolLike[]): Finding[] {
  const findings: Finding[] = [];
  let counter = 0;

  for (const tool of tools) {
    const issues: string[] = [];

    if (/\s/.test(tool.name)) {
      issues.push('contains whitespace');
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(tool.name)) {
      issues.push('contains special characters');
    }
    if (tool.name.length <= 1) {
      issues.push('name too short');
    }

    if (issues.length > 0) {
      counter++;
      findings.push({
        id: `FUNC-004-${String(counter).padStart(3, '0')}`,
        title: `Bad tool name: ${tool.name}`,
        severity: 'medium',
        category: 'functional',
        description: `Tool "${tool.name}": ${issues.join(', ')}`,
        source: tool.name,
        remediation: 'Use alphanumeric characters, hyphens, and underscores only',
      });
    }
  }

  if (counter === 0) {
    findings.push({
      id: 'FUNC-004',
      title: 'Tool names are well-formed',
      severity: 'info',
      category: 'functional',
      description: 'All tool names follow naming conventions',
    });
  }

  return findings;
}

async function testToolCall(
  client: Client,
  tool: ToolLike,
  ctx: SuiteContext,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const toolId = tool.name.replace(/[^a-zA-Z0-9]/g, '-').toUpperCase();

  try {
    const result = await withTimeout(
      client.callTool({ name: tool.name, arguments: {} }),
      ctx.timeout,
      `callTool(${tool.name})`,
    );

    // A tool returning isError with empty args is reasonable behavior
    if (result.isError) {
      findings.push({
        id: `FUNC-CALL-${toolId}`,
        title: `Tool call: ${tool.name}`,
        severity: 'info',
        category: 'functional',
        description: `Tool "${tool.name}" returned error for empty args (expected behavior)`,
        source: tool.name,
      });
    } else if (!result.content || !Array.isArray(result.content)) {
      findings.push({
        id: `FUNC-CALL-${toolId}`,
        title: `Tool call missing content: ${tool.name}`,
        severity: 'medium',
        category: 'functional',
        description: `Tool "${tool.name}" response is missing content array`,
        source: tool.name,
        remediation: 'Return a content array in the tool response',
      });
    } else {
      findings.push({
        id: `FUNC-CALL-${toolId}`,
        title: `Tool call: ${tool.name}`,
        severity: 'info',
        category: 'functional',
        description: `Tool "${tool.name}" returned ${result.content.length} content item(s)`,
        source: tool.name,
      });
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    findings.push({
      id: `FUNC-CALL-${toolId}`,
      title: `Tool call error: ${tool.name}`,
      severity: 'medium',
      category: 'functional',
      description: `Protocol error calling "${tool.name}" with empty args: ${msg}`,
      source: tool.name,
      evidence: msg,
    });
  }

  return findings;
}
