import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { SuiteResult, SuiteContext, TestResult } from '../types.js';
import { runTest, computeSuiteScore } from '../utils.js';

interface ToolLike {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export async function functionalSuite(
  client: Client,
  ctx: SuiteContext,
): Promise<SuiteResult> {
  const tests: TestResult[] = [];
  const caps = client.getServerCapabilities();

  // Get tools
  let tools: ToolLike[] = [];
  if (caps?.tools) {
    try {
      const result = await client.listTools();
      tools = result.tools as ToolLike[];
    } catch {
      // Already covered in protocol suite
    }
  }

  // 1. All tools have descriptions
  if (tools.length > 0) {
    const noDesc = tools.filter((t) => !t.description || t.description.trim() === '');
    if (noDesc.length === 0) {
      tests.push({ name: 'All tools have descriptions', status: 'pass' });
    } else {
      tests.push({
        name: 'Tool descriptions present',
        status: 'warn',
        message: `${noDesc.length} tool(s) missing descriptions`,
        details: noDesc.map((t) => t.name).join(', '),
      });
    }
  }

  // 2. Input schemas are valid JSON Schema
  if (tools.length > 0) {
    tests.push(validateInputSchemas(tools));
  }

  // 3. Required fields are declared
  if (tools.length > 0) {
    tests.push(checkRequiredFields(tools));
  }

  // 4. Tool name quality
  if (tools.length > 0) {
    tests.push(checkToolNames(tools));
  }

  // 5. Tool calling (opt-in, may have side effects)
  if (ctx.options.callTools && tools.length > 0) {
    for (const tool of tools.slice(0, 5)) {
      tests.push(await testToolCall(client, tool));
    }
  }

  if (tests.length === 0) {
    tests.push({
      name: 'No tools to test',
      status: 'skip',
      message: 'Server has no tools',
    });
  }

  return {
    name: 'Functional',
    tests,
    score: computeSuiteScore(tests),
  };
}

function validateInputSchemas(tools: ToolLike[]): TestResult {
  const issues: string[] = [];

  for (const tool of tools) {
    const schema = tool.inputSchema;
    if (!schema) continue;

    if (schema['type'] !== 'object') {
      issues.push(`${tool.name}: inputSchema type is "${schema['type']}", expected "object"`);
    }
  }

  if (issues.length === 0) {
    return { name: 'Input schemas are valid', status: 'pass' };
  }
  return {
    name: 'Input schema validation',
    status: 'warn',
    message: `${issues.length} issue(s)`,
    details: issues.join('\n'),
  };
}

function checkRequiredFields(tools: ToolLike[]): TestResult {
  const issues: string[] = [];

  for (const tool of tools) {
    const schema = tool.inputSchema;
    if (!schema || schema['type'] !== 'object') continue;

    const properties = schema['properties'] as Record<string, unknown> | undefined;
    const required = schema['required'] as string[] | undefined;

    if (properties && Object.keys(properties).length > 0 && !required) {
      issues.push(`${tool.name}: has properties but no "required" array`);
    }

    if (required && properties) {
      for (const field of required) {
        if (!(field in properties)) {
          issues.push(`${tool.name}: required field "${field}" not in properties`);
        }
      }
    }
  }

  if (issues.length === 0) {
    return { name: 'Required fields properly declared', status: 'pass' };
  }
  return {
    name: 'Required field declarations',
    status: 'warn',
    message: `${issues.length} issue(s)`,
    details: issues.join('\n'),
  };
}

function checkToolNames(tools: ToolLike[]): TestResult {
  const issues: string[] = [];

  for (const tool of tools) {
    // Check for spaces or weird characters in names
    if (/\s/.test(tool.name)) {
      issues.push(`"${tool.name}": contains whitespace`);
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(tool.name)) {
      issues.push(`"${tool.name}": contains special characters`);
    }
    // Very short names are ambiguous
    if (tool.name.length <= 1) {
      issues.push(`"${tool.name}": name too short`);
    }
  }

  if (issues.length === 0) {
    return { name: 'Tool names are well-formed', status: 'pass' };
  }
  return {
    name: 'Tool name quality',
    status: 'warn',
    message: `${issues.length} issue(s)`,
    details: issues.join('\n'),
  };
}

async function testToolCall(
  client: Client,
  tool: ToolLike,
): Promise<TestResult> {
  return runTest(`Call tool: ${tool.name}`, async () => {
    try {
      const result = await client.callTool({
        name: tool.name,
        arguments: {},
      });

      // A tool returning isError with empty args is reasonable behavior
      if (result.isError) {
        return {
          status: 'pass',
          message: 'Returned error for empty args (expected)',
        };
      }

      // Tool succeeded with empty args
      if (!result.content || !Array.isArray(result.content)) {
        return { status: 'warn', message: 'Response missing content array' };
      }

      return {
        status: 'pass',
        message: `Returned ${result.content.length} content item(s)`,
      };
    } catch (err: unknown) {
      // Protocol-level error (not tool-level isError) could indicate poor error handling
      const msg = err instanceof Error ? err.message : String(err);
      return {
        status: 'warn',
        message: `Protocol error on empty args: ${msg}`,
      };
    }
  });
}
