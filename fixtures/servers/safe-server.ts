#!/usr/bin/env npx tsx
/**
 * Well-built reference MCP server for testing mcp-certify.
 *
 * This server follows all best practices and should score 100/100 on
 * certification checks. Use it as a reference implementation.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const server = new McpServer({
  name: 'safe-reference-server',
  version: '1.0.0',
});

// ---------------------------------------------------------------------------
// Tool 1: String manipulation
// ---------------------------------------------------------------------------
server.tool(
  'reverse_string',
  'Reverse the characters in a given string and return the result.',
  {
    input: z.string().describe('The string to reverse'),
  },
  async ({ input }) => {
    try {
      const reversed = input.split('').reverse().join('');
      return {
        content: [{ type: 'text', text: reversed }],
      };
    } catch {
      return {
        content: [{ type: 'text', text: 'Failed to reverse the string.' }],
        isError: true,
      };
    }
  },
);

// ---------------------------------------------------------------------------
// Tool 2: Math operations
// ---------------------------------------------------------------------------
server.tool(
  'calculate',
  'Perform a basic arithmetic operation on two numbers.',
  {
    a: z.number().describe('First operand'),
    b: z.number().describe('Second operand'),
    operation: z
      .enum(['add', 'subtract', 'multiply', 'divide'])
      .describe('Arithmetic operation to perform'),
  },
  async ({ a, b, operation }) => {
    try {
      let result: number;
      switch (operation) {
        case 'add':
          result = a + b;
          break;
        case 'subtract':
          result = a - b;
          break;
        case 'multiply':
          result = a * b;
          break;
        case 'divide':
          if (b === 0) {
            return {
              content: [{ type: 'text', text: 'Error: Division by zero.' }],
              isError: true,
            };
          }
          result = a / b;
          break;
      }
      return {
        content: [{ type: 'text', text: String(result) }],
      };
    } catch {
      return {
        content: [{ type: 'text', text: 'Calculation failed.' }],
        isError: true,
      };
    }
  },
);

// ---------------------------------------------------------------------------
// Tool 3: Word count
// ---------------------------------------------------------------------------
server.tool(
  'word_count',
  'Count the number of words in the provided text.',
  {
    text: z.string().describe('Text to count words in'),
  },
  async ({ text }) => {
    try {
      const count = text.trim().split(/\s+/).filter(Boolean).length;
      return {
        content: [{ type: 'text', text: String(count) }],
      };
    } catch {
      return {
        content: [{ type: 'text', text: 'Word count failed.' }],
        isError: true,
      };
    }
  },
);

// ---------------------------------------------------------------------------
// Tool 4: JSON validator
// ---------------------------------------------------------------------------
server.tool(
  'validate_json',
  'Check whether the given string is valid JSON and return the parsed structure.',
  {
    input: z.string().describe('JSON string to validate'),
  },
  async ({ input }) => {
    try {
      const parsed = JSON.parse(input);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ valid: true, keys: Object.keys(parsed) }),
          },
        ],
      };
    } catch {
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ valid: false, error: 'Invalid JSON' }),
          },
        ],
        isError: true,
      };
    }
  },
);

// ---------------------------------------------------------------------------
// Resource 1: Server status
// ---------------------------------------------------------------------------
server.resource(
  'server-status',
  'status://server',
  {
    description: 'Current server status and uptime information.',
    mimeType: 'application/json',
  },
  async () => ({
    contents: [
      {
        uri: 'status://server',
        mimeType: 'application/json',
        text: JSON.stringify({
          status: 'healthy',
          uptime: process.uptime(),
          version: '1.0.0',
        }),
      },
    ],
  }),
);

// ---------------------------------------------------------------------------
// Resource 2: Available operations
// ---------------------------------------------------------------------------
server.resource(
  'operations-list',
  'info://operations',
  {
    description: 'List of supported arithmetic operations.',
    mimeType: 'application/json',
  },
  async () => ({
    contents: [
      {
        uri: 'info://operations',
        mimeType: 'application/json',
        text: JSON.stringify({
          operations: ['add', 'subtract', 'multiply', 'divide'],
        }),
      },
    ],
  }),
);

// ---------------------------------------------------------------------------
// Prompt: Text analysis helper
// ---------------------------------------------------------------------------
server.prompt(
  'analyze_text',
  'Generate a prompt for analyzing text using the available tools.',
  {
    text: z.string().describe('The text to analyze'),
  },
  async ({ text }) => ({
    messages: [
      {
        role: 'user',
        content: {
          type: 'text',
          text:
            `Please analyze the following text using the available tools:\n\n` +
            `"${text}"\n\n` +
            `1. Use word_count to count the words.\n` +
            `2. Use reverse_string on the first word.\n` +
            `3. Summarize your findings.`,
        },
      },
    ],
  }),
);

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  process.stderr.write(`Fatal: ${err}\n`);
  process.exit(1);
});
