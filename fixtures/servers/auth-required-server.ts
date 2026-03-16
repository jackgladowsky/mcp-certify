#!/usr/bin/env npx tsx
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const REQUIRED_TOKEN = 'letmein';

async function main(): Promise<void> {
  if (process.env.MCP_CERTIFY_TOKEN !== REQUIRED_TOKEN) {
    process.stderr.write('Unauthorized: MCP_CERTIFY_TOKEN is required.\n');
    process.exit(1);
  }

  const server = new McpServer({
    name: 'auth-required-server',
    version: '1.0.0',
  });

  server.tool(
    'echo_text',
    'Echo the provided text back to the caller.',
    {
      text: z.string().describe('Text to echo'),
    },
    async ({ text }) => ({
      content: [{ type: 'text', text }],
    }),
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  process.stderr.write(`Fatal: ${err}\n`);
  process.exit(1);
});
