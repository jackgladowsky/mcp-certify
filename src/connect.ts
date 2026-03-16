import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { ServerTarget } from './types.js';

function createClient(): Client {
  return new Client({ name: 'mcp-certify', version: '0.1.0' }, { capabilities: {} });
}

export async function connect(
  target: ServerTarget,
): Promise<{ client: Client; transport: Transport }> {
  if (target.url) {
    return connectHTTP(target.url);
  }

  if (target.command) {
    const client = createClient();
    const transport = new StdioClientTransport({
      command: target.command,
      args: target.args ?? [],
      env: target.env,
      stderr: 'ignore',
    });
    await client.connect(transport);
    return { client, transport };
  }

  throw new Error('Either --url or a command must be provided');
}

async function connectHTTP(
  url: string,
): Promise<{ client: Client; transport: Transport }> {
  // Try streamable HTTP first, fall back to SSE
  try {
    const { StreamableHTTPClientTransport } = await import(
      '@modelcontextprotocol/sdk/client/streamableHttp.js'
    );
    const client = createClient();
    const transport = new StreamableHTTPClientTransport(new URL(url));
    await client.connect(transport);
    return { client, transport };
  } catch {
    const { SSEClientTransport } = await import(
      '@modelcontextprotocol/sdk/client/sse.js'
    );
    const client = createClient();
    const transport = new SSEClientTransport(new URL(url));
    await client.connect(transport);
    return { client, transport };
  }
}
