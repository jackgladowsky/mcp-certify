import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { applyAuthEnv, buildRequestInit } from './auth/config.js';
import type { AuthConfig, ServerTarget } from './types.js';
import { TOOL_VERSION } from './version.js';

export interface ConnectOptions {
  auth?: AuthConfig;
  includeAuth?: boolean;
}

function createClient(): Client {
  return new Client({ name: 'mcp-certify', version: TOOL_VERSION }, { capabilities: {} });
}

function formatConnectError(err: unknown): string {
  if (err instanceof Error) {
    return err.message;
  }
  return String(err);
}

export async function connect(
  target: ServerTarget,
  options: ConnectOptions = {},
): Promise<{ client: Client; transport: Transport }> {
  const auth = options.includeAuth === false ? undefined : options.auth;

  if (target.url) {
    return connectHTTP(target.url, auth);
  }

  if (target.command) {
    const client = createClient();
    const transport = new StdioClientTransport({
      command: target.command,
      args: target.args ?? [],
      env: applyAuthEnv(target.env, auth),
      stderr: 'ignore',
    });
    await client.connect(transport);
    return { client, transport };
  }

  throw new Error('Either --url or a command must be provided');
}

async function connectHTTP(
  url: string,
  auth?: AuthConfig,
): Promise<{ client: Client; transport: Transport }> {
  const requestInit = buildRequestInit(auth);

  // Try streamable HTTP first, fall back to SSE
  try {
    const { StreamableHTTPClientTransport } = await import(
      '@modelcontextprotocol/sdk/client/streamableHttp.js'
    );
    const client = createClient();
    const transport = new StreamableHTTPClientTransport(new URL(url), {
      requestInit,
    });
    await client.connect(transport);
    return { client, transport };
  } catch (streamableError: unknown) {
    try {
      const { SSEClientTransport } = await import(
        '@modelcontextprotocol/sdk/client/sse.js'
      );
      const client = createClient();
      const transport = new SSEClientTransport(new URL(url), {
        requestInit,
      });
      await client.connect(transport);
      return { client, transport };
    } catch (sseError: unknown) {
      const streamableMessage = formatConnectError(streamableError);
      const sseMessage = formatConnectError(sseError);
      throw new Error(
        `Failed to connect to ${url} via streamable HTTP: ${streamableMessage}. SSE fallback also failed: ${sseMessage}`,
        {
          cause: streamableError instanceof Error ? streamableError : undefined,
        },
      );
    }
  }
}
