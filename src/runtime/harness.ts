import { mkdtemp, rm, mkdir } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { CanaryFile } from './canaries.js';
import { generateCanaries, seedCanaries, checkCanaryLeaks, checkCanaryAccess } from './canaries.js';
import { startCapture, proxyEnv } from './networkCapture.js';
import type { CaptureSession } from './networkCapture.js';
import type { Scenario, ScenarioResult } from './scenarios/types.js';
import type { Readable } from 'node:stream';

export interface HarnessConfig {
  command: string;
  args: string[];
  env?: Record<string, string>;
  timeout: number;
  workDir?: string;
}

function resolveCommandPath(command: string, workDir: string): string {
  if (command.includes('/') || command.includes('\\')) {
    return isAbsolute(command) ? command : resolve(workDir, command);
  }
  return command;
}

export interface HarnessResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  filesAccessed: string[];
  networkRequests: string[];
  canaryLeaks: string[];
  durationMs: number;
  scenarioResults: Map<string, ScenarioResult>;
}

/**
 * Launch an MCP server in a sandboxed environment and run security scenarios.
 *
 * The harness:
 * 1. Creates a temp directory mimicking a real HOME with canary files
 * 2. Starts a network capture proxy
 * 3. Launches the MCP server with HOME redirected to the temp dir
 * 4. Connects as an MCP client
 * 5. Runs each scenario against the connected client
 * 6. Collects all output, file access, network events, and canary leaks
 * 7. Cleans up everything
 */
export async function runInHarness(
  config: HarnessConfig,
  scenarios: Scenario[],
): Promise<HarnessResult> {
  const startTime = performance.now();
  let tempHome = '';
  let capture: CaptureSession | undefined;
  let client: Client | undefined;
  let transport: StdioClientTransport | undefined;
  let stderrText = '';
  const scenarioResults = new Map<string, ScenarioResult>();

  try {
    // 1. Create isolated HOME directory structure
    tempHome = await mkdtemp(join(tmpdir(), 'mcp-certify-sandbox-'));
    await mkdir(join(tempHome, '.config'), { recursive: true });
    await mkdir(join(tempHome, '.local', 'share'), { recursive: true });

    // 2. Generate and seed canary files
    const canaries = generateCanaries();
    await seedCanaries(tempHome, canaries);

    // 3. Run scenario setup hooks
    for (const scenario of scenarios) {
      if (scenario.setup) {
        await scenario.setup(tempHome);
      }
    }

    // 4. Start network capture proxy
    capture = await startCapture();

    // 5. Build sandboxed environment
    const sandboxEnv: Record<string, string> = {
      ...filterSafeEnv(),
      ...(config.env ?? {}),
      HOME: tempHome,
      USERPROFILE: tempHome, // Windows compat
      XDG_CONFIG_HOME: join(tempHome, '.config'),
      XDG_DATA_HOME: join(tempHome, '.local', 'share'),
      XDG_CACHE_HOME: join(tempHome, '.cache'),
      XDG_STATE_HOME: join(tempHome, '.local', 'state'),
      TMPDIR: join(tempHome, 'tmp'),
      ...proxyEnv(capture.port),
    };

    // Ensure TMPDIR exists
    await mkdir(join(tempHome, 'tmp'), { recursive: true });

    // 6. Launch MCP server via StdioClientTransport
    client = new Client(
      { name: 'mcp-certify-sandbox', version: '0.1.0' },
      { capabilities: {} },
    );

    const workDir = config.workDir ?? process.cwd();
    transport = new StdioClientTransport({
      command: resolveCommandPath(config.command, workDir),
      args: config.args,
      env: sandboxEnv,
      cwd: workDir,
      stderr: 'pipe',
    });

    // Capture stderr from the server process
    const stderrStream = transport.stderr as Readable | null;
    if (stderrStream) {
      stderrStream.on('data', (chunk: Buffer) => {
        stderrText += chunk.toString('utf-8');
      });
    }

    // Connect with timeout
    await withTimeout(
      client.connect(transport),
      config.timeout,
      'MCP server connection timed out',
    );

    // 7. Run each scenario
    for (const scenario of scenarios) {
      try {
        const result = await withTimeout(
          scenario.run(client, tempHome, canaries, capture),
          config.timeout,
          `Scenario "${scenario.name}" timed out`,
        );
        scenarioResults.set(scenario.id, result);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        scenarioResults.set(scenario.id, {
          passed: false,
          findings: [
            {
              id: scenario.id,
              title: `Scenario error: ${scenario.name}`,
              severity: 'medium',
              category: scenario.category,
              description: `Scenario failed with error: ${msg}`,
              evidence: msg,
            },
          ],
          evidence: `Error: ${msg}`,
        });
      }
    }

    // 8. Post-run analysis: check stderr for canary leaks.
    // Tool results are inspected inside the runtime scenarios themselves.
    const leaks = checkCanaryLeaks(stderrText, canaries);
    const filesAccessed = await checkCanaryAccess(tempHome, canaries);
    const networkRequests = (capture?.events ?? []).map(
      (e) => `${e.method ?? e.type} ${e.destination}`,
    );

    // 9. Disconnect
    try {
      await client.close();
    } catch {
      // Server may have already exited
    }

    return {
      stdout: '',
      stderr: stderrText,
      exitCode: null,
      filesAccessed,
      networkRequests,
      canaryLeaks: leaks,
      durationMs: Math.round(performance.now() - startTime),
      scenarioResults,
    };
  } finally {
    // Cleanup: stop capture proxy
    if (capture) {
      try {
        capture.stop();
      } catch {
        // Best effort
      }
    }

    // Cleanup: disconnect client
    if (client) {
      try {
        await client.close();
      } catch {
        // Already closed or server exited
      }
    }

    // Cleanup: remove temp directory
    if (tempHome) {
      try {
        await rm(tempHome, { recursive: true, force: true });
      } catch {
        // Best effort cleanup
      }
    }
  }
}

/**
 * Filter the current process env to only include safe, non-secret variables.
 * We avoid leaking real credentials into the sandbox.
 */
function filterSafeEnv(): Record<string, string> {
  const safe: Record<string, string> = {};
  const allowlist = [
    'PATH',
    'LANG',
    'LC_ALL',
    'LC_CTYPE',
    'TERM',
    'SHELL',
    'USER',
    'LOGNAME',
    'EDITOR',
    'VISUAL',
    'NODE_ENV',
    'NODE_OPTIONS',
  ];

  for (const key of allowlist) {
    if (process.env[key]) {
      safe[key] = process.env[key]!;
    }
  }

  return safe;
}

/**
 * Wrap a promise with a timeout.
 */
function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  message: string,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), ms);
    promise
      .then((val) => {
        clearTimeout(timer);
        resolve(val);
      })
      .catch((err) => {
        clearTimeout(timer);
        reject(err);
      });
  });
}
