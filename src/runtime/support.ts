import type { ServerTarget } from '../types.js';

export type RuntimeSupportStatus =
  | 'supported'
  | 'unsupported_transport'
  | 'unsupported_launcher';

export interface RuntimeSupportResult {
  status: RuntimeSupportStatus;
  detail: string;
  launcher?: string;
}

const UNSUPPORTED_LAUNCHERS = new Set([
  'npx',
  'npm',
  'pnpm',
  'yarn',
  'bunx',
  'pipx',
  'uvx',
]);

export function detectUnsupportedLauncher(target: ServerTarget): string | undefined {
  if (!target.command) return undefined;

  const command = target.command.split('/').pop()?.toLowerCase() ?? target.command.toLowerCase();
  const firstArg = target.args?.[0]?.toLowerCase();

  if (UNSUPPORTED_LAUNCHERS.has(command)) {
    return target.command;
  }

  if (
    (command === 'bun' && firstArg === 'x') ||
    (command === 'yarn' && firstArg === 'dlx') ||
    (command === 'pnpm' && firstArg === 'dlx')
  ) {
    return `${target.command} ${target.args?.[0] ?? ''}`.trim();
  }

  return undefined;
}

export function assessRuntimeSupport(target?: ServerTarget): RuntimeSupportResult {
  if (!target) {
    return {
      status: 'supported',
      detail:
        'Runtime sandbox coverage is available for supported local stdio launches such as `node dist/index.js` or `python path/to/server.py`.',
    };
  }

  if (!target.command) {
    return {
      status: 'unsupported_transport',
      detail:
        'Runtime sandbox coverage currently supports only local stdio servers. HTTP/SSE targets do not receive runtime coverage.',
    };
  }

  const launcher = detectUnsupportedLauncher(target);
  if (launcher) {
    return {
      status: 'unsupported_launcher',
      detail: `Runtime sandbox coverage is unavailable for launcher "${launcher}" because bootstrap traffic can be confused with server behavior.`,
      launcher,
    };
  }

  return {
    status: 'supported',
    detail:
      'Runtime sandbox coverage is available for this target because it uses a stable local stdio launch command.',
  };
}
