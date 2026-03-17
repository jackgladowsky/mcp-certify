import { existsSync } from 'node:fs';
import { delimiter, isAbsolute, join, resolve } from 'node:path';
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

interface UnwrappedCommand {
  command: string;
  args: string[];
  originalLauncher: string;
}

function findExecutableOnPath(name: string, cwd: string): string | undefined {
  const candidates = [
    join(cwd, 'node_modules', '.bin', name),
  ];

  if (process.platform === 'win32') {
    candidates.push(join(cwd, 'node_modules', '.bin', `${name}.cmd`));
  }

  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }

  const pathDirs = (process.env.PATH ?? '').split(delimiter).filter(Boolean);
  for (const dir of pathDirs) {
    const candidate = join(dir, name);
    if (existsSync(candidate)) {
      return candidate;
    }
    if (process.platform === 'win32') {
      const cmdCandidate = join(dir, `${name}.cmd`);
      if (existsSync(cmdCandidate)) {
        return cmdCandidate;
      }
    }
  }

  return undefined;
}

function resolveExecutable(command: string, cwd: string): string | undefined {
  if (command.includes('/') || command.includes('\\')) {
    const fullPath = isAbsolute(command) ? command : resolve(cwd, command);
    return existsSync(fullPath) ? fullPath : undefined;
  }

  return findExecutableOnPath(command, cwd);
}

function unwrapLauncherTarget(
  target: ServerTarget,
  cwd: string = process.cwd(),
): UnwrappedCommand | undefined {
  if (!target.command) {
    return undefined;
  }

  const command = target.command.split('/').pop()?.toLowerCase() ?? target.command.toLowerCase();
  const args = target.args ?? [];
  let wrappedCommand: string | undefined;
  let wrappedArgs: string[] = [];

  if (command === 'npx' || command === 'bunx' || command === 'uvx' || command === 'pipx') {
    const firstRunnableIndex = args.findIndex((arg) => !arg.startsWith('-'));
    if (firstRunnableIndex >= 0) {
      wrappedCommand = args[firstRunnableIndex];
      wrappedArgs = args.slice(firstRunnableIndex + 1);
    }
  } else if (command === 'npm' && args[0] === 'exec' && args[1]) {
    wrappedCommand = args[1];
    wrappedArgs = args.slice(2);
  } else if ((command === 'pnpm' || command === 'yarn') && args[0] === 'dlx' && args[1]) {
    wrappedCommand = args[1];
    wrappedArgs = args.slice(2);
  } else if (command === 'bun' && args[0] === 'x' && args[1]) {
    wrappedCommand = args[1];
    wrappedArgs = args.slice(2);
  }

  if (!wrappedCommand) {
    return undefined;
  }

  const resolvedCommand = resolveExecutable(wrappedCommand, cwd);
  if (!resolvedCommand) {
    return undefined;
  }

  return {
    command: resolvedCommand,
    args: wrappedArgs,
    originalLauncher: target.command,
  };
}

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

export function resolveRuntimeTarget(
  target: ServerTarget,
  cwd: string = process.cwd(),
): ServerTarget | undefined {
  if (!target.command) {
    return undefined;
  }

  const launcher = detectUnsupportedLauncher(target);
  if (!launcher) {
    return target;
  }

  const unwrapped = unwrapLauncherTarget(target, cwd);
  if (!unwrapped) {
    return undefined;
  }

  return {
    ...target,
    command: unwrapped.command,
    args: unwrapped.args,
  };
}

export function assessRuntimeSupport(
  target?: ServerTarget,
  cwd: string = process.cwd(),
): RuntimeSupportResult {
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

  const resolvedTarget = resolveRuntimeTarget(target, cwd);
  if (resolvedTarget) {
    const launcher = detectUnsupportedLauncher(target);
    if (!launcher) {
      return {
        status: 'supported',
        detail:
          'Runtime sandbox coverage is available for this target because it uses a stable local stdio launch command.',
      };
    }

    return {
      status: 'supported',
      detail:
        `Runtime sandbox coverage is available for this target by executing the locally installed underlying command directly instead of the launcher "${launcher}".`,
      launcher,
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
