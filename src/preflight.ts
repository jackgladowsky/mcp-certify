import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { connect } from './connect.js';
import { assessRuntimeSupport } from './runtime/support.js';
import { isTrivyDatabaseReady, isTrivyInstalled, warmTrivyDatabase } from './integrations/trivy.js';
import { withTimeout } from './utils.js';
import type { ServerTarget } from './types.js';

const execFileAsync = promisify(execFile);

export type PreflightStatus = 'pass' | 'warn' | 'fail';

export interface PreflightCheck {
  id: string;
  title: string;
  status: PreflightStatus;
  detail: string;
  remediation?: string;
}

export interface PreflightReport {
  ready: boolean;
  checks: PreflightCheck[];
}

function parseNodeMajor(version: string): number {
  const normalized = version.startsWith('v') ? version.slice(1) : version;
  return Number.parseInt(normalized.split('.')[0] ?? '0', 10);
}

async function hasCommand(command: string, args: string[] = ['--version']): Promise<boolean> {
  try {
    await execFileAsync(command, args, { timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
}

async function isOpaInstalled(): Promise<boolean> {
  return hasCommand('opa', ['version']);
}

async function canImportMcpValidator(pythonCommand: string): Promise<boolean> {
  try {
    await execFileAsync(
      pythonCommand,
      ['-c', 'import importlib.util,sys; sys.exit(0 if importlib.util.find_spec("mcp_testing") else 1)'],
      { timeout: 10_000 },
    );
    return true;
  } catch {
    return false;
  }
}

async function isMcpValidatorInstalled(): Promise<boolean> {
  if (await hasCommand('mcp-validator', ['--help'])) {
    return true;
  }

  if (await canImportMcpValidator('python3')) {
    return true;
  }

  if (await canImportMcpValidator('python')) {
    return true;
  }

  return false;
}

async function installWithBrew(formula: string): Promise<void> {
  await execFileAsync('brew', ['install', formula], {
    timeout: 600_000,
    maxBuffer: 10 * 1024 * 1024,
  });
}

async function installMcpValidator(): Promise<void> {
  const packageRef = 'git+https://github.com/Janix-ai/mcp-validator.git';

  if (await hasCommand('pipx', ['--version'])) {
    await execFileAsync('pipx', ['install', packageRef], {
      timeout: 600_000,
      maxBuffer: 10 * 1024 * 1024,
    });
    return;
  }

  if (await hasCommand('python3', ['--version'])) {
    await execFileAsync('python3', ['-m', 'pip', 'install', '--user', packageRef], {
      timeout: 600_000,
      maxBuffer: 10 * 1024 * 1024,
    });
    return;
  }

  if (await hasCommand('python', ['--version'])) {
    await execFileAsync('python', ['-m', 'pip', 'install', '--user', packageRef], {
      timeout: 600_000,
      maxBuffer: 10 * 1024 * 1024,
    });
    return;
  }

  throw new Error('No supported installer found for mcp-validator (expected pipx, python3, or python).');
}

async function ensureOptionalDependency(options: {
  id: string;
  title: string;
  checkInstalled: () => Promise<boolean>;
  install?: () => Promise<void>;
  installRemediation: string;
  successDetail: string;
  missingDetail: string;
}): Promise<PreflightCheck> {
  if (await options.checkInstalled()) {
    return {
      id: options.id,
      title: options.title,
      status: 'pass',
      detail: options.successDetail,
    };
  }

  if (!options.install) {
    return {
      id: options.id,
      title: options.title,
      status: 'warn',
      detail: options.missingDetail,
      remediation: options.installRemediation,
    };
  }

  try {
    await options.install();
    if (await options.checkInstalled()) {
      return {
        id: options.id,
        title: options.title,
        status: 'pass',
        detail: `${options.title} installed and verified successfully.`,
      };
    }

    return {
      id: options.id,
      title: options.title,
      status: 'warn',
      detail: `${options.title} install command completed, but verification still failed.`,
      remediation: options.installRemediation,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      id: options.id,
      title: options.title,
      status: 'warn',
      detail: `Unable to install ${options.title}: ${message}`,
      remediation: options.installRemediation,
    };
  }
}

export async function runDoctor(target?: ServerTarget): Promise<PreflightReport> {
  const checks: PreflightCheck[] = [];

  const nodeMajor = parseNodeMajor(process.version);
  if (nodeMajor >= 20) {
    checks.push({
      id: 'node-version',
      title: 'Node.js version',
      status: 'pass',
      detail: `Detected ${process.version}; Node.js 20+ requirement satisfied.`,
    });
  } else {
    checks.push({
      id: 'node-version',
      title: 'Node.js version',
      status: 'fail',
      detail: `Detected ${process.version}; mcp-certify requires Node.js 20 or newer.`,
      remediation: 'Upgrade Node.js before running certification scans.',
    });
  }

  const trivyInstalled = await isTrivyInstalled();
  if (!trivyInstalled) {
    checks.push({
      id: 'trivy-installed',
      title: 'Trivy installation',
      status: 'warn',
      detail: 'Trivy is not installed; supply-chain scanning will be unavailable.',
      remediation: 'Install Trivy or run `mcp-certify setup` after installing it.',
    });
  } else {
    checks.push({
      id: 'trivy-installed',
      title: 'Trivy installation',
      status: 'pass',
      detail: 'Trivy is installed and available on PATH.',
    });

    const dbReady = await isTrivyDatabaseReady();
    checks.push(
      dbReady
        ? {
            id: 'trivy-db',
            title: 'Trivy vulnerability database',
            status: 'pass',
            detail: 'Trivy vulnerability database is ready for offline scans.',
          }
        : {
            id: 'trivy-db',
            title: 'Trivy vulnerability database',
            status: 'warn',
            detail: 'Trivy database is not warmed yet; first supply-chain scans may fail or be noisy.',
            remediation: 'Run `mcp-certify setup` to warm the Trivy database before scanning.',
          },
    );
  }

  checks.push(
    (await isOpaInstalled())
      ? {
          id: 'opa-installed',
          title: 'OPA installation',
          status: 'pass',
          detail: 'OPA is installed. Custom Rego policy evaluation is available.',
        }
      : {
          id: 'opa-installed',
          title: 'OPA installation',
          status: 'warn',
          detail: 'OPA is not installed. Built-in JS policy checks still work, but custom Rego execution is unavailable.',
          remediation: 'Install OPA only if you need custom policy evaluation.',
        },
  );

  checks.push(
    (await isMcpValidatorInstalled())
      ? {
          id: 'mcp-validator-installed',
          title: 'mcp-validator installation',
          status: 'pass',
          detail: 'mcp-validator is installed for optional manual protocol cross-checks.',
        }
      : {
          id: 'mcp-validator-installed',
          title: 'mcp-validator installation',
          status: 'warn',
          detail: 'mcp-validator is not installed. Default mcp-certify scans still use the built-in protocol suite.',
          remediation:
            'Install Janix mcp-validator only if you want an extra manual protocol cross-check outside the default scan path.',
        },
  );

  const runtimeSupport = assessRuntimeSupport(target);
  checks.push({
    id: 'runtime-support',
    title: 'Runtime sandbox support',
    status:
      runtimeSupport.status === 'supported'
        ? 'pass'
        : runtimeSupport.status === 'unsupported_transport'
          ? 'warn'
          : 'warn',
    detail: runtimeSupport.detail,
    remediation:
      runtimeSupport.status === 'unsupported_launcher'
        ? 'Build and run the server directly before using --sandbox.'
        : runtimeSupport.status === 'unsupported_transport'
          ? 'Use runtime analysis only with local stdio servers.'
          : undefined,
  });

  if (target) {
    try {
      const timeout = target.timeout ?? 10_000;
      const { client } = await withTimeout(connect(target), timeout, 'doctor probe');
      const serverVersion = client.getServerVersion();
      const serverLabel = serverVersion
        ? `${serverVersion.name} v${serverVersion.version}`
        : 'server responded without version metadata';
      checks.push({
        id: 'target-probe',
        title: 'Target connectivity probe',
        status: 'pass',
        detail: `Connected successfully to ${serverLabel}.`,
      });
      await client.close().catch(() => undefined);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      checks.push({
        id: 'target-probe',
        title: 'Target connectivity probe',
        status: 'fail',
        detail: `Failed to connect to the target server: ${message}`,
        remediation:
          'Verify the server is running, reachable, and supplied with any required auth before scanning.',
      });
    }
  }

  return {
    ready: checks.every((check) => check.status !== 'fail'),
    checks,
  };
}

export async function runSetup(): Promise<PreflightReport> {
  const checks: PreflightCheck[] = [];

  const nodeMajor = parseNodeMajor(process.version);
  checks.push(
    nodeMajor >= 20
      ? {
          id: 'node-version',
          title: 'Node.js version',
          status: 'pass',
          detail: `Detected ${process.version}; Node.js 20+ requirement satisfied.`,
        }
      : {
          id: 'node-version',
          title: 'Node.js version',
          status: 'fail',
          detail: `Detected ${process.version}; mcp-certify requires Node.js 20 or newer.`,
          remediation: 'Upgrade Node.js before running setup or certification scans.',
        },
  );

  checks.push(
    await ensureOptionalDependency({
      id: 'trivy-installed',
      title: 'Trivy installation',
      checkInstalled: isTrivyInstalled,
      install: (await hasCommand('brew', ['--version'])) ? () => installWithBrew('trivy') : undefined,
      installRemediation:
        'Install Trivy manually from https://trivy.dev/latest/getting-started/installation/ if Homebrew is unavailable.',
      successDetail: 'Trivy is installed and available on PATH.',
      missingDetail: 'Trivy is not installed. Supply-chain scanning will remain unavailable until it is installed.',
    }),
  );

  if (await isTrivyInstalled()) {
    try {
      await warmTrivyDatabase();
      checks.push({
        id: 'trivy-db',
        title: 'Trivy vulnerability database',
        status: 'pass',
        detail: 'Trivy vulnerability database warmed successfully.',
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      checks.push({
        id: 'trivy-db',
        title: 'Trivy vulnerability database',
        status: 'warn',
        detail: `Failed to warm Trivy database: ${msg}`,
        remediation: 'Check network access and rerun `mcp-certify setup` before relying on supply-chain scans.',
      });
    }
  }

  checks.push(
    await ensureOptionalDependency({
      id: 'opa-installed',
      title: 'OPA installation',
      checkInstalled: isOpaInstalled,
      install: (await hasCommand('brew', ['--version'])) ? () => installWithBrew('opa') : undefined,
      installRemediation:
        'Install OPA manually from https://www.openpolicyagent.org/docs/latest/#running-opa if Homebrew is unavailable.',
      successDetail: 'OPA is installed. Custom Rego policy evaluation is available.',
      missingDetail: 'OPA is not installed. Custom Rego policy evaluation will remain unavailable.',
    }),
  );

  checks.push(
    await ensureOptionalDependency({
      id: 'mcp-validator-installed',
      title: 'mcp-validator installation',
      checkInstalled: isMcpValidatorInstalled,
      install: installMcpValidator,
      installRemediation:
        'Install Janix mcp-validator with pipx or python -m pip if you want optional manual protocol cross-checks.',
      successDetail: 'mcp-validator is installed for optional manual protocol cross-checks.',
      missingDetail: 'mcp-validator is not installed. This does not affect the default built-in protocol suite.',
    }),
  );

  checks.push({
    id: 'runtime-support',
    title: 'Runtime sandbox support',
    status: 'pass',
    detail:
      'Runtime sandbox coverage is experimental and intended for stable local stdio launches such as `node dist/index.js` or `python path/to/server.py`.',
  });

  return {
    ready: checks.every((check) => check.status !== 'fail'),
    checks,
  };
}
