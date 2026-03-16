import { program } from 'commander';
import { run } from './runner.js';
import { printResults } from './reporter.js';
import { runDoctor, runSetup, type PreflightReport } from './preflight.js';
import type { AuthConfig, ServerTarget, RunOptions, Severity } from './types.js';

function collectValues(value: string, previous: string[] = []): string[] {
  previous.push(value);
  return previous;
}

function setIfExplicit<T extends object, K extends keyof T>(
  target: Partial<T>,
  key: K,
  value: T[K],
  source: string,
): void {
  if (source === 'cli') {
    target[key] = value;
  }
}

function parseNameValuePairs(entries: string[], separator: string): Array<{ key: string; value: string }> {
  return entries.map((entry) => {
    const index = entry.indexOf(separator);
    if (index <= 0 || index === entry.length - 1) {
      throw new Error(`Expected NAME${separator}VALUE format, received "${entry}"`);
    }

    return {
      key: entry.slice(0, index),
      value: entry.slice(index + 1),
    };
  });
}

function buildAuthConfig(options: {
  bearerToken?: string;
  basicUser?: string;
  basicPass?: string;
  header?: string[];
  authEnv?: string[];
  authRequired?: boolean;
}): AuthConfig | undefined {
  const auth: AuthConfig = {};

  if (options.bearerToken) {
    auth.bearerToken = options.bearerToken;
  }

  if (options.basicUser || options.basicPass) {
    if (!options.basicUser || !options.basicPass) {
      throw new Error('Both --basic-user and --basic-pass are required for basic auth');
    }
    auth.basic = {
      username: options.basicUser,
      password: options.basicPass,
    };
  }

  if ((options.header ?? []).length > 0) {
    auth.headers = parseNameValuePairs(options.header ?? [], ':').map(({ key, value }) => ({
      name: key,
      value,
    }));
  }

  if ((options.authEnv ?? []).length > 0) {
    auth.env = Object.fromEntries(
      parseNameValuePairs(options.authEnv ?? [], '=').map(({ key, value }) => [key, value]),
    );
  }

  if (options.authRequired) {
    if (
      !auth.bearerToken &&
      !auth.basic &&
      !(auth.headers && auth.headers.length > 0) &&
      !(auth.env && Object.keys(auth.env).length > 0)
    ) {
      throw new Error('--auth-required must be used with --bearer-token, --basic-user/--basic-pass, --header, or --auth-env');
    }
    auth.required = true;
  }

  return Object.keys(auth).length > 0 ? auth : undefined;
}

function buildTarget(commandParts: string[], url?: string, timeout?: string): ServerTarget {
  const target: ServerTarget = {
    timeout: parseInt(timeout ?? '10000', 10),
  };

  if (url) {
    target.url = url;
  } else if (commandParts.length > 0) {
    target.command = commandParts[0];
    target.args = commandParts.slice(1);
  }

  return target;
}

function printPreflight(report: PreflightReport): void {
  const icon = (status: 'pass' | 'warn' | 'fail'): string => {
    switch (status) {
      case 'pass':
        return 'PASS';
      case 'warn':
        return 'WARN';
      case 'fail':
        return 'FAIL';
    }
  };

  console.log();
  console.log(`mcp-certify preflight`);
  console.log();
  for (const check of report.checks) {
    console.log(`  [${icon(check.status)}] ${check.title}`);
    console.log(`        ${check.detail}`);
    if (check.remediation) {
      console.log(`        ${check.remediation}`);
    }
  }
  console.log();
}

program.enablePositionalOptions();

program
  .command('doctor')
  .description('Check local environment readiness and runtime coverage support')
  .passThroughOptions()
  .argument('[command...]', 'Optional server command and arguments to evaluate for runtime support')
  .option('--url <url>', 'Optional server URL to evaluate for runtime support')
  .option('--timeout <ms>', 'Optional timeout context for the target', '10000')
  .option('--json', 'Output preflight results as JSON')
  .action(async (commandParts: string[], options) => {
    const target =
      commandParts.length > 0 || options.url
        ? buildTarget(commandParts, options.url, options.timeout)
        : undefined;

    const report = await runDoctor(target);

    if (options.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      printPreflight(report);
    }

    process.exit(report.ready ? 0 : 1);
  });

program
  .command('setup')
  .description('Prepare optional local dependencies for cleaner first-run scans')
  .option('--json', 'Output setup results as JSON')
  .action(async (options) => {
    const report = await runSetup();

    if (options.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      printPreflight(report);
    }

    process.exit(report.ready ? 0 : 1);
  });

program
  .name('mcp-certify')
  .version('0.1.0')
  .description('Testing and certification for MCP servers');

program
  .command('scan', { isDefault: true })
  .description('Test and certify an MCP server')
  .passThroughOptions()
  .argument('[command...]', 'Server command and arguments (stdio mode)')
  .option('--url <url>', 'Server URL (HTTP mode)')
  .option('--timeout <ms>', 'Timeout per operation in milliseconds', '10000')
  .option('--json', 'Output results as JSON')
  .option('--call-tools', 'Actually call tools during testing (may have side effects)')
  .option('--profile <name>', 'Certification profile to use')
  .option('--artifacts-dir <path>', 'Directory for evidence and artifacts output')
  .option('--fail-on <severity>', 'Override: fail on this severity or above (critical|high|medium|low|info)')
  .option('--baseline <path>', 'Diff against a saved manifest baseline')
  .option('--policy <path>', 'Path to a custom OPA/Rego policy file')
  .option('--allow-host <host>', 'Allow outbound access to this host in policy checks', collectValues, [])
  .option('--deny-host <host>', 'Deny outbound access to this host in policy checks', collectValues, [])
  .option('--bearer-token <token>', 'Bearer token for authenticated HTTP MCP servers')
  .option('--basic-user <username>', 'Basic auth username for authenticated HTTP MCP servers')
  .option('--basic-pass <password>', 'Basic auth password for authenticated HTTP MCP servers')
  .option('--header <name:value>', 'Custom HTTP header to send during MCP requests', collectValues, [])
  .option('--auth-env <KEY=VALUE>', 'Environment variable to inject for authenticated stdio servers', collectValues, [])
  .option('--auth-required', 'Assert that the server should reject unauthenticated access')
  .option('--sandbox', 'Run server in sandbox mode')
  .action(async (commandParts: string[], options, command) => {
    if (!commandParts.length && !options.url) {
      program.help();
      return;
    }

    const target = buildTarget(commandParts, options.url, options.timeout);

    const runOptions: Partial<RunOptions> = {
      timeout: target.timeout,
    };
    setIfExplicit(runOptions, 'callTools', options.callTools, command.getOptionValueSource('callTools'));
    setIfExplicit(runOptions, 'profile', options.profile, command.getOptionValueSource('profile'));
    setIfExplicit(runOptions, 'artifactsDir', options.artifactsDir, command.getOptionValueSource('artifactsDir'));
    setIfExplicit(
      runOptions,
      'failOn',
      options.failOn as Severity | undefined,
      command.getOptionValueSource('failOn'),
    );
    setIfExplicit(runOptions, 'sandbox', options.sandbox, command.getOptionValueSource('sandbox'));
    setIfExplicit(runOptions, 'baselinePath', options.baseline, command.getOptionValueSource('baseline'));
    setIfExplicit(runOptions, 'policyPath', options.policy, command.getOptionValueSource('policy'));

    if ((options.allowHost as string[]).length > 0) {
      runOptions.allowHosts = options.allowHost as string[];
    }
    if ((options.denyHost as string[]).length > 0) {
      runOptions.denyHosts = options.denyHost as string[];
    }

    const auth = buildAuthConfig({
      bearerToken: options.bearerToken,
      basicUser: options.basicUser,
      basicPass: options.basicPass,
      header: options.header as string[],
      authEnv: options.authEnv as string[],
      authRequired: options.authRequired,
    });
    if (auth) {
      runOptions.auth = auth;
    }

    try {
      const result = await run(target, runOptions);

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        printResults(result);
      }

      process.exit(result.decision === 'pass' ? 0 : 1);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`\nFatal: ${msg}\n`);
      process.exit(2);
    }
  });

program.parse();
