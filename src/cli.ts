import { program } from 'commander';
import { run } from './runner.js';
import { printResults } from './reporter.js';
import type { ServerTarget, RunOptions, Severity } from './types.js';

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

program
  .name('mcp-certify')
  .version('0.1.0')
  .description('Testing and certification for MCP servers')
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
  .option('--sandbox', 'Run server in sandbox mode')
  .action(async (commandParts: string[], options, command) => {
    if (!commandParts.length && !options.url) {
      program.help();
      return;
    }

    const target: ServerTarget = {
      timeout: parseInt(options.timeout, 10),
    };

    if (options.url) {
      target.url = options.url;
    } else {
      target.command = commandParts[0];
      target.args = commandParts.slice(1);
    }

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
