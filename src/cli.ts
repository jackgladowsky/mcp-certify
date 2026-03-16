import { program } from 'commander';
import { run } from './runner.js';
import { printResults } from './reporter.js';
import type { ServerTarget, RunOptions } from './types.js';

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
  .option('--sandbox', 'Run server in sandbox mode')
  .action(async (commandParts: string[], options) => {
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

    const runOptions: RunOptions = {
      callTools: options.callTools,
      timeout: target.timeout,
      profile: options.profile,
      artifactsDir: options.artifactsDir,
      failOn: options.failOn,
      sandbox: options.sandbox,
    };

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
