import { program } from 'commander';
import { run } from './runner.js';
import { printResults } from './reporter.js';
import type { ServerTarget } from './types.js';

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

    try {
      const result = await run(target, {
        callTools: options.callTools,
        timeout: target.timeout,
      });

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        printResults(result);
      }

      process.exit(result.score >= 50 ? 0 : 1);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`\nFatal: ${msg}\n`);
      process.exit(2);
    }
  });

program.parse();
