import chalk from 'chalk';
import type { CertifyResult, TestResult, SuiteResult } from './types.js';

const SYMBOLS: Record<string, string> = {
  pass: chalk.green('✓'),
  fail: chalk.red('✗'),
  warn: chalk.yellow('⚠'),
  skip: chalk.dim('○'),
  error: chalk.red('!'),
};

function scoreColor(score: number): (text: string) => string {
  if (score >= 80) return chalk.green;
  if (score >= 50) return chalk.yellow;
  return chalk.red;
}

function bar(score: number, width: number = 20): string {
  const filled = Math.round((score / 100) * width);
  const empty = width - filled;
  const color = score >= 80 ? chalk.green : score >= 50 ? chalk.yellow : chalk.red;
  return color('█'.repeat(filled)) + chalk.dim('░'.repeat(empty));
}

function formatDuration(ms: number | undefined): string {
  if (ms === undefined) return '';
  return chalk.dim(` ${ms}ms`);
}

function printTest(test: TestResult): void {
  const symbol = SYMBOLS[test.status] ?? '?';
  const msg = test.message ? chalk.dim(` ${test.message}`) : '';
  // Don't double-print duration if message already contains it
  const dur = test.message && /\d+ms/.test(test.message) ? '' : formatDuration(test.duration);

  console.log(`  ${symbol} ${test.name}${msg}${dur}`);

  if (test.details) {
    for (const line of test.details.split('\n')) {
      console.log(`    ${chalk.dim(line)}`);
    }
  }
}

function printSuite(suite: SuiteResult): void {
  const color = scoreColor(suite.score);
  console.log();
  console.log(`${chalk.bold(suite.name)}${' '.repeat(Math.max(1, 48 - suite.name.length))}${color(String(suite.score))}`);

  for (const test of suite.tests) {
    printTest(test);
  }
}

export function printResults(result: CertifyResult): void {
  console.log();
  console.log(chalk.bold('mcp-certify') + chalk.dim(' v0.1.0'));
  console.log();

  // Server info
  if (result.server) {
    console.log(
      `  Server: ${chalk.bold(result.server.name)} ${chalk.dim('v' + result.server.version)}`,
    );
  }

  // Suites
  for (const suite of result.suites) {
    printSuite(suite);
  }

  // Overall score
  console.log();
  console.log(chalk.dim('─'.repeat(52)));

  const color = scoreColor(result.score);
  console.log(`${chalk.bold('Score:')} ${color(chalk.bold(String(result.score)))}${chalk.dim('/100')}`);

  console.log(chalk.dim('─'.repeat(52)));

  // Breakdown bars
  for (const { name, score } of result.breakdown) {
    const padded = name.padEnd(14);
    console.log(`  ${padded}${String(score).padStart(3)}  ${bar(score)}`);
  }

  console.log();
}
