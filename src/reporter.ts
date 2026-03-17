import chalk from 'chalk';
import type { CertifyReport, Finding, SuiteResult, Severity } from './types.js';
import { TOOL_VERSION } from './version.js';

const SEVERITY_SYMBOLS: Record<Severity, string> = {
  critical: chalk.red('\u25cf'),
  high: chalk.red('\u25b2'),
  medium: chalk.yellow('\u25a0'),
  low: chalk.dim('\u25aa'),
  info: chalk.dim('\u25cb'),
};

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
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
  return color('\u2588'.repeat(filled)) + chalk.dim('\u2591'.repeat(empty));
}

function printFinding(finding: Finding): void {
  const symbol = SEVERITY_SYMBOLS[finding.severity];
  const desc = finding.severity !== 'info' && finding.description
    ? chalk.dim(` ${finding.description}`)
    : '';
  console.log(`  ${symbol} ${finding.title}${desc}`);
}

function printSuite(suite: SuiteResult): void {
  const color = scoreColor(suite.score);
  console.log();
  console.log(
    `${chalk.bold(suite.name)}${' '.repeat(Math.max(1, 48 - suite.name.length))}${color(String(suite.score))}`,
  );

  if (suite.evidence.coverage && suite.evidence.coverage.status !== 'full') {
    console.log(
      `  ${chalk.yellow('!')} Runtime coverage: ${chalk.yellow(suite.evidence.coverage.status.replaceAll('_', ' '))}${suite.evidence.coverage.detail ? chalk.dim(` ${suite.evidence.coverage.detail}`) : ''}`,
    );
  }

  // Group findings by severity, sorted by severity order
  const grouped = new Map<Severity, Finding[]>();
  for (const finding of suite.findings) {
    const list = grouped.get(finding.severity) ?? [];
    list.push(finding);
    grouped.set(finding.severity, list);
  }

  const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  for (const sev of severities) {
    const items = grouped.get(sev);
    if (!items || items.length === 0) continue;
    for (const finding of items) {
      printFinding(finding);
    }
  }

  if (suite.certificationBlockers.length > 0) {
    console.log(chalk.red(`  ${suite.certificationBlockers.length} certification blocker(s)`));
  }
}

export function printResults(result: CertifyReport): void {
  console.log();
  console.log(chalk.bold('mcp-certify') + chalk.dim(` v${TOOL_VERSION}`));
  console.log();

  // Server info
  if (result.server) {
    console.log(
      `  Server: ${chalk.bold(result.server.name)} ${chalk.dim('v' + result.server.version)}`,
    );
  }

  if (result.notes && result.notes.length > 0) {
    for (const note of result.notes) {
      console.log(`  Note: ${chalk.yellow(note)}`);
    }
  }

  // Certification decision — prominent
  console.log();
  if (result.decision === 'pass') {
    console.log(chalk.green.bold('  CERTIFIED \u2713'));
  } else {
    console.log(chalk.red.bold('  CERTIFICATION FAILED \u2717'));
  }

  // Blockers section
  if (result.blockers.length > 0) {
    console.log();
    console.log(chalk.red.bold('  Blockers:'));
    for (const blocker of result.blockers) {
      console.log(`    ${chalk.red('\u2717')} ${blocker.reason} ${chalk.dim(`[${blocker.gate}]`)}`);
    }
  }

  // Suites
  for (const suite of result.suites) {
    printSuite(suite);
  }

  // Overall score (secondary)
  console.log();
  console.log(chalk.dim('\u2500'.repeat(52)));

  const color = scoreColor(result.score);
  console.log(
    `${chalk.bold('Score:')} ${color(chalk.bold(String(result.score)))}${chalk.dim('/100')}`,
  );

  console.log(chalk.dim('\u2500'.repeat(52)));

  // Breakdown bars
  for (const { name, score } of result.breakdown) {
    const padded = name.padEnd(14);
    console.log(`  ${padded}${String(score).padStart(3)}  ${bar(score)}`);
  }

  console.log();
}
