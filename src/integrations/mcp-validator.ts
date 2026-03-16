import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Finding, Severity } from '../types/index.js';

const execFileAsync = promisify(execFile);

interface ValidatorResult {
  findings: Finding[];
  rawOutput: string;
}

/**
 * Check whether the mcp-validator Python tool is available.
 */
async function isInstalled(): Promise<boolean> {
  try {
    await execFileAsync('python3', ['-m', 'mcp_testing', '--help'], {
      timeout: 10_000,
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Map a validator test status to our Severity type.
 * Tests that pass become "info", failures become "high", and others
 * are mapped based on available context.
 */
function mapSeverity(passed: boolean): Severity {
  return passed ? 'info' : 'high';
}

/**
 * Parse the compliance report output (JSON) from mcp-validator into findings.
 */
function parseReport(reportJson: string, rawText: string): Finding[] {
  const findings: Finding[] = [];
  let counter = 1;

  try {
    const report = JSON.parse(reportJson) as Record<string, unknown>;

    // The compliance report typically contains test results grouped by category
    const results = (report['results'] ?? report['tests'] ?? report['checks']) as
      | Record<string, unknown>[]
      | undefined;

    if (Array.isArray(results)) {
      for (const result of results) {
        const name = String(result['name'] ?? result['test'] ?? `Test ${counter}`);
        const passed =
          result['status'] === 'passed' ||
          result['status'] === 'pass' ||
          result['passed'] === true;
        const description = String(
          result['message'] ?? result['description'] ?? result['detail'] ?? '',
        );

        const id = `MCPVAL-${String(counter).padStart(3, '0')}`;
        findings.push({
          id,
          title: name,
          severity: mapSeverity(passed),
          category: 'protocol',
          description: description || (passed ? 'Test passed' : 'Test failed'),
          evidence: result['output'] != null ? String(result['output']) : undefined,
          source: 'mcp-validator',
        });
        counter++;
      }
    }

    // Handle summary-level fields if results array was absent or empty
    if (findings.length === 0 && typeof report === 'object') {
      // Try to extract section-level results (e.g. { "initialization": { ... } })
      for (const [section, value] of Object.entries(report)) {
        if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
          const sectionObj = value as Record<string, unknown>;
          const passed =
            sectionObj['status'] === 'passed' ||
            sectionObj['status'] === 'pass' ||
            sectionObj['passed'] === true;

          const id = `MCPVAL-${String(counter).padStart(3, '0')}`;
          findings.push({
            id,
            title: `${section}`,
            severity: mapSeverity(passed),
            category: 'protocol',
            description: String(sectionObj['message'] ?? sectionObj['description'] ?? section),
            source: 'mcp-validator',
          });
          counter++;
        }
      }
    }
  } catch {
    // If JSON parsing fails, try to extract info from raw text
    findings.push({
      id: 'MCPVAL-001',
      title: 'Validator output parsing failed',
      severity: 'medium',
      category: 'protocol',
      description: 'Could not parse mcp-validator JSON output; raw output preserved in evidence.',
      evidence: rawText.slice(0, 2000),
      source: 'mcp-validator',
    });
  }

  return findings;
}

/**
 * Run the mcp-validator compliance report against a target MCP server.
 *
 * If mcp-validator is not installed, returns a single info finding indicating
 * that built-in checks will be used instead.
 */
export async function runMcpValidator(
  serverCommand: string,
  args: string[],
  timeout: number,
): Promise<ValidatorResult> {
  // Check installation
  if (!(await isInstalled())) {
    return {
      findings: [
        {
          id: 'MCPVAL-000',
          title: 'mcp-validator not installed',
          severity: 'info',
          category: 'protocol',
          description:
            'mcp-validator not installed, using built-in checks. Install with: pip install mcp-testing',
          source: 'mcp-validator',
        },
      ],
      rawOutput: '',
    };
  }

  // Create temp directory for output
  const outputDir = await mkdtemp(join(tmpdir(), 'mcp-certify-validator-'));

  try {
    // Build the full server command string
    const fullCommand = [serverCommand, ...args].join(' ');

    const { stdout, stderr } = await execFileAsync(
      'python3',
      [
        '-m',
        'mcp_testing.scripts.compliance_report',
        '--server-command',
        fullCommand,
        '--protocol-version',
        '2025-03-26',
        '--output-dir',
        outputDir,
      ],
      {
        timeout,
        maxBuffer: 10 * 1024 * 1024, // 10 MB
      },
    );

    const rawOutput = stdout + (stderr ? `\n--- stderr ---\n${stderr}` : '');

    // Try to find and parse the JSON report file from the output directory
    let reportJson = '';
    try {
      const files = await readdir(outputDir);
      const jsonFile = files.find((f) => f.endsWith('.json'));
      if (jsonFile) {
        reportJson = await readFile(join(outputDir, jsonFile), 'utf-8');
      }
    } catch {
      // Output dir may not have files; fall through to stdout parsing
    }

    // If no JSON file found, try parsing stdout directly
    const sourceToParse = reportJson || stdout;
    const findings = parseReport(sourceToParse, rawOutput);

    // If we got no findings at all from the report, add a summary finding
    if (findings.length === 0) {
      findings.push({
        id: 'MCPVAL-001',
        title: 'Validator completed with no parseable results',
        severity: 'info',
        category: 'protocol-compliance',
        description: 'mcp-validator ran successfully but produced no parseable test results.',
        evidence: rawOutput.slice(0, 2000),
        source: 'mcp-validator',
      });
    }

    return { findings, rawOutput };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    const isTimeout = message.includes('timed out') || message.includes('TIMEOUT');

    return {
      findings: [
        {
          id: 'MCPVAL-ERR',
          title: isTimeout ? 'Validator timed out' : 'Validator execution failed',
          severity: 'medium',
          category: 'protocol',
          description: `mcp-validator failed: ${message}`,
          source: 'mcp-validator',
          remediation: isTimeout
            ? 'Increase the timeout or check if the server is responding'
            : 'Verify mcp-validator is correctly installed and the server command is valid',
        },
      ],
      rawOutput: message,
    };
  } finally {
    // Clean up temp directory
    try {
      await rm(outputDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  }
}
