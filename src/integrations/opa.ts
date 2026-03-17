/**
 * OPA (Open Policy Agent) integration for mcp-certify.
 *
 * Evaluates MCP server metadata against security policies defined in Rego.
 * Falls back to a built-in JavaScript implementation when the OPA binary
 * is not installed, so the tool always works out of the box.
 */

import { execFile } from 'node:child_process';
import { writeFile, unlink } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import type { Finding, Severity } from '../types/index.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface PolicyInput {
  tools: ToolMeta[];
  resources: ResourceMeta[];
  prompts: PromptMeta[];
  capabilities: Record<string, unknown>;
}

export interface PolicyOptions {
  /** Path to a custom .rego policy file. Uses built-in default when omitted. */
  policyPath?: string;
  /** Additional hosts to allow in network checks. */
  allowHosts?: string[];
  /** Additional hosts to explicitly deny. */
  denyHosts?: string[];
  /** Timeout in ms for the OPA binary call. Default: 15 000. */
  timeout?: number;
}

export interface PolicyResult {
  findings: Finding[];
  rawOutput: string;
}

// ---------------------------------------------------------------------------
// Internal types for tool / resource / prompt metadata
// ---------------------------------------------------------------------------

interface ToolMeta {
  name: string;
  description?: string;
  inputSchema?: {
    type?: string;
    properties?: Record<string, { description?: string; [k: string]: unknown }>;
    [k: string]: unknown;
  };
  annotations?: {
    readOnlyHint?: boolean;
    [k: string]: unknown;
  };
  [k: string]: unknown;
}

interface ResourceMeta {
  name: string;
  [k: string]: unknown;
}

interface PromptMeta {
  name: string;
  [k: string]: unknown;
}

interface Violation {
  msg: string;
  severity: string;
  rule: string;
}

// ---------------------------------------------------------------------------
// Rule-to-finding-id mapping
// ---------------------------------------------------------------------------

const RULE_ID_MAP: Record<string, string> = {
  'sensitive-paths': 'POLICY-001',
  'unapproved-network': 'POLICY-002',
  'undeclared-mutations': 'POLICY-003',
  'command-execution': 'POLICY-004',
  'missing-schema': 'POLICY-005',
};

const RULE_TITLE_MAP: Record<string, string> = {
  'sensitive-paths': 'Sensitive path reference detected',
  'unapproved-network': 'Unapproved network host reference',
  'undeclared-mutations': 'Undeclared mutation capability',
  'command-execution': 'Command execution capability',
  'missing-schema': 'Missing input schema',
};

const RULE_REMEDIATION_MAP: Record<string, string> = {
  'sensitive-paths':
    'Remove references to sensitive file paths from tool descriptions and schemas, or restrict tool access to those paths.',
  'unapproved-network':
    'Restrict network access to approved hosts only. Add required hosts to the allow-list via --allow-host.',
  'undeclared-mutations':
    'Add an explicit readOnlyHint annotation (set to false) on tools that perform mutations.',
  'command-execution':
    'Remove or rename command execution tools. If shell access is required, use a sandboxed execution environment.',
  'missing-schema':
    'Define a JSON Schema (inputSchema) for every tool so that callers can validate inputs.',
};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Evaluate an MCP server's metadata against the security policy.
 *
 * When the OPA binary is available and a custom policy path is provided, the
 * binary is used. Otherwise the built-in JavaScript rule engine evaluates the
 * default rule set — no external dependencies required.
 */
export async function evaluatePolicy(
  input: PolicyInput,
  options?: PolicyOptions,
): Promise<PolicyResult> {
  const opts: Required<PolicyOptions> = {
    policyPath: options?.policyPath ?? '',
    allowHosts: options?.allowHosts ?? [],
    denyHosts: options?.denyHosts ?? [],
    timeout: options?.timeout ?? 15_000,
  };

  // When a custom policy is provided, try the OPA binary first.
  if (opts.policyPath) {
    const opaAvailable = await isOpaInstalled(opts.timeout);
    if (opaAvailable) {
      return evaluateWithOpaBinary(input, opts);
    }
    // Custom policy requested but OPA not installed — warn and fall through.
    const warning: Finding = {
      id: 'POLICY-000',
      title: 'OPA binary not found',
      severity: 'info',
      category: 'runtime-policy',
      description:
        'A custom policy path was provided but the OPA binary is not installed. Falling back to built-in rules. Install OPA to use custom policies: https://www.openpolicyagent.org/docs/latest/#running-opa',
      source: 'opa-integration',
    };
    const builtIn = evaluateBuiltIn(input, opts);
    builtIn.findings.unshift(warning);
    return builtIn;
  }

  // Default: use built-in JavaScript rules (fast, no dependency).
  return evaluateBuiltIn(input, opts);
}

// ---------------------------------------------------------------------------
// OPA binary detection
// ---------------------------------------------------------------------------

async function isOpaInstalled(timeout: number): Promise<boolean> {
  return new Promise((resolve) => {
    const child = execFile('opa', ['version'], { timeout }, (err) => {
      resolve(!err);
    });
    // Swallow stdout/stderr.
    child.stdout?.resume();
    child.stderr?.resume();
  });
}

// ---------------------------------------------------------------------------
// OPA binary evaluation
// ---------------------------------------------------------------------------

async function evaluateWithOpaBinary(
  input: PolicyInput,
  opts: Required<PolicyOptions>,
): Promise<PolicyResult> {
  const id = randomBytes(8).toString('hex');
  const inputPath = join(tmpdir(), `mcp-certify-input-${id}.json`);

  const opaInput: Record<string, unknown> = {
    ...input,
    allow_hosts: opts.allowHosts,
    deny_hosts: opts.denyHosts,
  };

  try {
    await writeFile(inputPath, JSON.stringify(opaInput, null, 2), 'utf-8');

    const rawOutput = await runOpa(opts.policyPath, inputPath, opts.timeout);
    const violations = parseOpaOutput(rawOutput);
    const findings = violationsToFindings(violations);

    return { findings, rawOutput };
  } finally {
    // Best-effort cleanup.
    await unlink(inputPath).catch(() => {});
  }
}

function runOpa(policyPath: string, inputPath: string, timeout: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const args = [
      'eval',
      '-d', policyPath,
      '-i', inputPath,
      '--format', 'json',
      'data.mcpcertify.violations',
    ];

    const child = execFile('opa', args, { timeout }, (err, stdout, stderr) => {
      if (err) {
        reject(new Error(`OPA evaluation failed: ${stderr || err.message}`));
        return;
      }
      resolve(stdout);
    });
    child.stdin?.end();
  });
}

function parseOpaOutput(raw: string): Violation[] {
  try {
    const parsed = JSON.parse(raw);

    // OPA JSON output shape: { result: [{ expressions: [{ value: [...] }] }] }
    const expressions = parsed?.result?.[0]?.expressions;
    if (!Array.isArray(expressions) || expressions.length === 0) {
      return [];
    }
    const value = expressions[0]?.value;
    if (!Array.isArray(value)) {
      return [];
    }
    return value.filter(
      (v: unknown): v is Violation =>
        typeof v === 'object' &&
        v !== null &&
        'msg' in v &&
        'severity' in v &&
        'rule' in v,
    );
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Built-in JavaScript rule engine (no OPA binary required)
// ---------------------------------------------------------------------------

function evaluateBuiltIn(
  input: PolicyInput,
  opts: Required<PolicyOptions>,
): PolicyResult {
  const violations: Violation[] = [];
  const tools = input.tools ?? [];

  for (const tool of tools) {
    checkSensitivePaths(tool, violations);
    checkUnapprovedNetwork(tool, opts, violations);
    checkUndeclaredMutations(tool, violations);
    checkCommandExecution(tool, violations);
    checkMissingSchema(tool, violations);
  }

  const findings = violationsToFindings(violations);
  const rawOutput = JSON.stringify({ violations }, null, 2);
  return { findings, rawOutput };
}

// -- Rule: sensitive paths (high) --

const SENSITIVE_PATHS = ['~/.ssh', '~/.aws', '~/.gnupg', '/etc/passwd', '/etc/shadow', '.env'];

function checkSensitivePaths(tool: ToolMeta, out: Violation[]): void {
  const desc = tool.description ?? '';

  for (const path of SENSITIVE_PATHS) {
    if (desc.includes(path)) {
      out.push({
        msg: `Tool '${tool.name}' references sensitive path '${path}' in description`,
        severity: 'high',
        rule: 'sensitive-paths',
      });
    }
  }

  // Check input schema property descriptions.
  const props = tool.inputSchema?.properties;
  if (props) {
    for (const [propName, propDef] of Object.entries(props)) {
      const propDesc = propDef?.description ?? '';
      for (const path of SENSITIVE_PATHS) {
        if (propDesc.includes(path)) {
          out.push({
            msg: `Tool '${tool.name}' parameter '${propName}' references sensitive path '${path}'`,
            severity: 'high',
            rule: 'sensitive-paths',
          });
        }
      }
    }
  }
}

// -- Rule: unapproved network (high) --

const DEFAULT_APPROVED_HOSTS = ['localhost', '127.0.0.1', 'example.com'];
const URL_REGEX = /https?:\/\/[^\s"')]+/i;

function checkUnapprovedNetwork(
  tool: ToolMeta,
  opts: Required<PolicyOptions>,
  out: Violation[],
): void {
  const desc = tool.description ?? '';

  // Check for URLs that reference non-approved hosts.
  if (URL_REGEX.test(desc)) {
    const approved = new Set([...DEFAULT_APPROVED_HOSTS, ...opts.allowHosts]);
    const isApproved = [...approved].some((host) => desc.includes(host));

    // Only flag if the description has a URL and none of the approved hosts appear.
    if (!isApproved) {
      out.push({
        msg: `Tool '${tool.name}' references unapproved external host in description`,
        severity: 'high',
        rule: 'unapproved-network',
      });
    }
  }

  // Check explicit deny list.
  for (const host of opts.denyHosts) {
    if (desc.includes(host)) {
      out.push({
        msg: `Tool '${tool.name}' references denied host '${host}'`,
        severity: 'high',
        rule: 'unapproved-network',
      });
    }
  }
}

// -- Rule: undeclared mutations (medium) --

const MUTATION_NAME_PATTERNS = [
  'write', 'delete', 'update', 'create', 'modify',
  'remove', 'drop', 'insert', 'put', 'patch', 'set',
];

const MUTATION_DESC_PATTERNS = [
  'will delete', 'will modify', 'will update', 'will create',
  'will remove', 'will overwrite', 'writes to', 'mutates',
];

function checkUndeclaredMutations(tool: ToolMeta, out: Violation[]): void {
  const nameLower = tool.name.toLowerCase();
  const hasMutationAnnotation = tool.annotations?.readOnlyHint === false;

  if (hasMutationAnnotation) return;

  // Check tool name for mutation patterns.
  for (const pattern of MUTATION_NAME_PATTERNS) {
    if (nameLower.includes(pattern)) {
      out.push({
        msg: `Tool '${tool.name}' appears mutation-capable but lacks explicit readOnlyHint annotation`,
        severity: 'medium',
        rule: 'undeclared-mutations',
      });
      return; // One finding per tool for name-based detection.
    }
  }

  // Check description for mutation patterns.
  const descLower = (tool.description ?? '').toLowerCase();
  for (const pattern of MUTATION_DESC_PATTERNS) {
    if (descLower.includes(pattern)) {
      out.push({
        msg: `Tool '${tool.name}' description suggests mutation capability but lacks explicit readOnlyHint annotation`,
        severity: 'medium',
        rule: 'undeclared-mutations',
      });
      return;
    }
  }
}

// -- Rule: command execution (critical) --

const EXEC_EXACT_NAMES = [
  'exec', 'execute', 'eval', 'shell', 'bash', 'cmd',
  'run_command', 'run_shell', 'run_script',
];

const EXEC_PREFIX_ROOTS = ['exec', 'execute', 'eval', 'shell', 'bash', 'cmd'];

function checkCommandExecution(tool: ToolMeta, out: Violation[]): void {
  const nameLower = tool.name.toLowerCase();

  // Exact match.
  if (EXEC_EXACT_NAMES.includes(nameLower)) {
    out.push({
      msg: `Tool '${tool.name}' provides direct command execution capability`,
      severity: 'critical',
      rule: 'command-execution',
    });
    return;
  }

  // Prefix match with separator (e.g. exec_query, shell-run).
  for (const root of EXEC_PREFIX_ROOTS) {
    if (nameLower.startsWith(`${root}_`) || nameLower.startsWith(`${root}-`)) {
      out.push({
        msg: `Tool '${tool.name}' appears to provide command execution capability`,
        severity: 'critical',
        rule: 'command-execution',
      });
      return;
    }
  }
}

// -- Rule: missing schema (medium) --

function checkMissingSchema(tool: ToolMeta, out: Violation[]): void {
  if (!tool.inputSchema) {
    out.push({
      msg: `Tool '${tool.name}' has no input schema defined`,
      severity: 'medium',
      rule: 'missing-schema',
    });
    return;
  }

  // Empty schema: type object with no properties.
  if (
    tool.inputSchema.type === 'object' &&
    !tool.inputSchema.properties
  ) {
    out.push({
      msg: `Tool '${tool.name}' has an empty input schema with no properties`,
      severity: 'medium',
      rule: 'missing-schema',
    });
  }
}

// ---------------------------------------------------------------------------
// Convert violations to Finding[]
// ---------------------------------------------------------------------------

/** Deduplicate violations on message and convert to Finding objects. */
function violationsToFindings(violations: Violation[]): Finding[] {
  // Use a counter per rule to generate stable sub-IDs within each category.
  const ruleCounters: Record<string, number> = {};
  const seenMessages = new Set<string>();
  const findings: Finding[] = [];

  for (const v of violations) {
    // Deduplicate identical messages.
    if (seenMessages.has(v.msg)) continue;
    seenMessages.add(v.msg);

    const rule = v.rule || 'unknown';
    ruleCounters[rule] = (ruleCounters[rule] ?? 0) + 1;

    const baseId = RULE_ID_MAP[rule] ?? 'POLICY-099';
    const subIndex = ruleCounters[rule];
    const id = subIndex === 1 ? baseId : `${baseId}.${subIndex}`;

    const severity = normalizeSeverity(v.severity);

    findings.push({
      id,
      title: RULE_TITLE_MAP[rule] ?? rule,
      severity,
      category: 'runtime-policy',
      description: v.msg,
      source: 'opa-policy',
      remediation: RULE_REMEDIATION_MAP[rule],
    });
  }

  return findings;
}

function normalizeSeverity(s: string): Severity {
  const valid: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const lower = s.toLowerCase() as Severity;
  return valid.includes(lower) ? lower : 'medium';
}

// ---------------------------------------------------------------------------
// Utility: resolve path to the bundled default.rego
// ---------------------------------------------------------------------------

/** Return the absolute path to the bundled default.rego policy file. */
export function getDefaultPolicyPath(): string {
  const thisFile = fileURLToPath(import.meta.url);
  return join(dirname(thisFile), '..', 'policy', 'default.rego');
}
