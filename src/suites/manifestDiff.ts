import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { Finding, Severity, SuiteResult, Blocker, SuiteContext, Artifact } from '../types/index.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface Manifest {
  timestamp: string;
  server: { name: string; version: string } | null;
  capabilities: Record<string, unknown>;
  tools: Array<{ name: string; description?: string; inputSchema?: unknown }>;
  resources: Array<{ uri: string; name: string; description?: string; mimeType?: string }>;
  resourceTemplates: Array<{ uriTemplate: string; name: string; description?: string }>;
  prompts: Array<{ name: string; description?: string; arguments?: unknown[] }>;
}

export type ManifestChangeKind =
  | 'tool-added'
  | 'tool-removed'
  | 'tool-description-changed'
  | 'tool-description-grew'
  | 'tool-schema-changed'
  | 'resource-added'
  | 'resource-removed'
  | 'resource-changed'
  | 'resource-template-added'
  | 'resource-template-removed'
  | 'prompt-added'
  | 'prompt-removed'
  | 'prompt-changed'
  | 'capabilities-changed'
  | 'server-info-changed';

export interface ManifestChange {
  kind: ManifestChangeKind;
  severity: Severity;
  target: string;
  detail: string;
}

// ---------------------------------------------------------------------------
// Severity-based scoring
// ---------------------------------------------------------------------------

const DEDUCTIONS: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 10,
  low: 5,
  info: 0,
};

function computeScore(findings: Finding[]): number {
  const totalDeduction = findings.reduce(
    (sum, f) => sum + (DEDUCTIONS[f.severity] ?? 0),
    0,
  );
  return Math.max(0, 100 - totalDeduction);
}

// ---------------------------------------------------------------------------
// Capture
// ---------------------------------------------------------------------------

export async function captureManifest(client: Client): Promise<Manifest> {
  const serverVersion = client.getServerVersion();
  const capabilities = (client.getServerCapabilities() as Record<string, unknown>) ?? {};

  const manifest: Manifest = {
    timestamp: new Date().toISOString(),
    server: serverVersion
      ? { name: serverVersion.name, version: serverVersion.version }
      : null,
    capabilities,
    tools: [],
    resources: [],
    resourceTemplates: [],
    prompts: [],
  };

  // Collect tools
  if (capabilities.tools) {
    try {
      const { tools } = await client.listTools();
      manifest.tools = tools.map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
      }));
    } catch {
      // Server declared tools capability but list failed; leave empty
    }
  }

  // Collect resources
  if (capabilities.resources) {
    try {
      const { resources } = await client.listResources();
      manifest.resources = resources.map((r) => ({
        uri: r.uri,
        name: r.name,
        description: r.description,
        mimeType: r.mimeType,
      }));
    } catch {
      // leave empty
    }

    // Collect resource templates
    try {
      const { resourceTemplates } = await client.listResourceTemplates();
      manifest.resourceTemplates = resourceTemplates.map((rt) => ({
        uriTemplate: rt.uriTemplate,
        name: rt.name,
        description: rt.description,
      }));
    } catch {
      // leave empty
    }
  }

  // Collect prompts
  if (capabilities.prompts) {
    try {
      const { prompts } = await client.listPrompts();
      manifest.prompts = prompts.map((p) => ({
        name: p.name,
        description: p.description,
        arguments: p.arguments,
      }));
    } catch {
      // leave empty
    }
  }

  return manifest;
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

function jsonEq(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

export function diffManifests(baseline: Manifest, current: Manifest): ManifestChange[] {
  const changes: ManifestChange[] = [];

  // --- Server info ---
  if (!jsonEq(baseline.server, current.server)) {
    changes.push({
      kind: 'server-info-changed',
      severity: 'info',
      target: 'server',
      detail: `Server info changed from ${JSON.stringify(baseline.server)} to ${JSON.stringify(current.server)}`,
    });
  }

  // --- Capabilities ---
  if (!jsonEq(baseline.capabilities, current.capabilities)) {
    changes.push({
      kind: 'capabilities-changed',
      severity: 'medium',
      target: 'capabilities',
      detail: diffKeys('capabilities', baseline.capabilities, current.capabilities),
    });
  }

  // --- Tools ---
  const baselineTools = new Map(baseline.tools.map((t) => [t.name, t]));
  const currentTools = new Map(current.tools.map((t) => [t.name, t]));

  for (const [name, tool] of currentTools) {
    if (!baselineTools.has(name)) {
      changes.push({
        kind: 'tool-added',
        severity: 'info',
        target: `tool:${name}`,
        detail: `New tool "${name}" added`,
      });
    }
  }

  for (const [name, tool] of baselineTools) {
    if (!currentTools.has(name)) {
      changes.push({
        kind: 'tool-removed',
        severity: 'low',
        target: `tool:${name}`,
        detail: `Tool "${name}" was removed`,
      });
      continue;
    }

    const curr = currentTools.get(name)!;

    // Description changes
    if (tool.description !== curr.description) {
      const oldLen = tool.description?.length ?? 0;
      const newLen = curr.description?.length ?? 0;

      // Check for significant growth (>50% longer) — potential injection
      if (oldLen > 0 && newLen > oldLen * 1.5) {
        changes.push({
          kind: 'tool-description-grew',
          severity: 'high',
          target: `tool:${name}`,
          detail: `Tool "${name}" description grew significantly: ${oldLen} -> ${newLen} chars (+${Math.round(((newLen - oldLen) / oldLen) * 100)}%)`,
        });
      } else {
        changes.push({
          kind: 'tool-description-changed',
          severity: 'medium',
          target: `tool:${name}`,
          detail: `Tool "${name}" description changed`,
        });
      }
    }

    // Schema changes
    if (!jsonEq(tool.inputSchema, curr.inputSchema)) {
      changes.push({
        kind: 'tool-schema-changed',
        severity: 'medium',
        target: `tool:${name}`,
        detail: `Tool "${name}" inputSchema changed`,
      });
    }
  }

  // --- Resources ---
  const baselineResources = new Map(baseline.resources.map((r) => [r.uri, r]));
  const currentResources = new Map(current.resources.map((r) => [r.uri, r]));

  for (const [uri] of currentResources) {
    if (!baselineResources.has(uri)) {
      changes.push({
        kind: 'resource-added',
        severity: 'info',
        target: `resource:${uri}`,
        detail: `New resource "${uri}" added`,
      });
    }
  }

  for (const [uri, res] of baselineResources) {
    if (!currentResources.has(uri)) {
      changes.push({
        kind: 'resource-removed',
        severity: 'low',
        target: `resource:${uri}`,
        detail: `Resource "${uri}" was removed`,
      });
      continue;
    }

    const curr = currentResources.get(uri)!;
    if (!jsonEq(res, curr)) {
      changes.push({
        kind: 'resource-changed',
        severity: 'info',
        target: `resource:${uri}`,
        detail: `Resource "${uri}" metadata changed`,
      });
    }
  }

  // --- Resource Templates ---
  const baselineTemplates = new Map(baseline.resourceTemplates.map((rt) => [rt.uriTemplate, rt]));
  const currentTemplates = new Map(current.resourceTemplates.map((rt) => [rt.uriTemplate, rt]));

  for (const [uri] of currentTemplates) {
    if (!baselineTemplates.has(uri)) {
      changes.push({
        kind: 'resource-template-added',
        severity: 'info',
        target: `template:${uri}`,
        detail: `New resource template "${uri}" added`,
      });
    }
  }

  for (const [uri] of baselineTemplates) {
    if (!currentTemplates.has(uri)) {
      changes.push({
        kind: 'resource-template-removed',
        severity: 'low',
        target: `template:${uri}`,
        detail: `Resource template "${uri}" was removed`,
      });
    }
  }

  // --- Prompts ---
  const baselinePrompts = new Map(baseline.prompts.map((p) => [p.name, p]));
  const currentPrompts = new Map(current.prompts.map((p) => [p.name, p]));

  for (const [name] of currentPrompts) {
    if (!baselinePrompts.has(name)) {
      changes.push({
        kind: 'prompt-added',
        severity: 'info',
        target: `prompt:${name}`,
        detail: `New prompt "${name}" added`,
      });
    }
  }

  for (const [name, prompt] of baselinePrompts) {
    if (!currentPrompts.has(name)) {
      changes.push({
        kind: 'prompt-removed',
        severity: 'low',
        target: `prompt:${name}`,
        detail: `Prompt "${name}" was removed`,
      });
      continue;
    }

    const curr = currentPrompts.get(name)!;
    if (!jsonEq(prompt, curr)) {
      changes.push({
        kind: 'prompt-changed',
        severity: 'info',
        target: `prompt:${name}`,
        detail: `Prompt "${name}" definition changed`,
      });
    }
  }

  return changes;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function diffKeys(
  label: string,
  baseline: Record<string, unknown>,
  current: Record<string, unknown>,
): string {
  const added = Object.keys(current).filter((k) => !(k in baseline));
  const removed = Object.keys(baseline).filter((k) => !(k in current));
  const changed = Object.keys(baseline).filter(
    (k) => k in current && !jsonEq(baseline[k], current[k]),
  );

  const parts: string[] = [];
  if (added.length) parts.push(`added: ${added.join(', ')}`);
  if (removed.length) parts.push(`removed: ${removed.join(', ')}`);
  if (changed.length) parts.push(`changed: ${changed.join(', ')}`);
  return parts.length > 0 ? `${label}: ${parts.join('; ')}` : `${label} changed`;
}

function changesToFindings(changes: ManifestChange[]): Finding[] {
  return changes.map((c, i) => ({
    id: `MANIFEST-${String(i + 1).padStart(3, '0')}`,
    title: changeTitle(c),
    severity: c.severity,
    category: 'manifest-change',
    description: c.detail,
    evidence: `Kind: ${c.kind}, Target: ${c.target}`,
    remediation: changeRemediation(c),
  }));
}

function changeTitle(c: ManifestChange): string {
  switch (c.kind) {
    case 'tool-added':
      return `New tool added: ${c.target.replace('tool:', '')}`;
    case 'tool-removed':
      return `Tool removed: ${c.target.replace('tool:', '')}`;
    case 'tool-description-changed':
      return `Tool description changed: ${c.target.replace('tool:', '')}`;
    case 'tool-description-grew':
      return `Tool description grew significantly: ${c.target.replace('tool:', '')}`;
    case 'tool-schema-changed':
      return `Tool input schema changed: ${c.target.replace('tool:', '')}`;
    case 'resource-added':
      return `New resource added`;
    case 'resource-removed':
      return `Resource removed`;
    case 'resource-changed':
      return `Resource metadata changed`;
    case 'resource-template-added':
      return `New resource template added`;
    case 'resource-template-removed':
      return `Resource template removed`;
    case 'prompt-added':
      return `New prompt added: ${c.target.replace('prompt:', '')}`;
    case 'prompt-removed':
      return `Prompt removed: ${c.target.replace('prompt:', '')}`;
    case 'prompt-changed':
      return `Prompt definition changed: ${c.target.replace('prompt:', '')}`;
    case 'capabilities-changed':
      return `Server capabilities changed`;
    case 'server-info-changed':
      return `Server info changed`;
  }
}

function changeRemediation(c: ManifestChange): string {
  switch (c.kind) {
    case 'tool-description-grew':
      return 'Review the new description for hidden prompt injections. A significant increase in description length may indicate injected instructions.';
    case 'tool-description-changed':
      return 'Review the updated description to ensure it accurately reflects the tool behavior and does not contain injected instructions.';
    case 'tool-schema-changed':
      return 'Review the new input schema to ensure no unexpected parameters have been added.';
    case 'capabilities-changed':
      return 'Verify the server has not gained unexpected capabilities since the baseline.';
    case 'tool-removed':
      return 'Confirm that the tool removal was intentional and does not break dependent workflows.';
    default:
      return 'Review the change for expected behavior.';
  }
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

export async function manifestDiffSuite(
  client: Client,
  ctx: SuiteContext,
): Promise<SuiteResult> {
  const startTime = performance.now();
  let findings: Finding[] = [];
  const artifacts: Artifact[] = [];
  const certificationBlockers: Blocker[] = [];

  // 1. Capture current manifest
  const current = await captureManifest(client);
  const currentJson = JSON.stringify(current, null, 2);

  artifacts.push({
    name: 'current-manifest',
    type: 'json',
    content: currentJson,
  });

  // 2. Save current manifest if artifactsDir is provided
  if (ctx.options.artifactsDir) {
    try {
      const dir = ctx.options.artifactsDir;
      await mkdir(dir, { recursive: true });
      const manifestPath = join(dir, 'manifest.json');
      await writeFile(manifestPath, currentJson, 'utf-8');
      artifacts.push({
        name: 'manifest-path',
        type: 'text',
        content: manifestPath,
      });
    } catch {
      // Non-fatal: artifact saving is best-effort
    }
  }

  // 3. Diff against baseline if provided
  if (ctx.options.baselinePath) {
    try {
      const baselineRaw = await readFile(ctx.options.baselinePath, 'utf-8');
      const baseline = JSON.parse(baselineRaw) as Manifest;
      const changes = diffManifests(baseline, current);

      if (changes.length > 0) {
        findings = changesToFindings(changes);

        artifacts.push({
          name: 'manifest-diff',
          type: 'diff',
          content: JSON.stringify(changes, null, 2),
        });
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      findings.push({
        id: 'MANIFEST-BASELINE-ERR',
        title: 'Failed to load baseline manifest',
        severity: 'medium',
        category: 'manifest-change',
        description: `Could not load or parse baseline: ${msg}`,
        remediation: 'Ensure the baseline path is correct and contains valid JSON.',
      });
      certificationBlockers.push({
        findingId: 'MANIFEST-BASELINE-ERR',
        gate: 'manifest-baseline',
        reason: 'Requested manifest baseline could not be loaded',
      });
    }
  }

  const durationMs = Math.round(performance.now() - startTime);
  const score = computeScore(findings);
  certificationBlockers.push(
    ...findings
      .filter((f) => f.severity === 'critical' || f.severity === 'high')
      .map((f) => ({
        findingId: f.id,
        gate: 'manifest-integrity',
        reason: `Manifest change: ${f.title}`,
      })),
  );

  return {
    name: 'Manifest Diff',
    findings,
    score,
    certificationBlockers,
    evidence: {
      artifacts,
      durationMs,
    },
  };
}
