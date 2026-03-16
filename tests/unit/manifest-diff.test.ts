import { describe, it, expect } from 'vitest';
import { diffManifests, type Manifest } from '../../src/suites/manifestDiff.js';

function emptyManifest(overrides?: Partial<Manifest>): Manifest {
  return {
    timestamp: '2026-01-01T00:00:00.000Z',
    server: { name: 'test', version: '1.0.0' },
    capabilities: { tools: {} },
    tools: [],
    resources: [],
    resourceTemplates: [],
    prompts: [],
    ...overrides,
  };
}

describe('diffManifests', () => {
  it('returns empty array when manifests are identical', () => {
    const m = emptyManifest({ tools: [{ name: 'foo', description: 'bar' }] });
    expect(diffManifests(m, m)).toEqual([]);
  });

  it('detects tool-added', () => {
    const baseline = emptyManifest();
    const current = emptyManifest({ tools: [{ name: 'new_tool', description: 'hi' }] });
    const changes = diffManifests(baseline, current);
    expect(changes).toHaveLength(1);
    expect(changes[0].kind).toBe('tool-added');
    expect(changes[0].severity).toBe('info');
    expect(changes[0].target).toContain('new_tool');
  });

  it('detects tool-removed', () => {
    const baseline = emptyManifest({ tools: [{ name: 'old_tool', description: 'bye' }] });
    const current = emptyManifest();
    const changes = diffManifests(baseline, current);
    expect(changes).toHaveLength(1);
    expect(changes[0].kind).toBe('tool-removed');
    expect(changes[0].severity).toBe('low');
  });

  it('detects tool-description-changed', () => {
    const baseline = emptyManifest({ tools: [{ name: 'foo', description: 'old' }] });
    const current = emptyManifest({ tools: [{ name: 'foo', description: 'new' }] });
    const changes = diffManifests(baseline, current);
    expect(changes).toHaveLength(1);
    expect(changes[0].kind).toBe('tool-description-changed');
    expect(changes[0].severity).toBe('medium');
  });

  it('detects tool-description-grew with high severity when >50% longer', () => {
    const baseline = emptyManifest({
      tools: [{ name: 'foo', description: 'short desc' }],
    });
    const current = emptyManifest({
      tools: [{ name: 'foo', description: 'short desc'.padEnd(200, ' injected content') }],
    });
    const changes = diffManifests(baseline, current);
    expect(changes).toHaveLength(1);
    expect(changes[0].kind).toBe('tool-description-grew');
    expect(changes[0].severity).toBe('high');
  });

  it('detects tool-schema-changed', () => {
    const baseline = emptyManifest({
      tools: [{ name: 'foo', description: 'x', inputSchema: { type: 'object' } }],
    });
    const current = emptyManifest({
      tools: [
        {
          name: 'foo',
          description: 'x',
          inputSchema: { type: 'object', properties: { a: { type: 'string' } } },
        },
      ],
    });
    const changes = diffManifests(baseline, current);
    expect(changes).toHaveLength(1);
    expect(changes[0].kind).toBe('tool-schema-changed');
    expect(changes[0].severity).toBe('medium');
  });

  it('detects resource-added and resource-removed', () => {
    const baseline = emptyManifest({
      resources: [{ uri: 'file:///old', name: 'old' }],
    });
    const current = emptyManifest({
      resources: [{ uri: 'file:///new', name: 'new' }],
    });
    const changes = diffManifests(baseline, current);
    const kinds = changes.map((c) => c.kind);
    expect(kinds).toContain('resource-added');
    expect(kinds).toContain('resource-removed');
  });

  it('detects prompt-added and prompt-removed', () => {
    const baseline = emptyManifest({ prompts: [{ name: 'old_prompt' }] });
    const current = emptyManifest({ prompts: [{ name: 'new_prompt' }] });
    const changes = diffManifests(baseline, current);
    const kinds = changes.map((c) => c.kind);
    expect(kinds).toContain('prompt-added');
    expect(kinds).toContain('prompt-removed');
  });

  it('detects capabilities-changed', () => {
    const baseline = emptyManifest({ capabilities: { tools: {} } });
    const current = emptyManifest({ capabilities: { tools: {}, resources: {} } });
    const changes = diffManifests(baseline, current);
    expect(changes).toHaveLength(1);
    expect(changes[0].kind).toBe('capabilities-changed');
    expect(changes[0].severity).toBe('medium');
  });

  it('detects server-info-changed', () => {
    const baseline = emptyManifest({ server: { name: 'srv', version: '1.0.0' } });
    const current = emptyManifest({ server: { name: 'srv', version: '2.0.0' } });
    const changes = diffManifests(baseline, current);
    expect(changes).toHaveLength(1);
    expect(changes[0].kind).toBe('server-info-changed');
    expect(changes[0].severity).toBe('info');
  });

  it('detects multiple changes at once', () => {
    const baseline = emptyManifest({
      tools: [{ name: 'a', description: 'original description here' }],
      prompts: [{ name: 'p1' }],
    });
    const current = emptyManifest({
      tools: [
        { name: 'a', description: 'updated description here' },
        { name: 'b', description: 'new' },
      ],
      prompts: [],
    });
    const changes = diffManifests(baseline, current);
    expect(changes.length).toBeGreaterThanOrEqual(3);
    const kinds = changes.map((c) => c.kind);
    expect(kinds).toContain('tool-description-changed');
    expect(kinds).toContain('tool-added');
    expect(kinds).toContain('prompt-removed');
  });
});
