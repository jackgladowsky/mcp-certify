import { describe, it, expect } from 'vitest';
import { DEFAULT_GATES } from '../../src/types/index.js';
import type { Finding } from '../../src/types/index.js';

function makeFinding(overrides: Partial<Finding>): Finding {
  return {
    id: 'TEST-001',
    title: 'Test finding',
    severity: 'info',
    category: 'test',
    description: 'A test finding',
    ...overrides,
  };
}

describe('DEFAULT_GATES', () => {
  const [noCritical, noHighProtocol] = DEFAULT_GATES;

  describe('no-critical gate', () => {
    it('produces no blockers when no critical findings', () => {
      const findings = [
        makeFinding({ severity: 'high' }),
        makeFinding({ severity: 'medium' }),
        makeFinding({ severity: 'info' }),
      ];
      expect(noCritical.evaluate(findings)).toHaveLength(0);
    });

    it('produces a blocker for each critical finding', () => {
      const findings = [
        makeFinding({ id: 'A', severity: 'critical', title: 'Bad thing' }),
        makeFinding({ id: 'B', severity: 'critical', title: 'Worse thing' }),
        makeFinding({ id: 'C', severity: 'high' }),
      ];
      const blockers = noCritical.evaluate(findings);
      expect(blockers).toHaveLength(2);
      expect(blockers[0].gate).toBe('no-critical');
      expect(blockers[0].reason).toContain('Bad thing');
      expect(blockers[1].reason).toContain('Worse thing');
    });

    it('produces no blockers for empty findings', () => {
      expect(noCritical.evaluate([])).toHaveLength(0);
    });
  });

  describe('no-high-protocol gate', () => {
    it('produces blocker for high finding in protocol category', () => {
      const findings = [
        makeFinding({ id: 'P1', severity: 'high', category: 'protocol', title: 'Proto issue' }),
      ];
      const blockers = noHighProtocol.evaluate(findings);
      expect(blockers).toHaveLength(1);
      expect(blockers[0].gate).toBe('no-high-protocol');
    });

    it('produces blocker for high finding in runtime-policy category', () => {
      const findings = [
        makeFinding({ severity: 'high', category: 'runtime-policy' }),
      ];
      expect(noHighProtocol.evaluate(findings)).toHaveLength(1);
    });

    it('ignores high findings in other categories', () => {
      const findings = [
        makeFinding({ severity: 'high', category: 'security' }),
        makeFinding({ severity: 'high', category: 'functional' }),
        makeFinding({ severity: 'high', category: 'performance' }),
      ];
      expect(noHighProtocol.evaluate(findings)).toHaveLength(0);
    });

    it('ignores non-high findings in protocol category', () => {
      const findings = [
        makeFinding({ severity: 'medium', category: 'protocol' }),
        makeFinding({ severity: 'critical', category: 'protocol' }),
      ];
      expect(noHighProtocol.evaluate(findings)).toHaveLength(0);
    });
  });
});
