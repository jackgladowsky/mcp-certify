export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  description: string;
  evidence?: string;
  source?: string;
  remediation?: string;
}

export interface Artifact {
  name: string;
  type: 'json' | 'text' | 'log' | 'diff';
  content?: string;
  path?: string;
}

export interface SuiteEvidence {
  rawOutput?: string;
  artifacts: Artifact[];
  durationMs: number;
}
