import type { RunOptions, Severity } from '../types/index.js';

export interface CertificationProfile {
  name: string;
  description: string;
  suites: string[];
  failThresholds: {
    minScore?: number;
    maxCritical?: number;
    maxHigh?: number;
  };
  options: Partial<RunOptions>;
}
