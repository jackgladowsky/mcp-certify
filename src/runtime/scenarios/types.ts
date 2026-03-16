import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { Finding } from '../../types/findings.js';
import type { CanaryFile } from '../canaries.js';
import type { CaptureSession } from '../networkCapture.js';

export interface ScenarioResult {
  passed: boolean;
  findings: Finding[];
  evidence: string;
}

export interface Scenario {
  id: string;
  name: string;
  description: string;
  category: string;
  setup?: (homeDir: string) => Promise<void>;
  run: (
    client: Client,
    homeDir: string,
    canaries: CanaryFile[],
    capture?: CaptureSession,
  ) => Promise<ScenarioResult>;
}
