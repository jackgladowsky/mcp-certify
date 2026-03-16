// Re-export new type system
export type {
  Severity,
  Finding,
  Artifact,
  SuiteEvidence,
  Blocker,
  CertificationDecision,
  SuiteResult,
  CertifyReport,
  GateRule,
  AuthHeader,
  BasicAuthConfig,
  OAuthConfig,
  AuthConfig,
  RunOptions,
  SuiteContext,
} from './types/index.js';

export { DEFAULT_GATES } from './types/index.js';

// Types still used directly by existing code during transition
export interface ServerTarget {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  timeout?: number;
}
