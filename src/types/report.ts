import type { Finding, Severity } from './findings.js';

export interface Blocker {
  findingId: string;
  gate: string;
  reason: string;
}

export type CertificationDecision = 'pass' | 'fail' | 'conditional';

export interface SuiteResult {
  name: string;
  findings: Finding[];
  score: number;
  certificationBlockers: Blocker[];
  evidence: {
    rawOutput?: string;
    artifacts: { name: string; type: string; content?: string; path?: string }[];
    durationMs: number;
  };
}

export interface CertifyReport {
  server?: { name: string; version: string };
  decision: CertificationDecision;
  blockers: Blocker[];
  suites: SuiteResult[];
  score: number;
  breakdown: { name: string; score: number }[];
  timestamp: string;
  profile?: string;
}

export interface GateRule {
  name: string;
  description: string;
  evaluate: (findings: Finding[]) => Blocker[];
}

export interface AuthHeader {
  name: string;
  value: string;
}

export interface BasicAuthConfig {
  username: string;
  password: string;
}

export interface OAuthConfig {
  issuerUrl?: string;
  authorizationServerUrl?: string;
  clientId?: string;
  redirectUrl?: string;
  scopes?: string[];
}

export interface AuthConfig {
  bearerToken?: string;
  basic?: BasicAuthConfig;
  headers?: AuthHeader[];
  env?: Record<string, string>;
  required?: boolean;
  oauth?: OAuthConfig;
}

export const DEFAULT_GATES: GateRule[] = [
  {
    name: 'no-critical',
    description: 'Any critical finding fails certification',
    evaluate: (findings) =>
      findings
        .filter((f) => f.severity === 'critical')
        .map((f) => ({
          findingId: f.id,
          gate: 'no-critical',
          reason: `Critical: ${f.title}`,
        })),
  },
  {
    name: 'no-high-protocol',
    description: 'High findings in protocol/runtime-policy/authentication fail certification',
    evaluate: (findings) =>
      findings
        .filter(
          (f) =>
            f.severity === 'high' &&
            (
              f.category === 'protocol' ||
              f.category === 'runtime-policy' ||
              f.category === 'authentication'
            ),
        )
        .map((f) => ({
          findingId: f.id,
          gate: 'no-high-protocol',
          reason: `High ${f.category}: ${f.title}`,
        })),
  },
];

export interface RunOptions {
  callTools?: boolean;
  timeout?: number;
  profile?: string;
  auth?: AuthConfig;
  policyPath?: string;
  baselinePath?: string;
  artifactsDir?: string;
  failOn?: Severity;
  sandbox?: boolean;
  allowHosts?: string[];
  denyHosts?: string[];
}

export interface SuiteContext {
  capabilities: Record<string, unknown>;
  connectDuration: number;
  options: RunOptions;
  timeout: number;
}
