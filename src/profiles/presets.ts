import type { CertificationProfile } from './types.js';

/**
 * Quick check for MCP server authors during development.
 *
 * Runs core quality suites with lenient thresholds.
 * No sandbox required -- designed for rapid iteration.
 */
export const authorSelfCheck: CertificationProfile = {
  name: 'author-self-check',
  description: 'Quick check for server authors during development',
  suites: ['protocol', 'security', 'functional'],
  failThresholds: {
    minScore: 60,
    maxCritical: 0,
    maxHigh: 3,
  },
  options: {
    callTools: false,
    sandbox: false,
    timeout: 30_000,
  },
};

/**
 * Screening profile for registries vetting MCP servers.
 *
 * Runs all static analysis suites including supply chain scanning.
 * Moderate thresholds for marketplace or registry reviews.
 */
export const registryScreening: CertificationProfile = {
  name: 'registry-screening',
  description: 'Registry vetting for MCP server submissions',
  suites: ['protocol', 'security', 'functional', 'supplyChain'],
  failThresholds: {
    minScore: 75,
    maxCritical: 0,
    maxHigh: 1,
  },
  options: {
    callTools: false,
    sandbox: false,
    timeout: 120_000,
  },
};

/**
 * Full security evaluation for enterprise environments.
 *
 * Runs ALL suites including runtime analysis. Zero tolerance for critical
 * and high findings. Requires --sandbox for safe runtime testing.
 */
export const enterpriseStrict: CertificationProfile = {
  name: 'enterprise-strict',
  description: 'Full security evaluation with zero tolerance',
  suites: [
    'protocol',
    'security',
    'functional',
    'performance',
    'supplyChain',
    'runtime',
  ],
  failThresholds: {
    minScore: 90,
    maxCritical: 0,
    maxHigh: 0,
  },
  options: {
    callTools: true,
    sandbox: true,
    timeout: 300_000,
  },
};

/**
 * All built-in certification profiles keyed by name.
 */
export const PROFILES: Record<string, CertificationProfile> = {
  'author-self-check': authorSelfCheck,
  'registry-screening': registryScreening,
  'enterprise-strict': enterpriseStrict,
};
