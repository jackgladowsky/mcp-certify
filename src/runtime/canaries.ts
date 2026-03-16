import { randomUUID } from 'node:crypto';
import { mkdir, writeFile, stat } from 'node:fs/promises';
import { join, dirname } from 'node:path';

export interface CanaryFile {
  relativePath: string;
  content: string;
  token: string;
  /** Timestamp when the file was seeded (ms since epoch) */
  seededAt?: number;
}

/**
 * Generate a set of fake sensitive files, each containing a unique canary token.
 * These files mimic common credential/secret locations found in a user's HOME.
 */
export function generateCanaries(): CanaryFile[] {
  const canaries: CanaryFile[] = [];

  function token(): string {
    return `CANARY-${randomUUID()}`;
  }

  // SSH private key
  const sshToken = token();
  canaries.push({
    relativePath: '.ssh/id_rsa',
    token: sshToken,
    content: [
      '-----BEGIN OPENSSH PRIVATE KEY-----',
      'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW',
      `QyNTUxOQAAACDcanary${sshToken}AAAAAAAAAAAAAAAA`,
      'AAAAMwAAAAtzc2gtZWQyNTUxOQAAACDcanaryAAAAAAAAAAAAAAAAAAAAAAAA',
      `AAAAN${sshToken}AAAAAAAAAAAAA==`,
      '-----END OPENSSH PRIVATE KEY-----',
    ].join('\n'),
  });

  // SSH public key
  const sshPubToken = token();
  canaries.push({
    relativePath: '.ssh/id_rsa.pub',
    token: sshPubToken,
    content: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI${sshPubToken} canary@mcp-certify`,
  });

  // AWS credentials
  const awsToken = token();
  canaries.push({
    relativePath: '.aws/credentials',
    token: awsToken,
    content: [
      '[default]',
      `aws_access_key_id = ${awsToken}`,
      `aws_secret_access_key = ${token()}`,
      'region = us-east-1',
    ].join('\n'),
  });

  // .env file
  const envToken = token();
  canaries.push({
    relativePath: '.env',
    token: envToken,
    content: [
      `API_KEY=${envToken}`,
      `DATABASE_URL=postgres://admin:${token()}@localhost:5432/mydb`,
      `STRIPE_SECRET_KEY=sk_live_${token()}`,
    ].join('\n'),
  });

  // Config secrets JSON
  const secretsToken = token();
  canaries.push({
    relativePath: '.config/secrets.json',
    token: secretsToken,
    content: JSON.stringify(
      {
        github_token: secretsToken,
        openai_api_key: token(),
        slack_webhook: `https://hooks.slack.com/services/${token()}`,
      },
      null,
      2,
    ),
  });

  // GPG private key
  const gpgToken = token();
  canaries.push({
    relativePath: '.gnupg/private-keys-v1.d/canary.key',
    token: gpgToken,
    content: [
      '-----BEGIN PGP PRIVATE KEY BLOCK-----',
      '',
      `mDMEZcanary${gpgToken}AAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==',
      `=${gpgToken.slice(0, 8)}`,
      '-----END PGP PRIVATE KEY BLOCK-----',
    ].join('\n'),
  });

  return canaries;
}

/**
 * Write all canary files into the given home directory.
 * Records the seeded timestamp on each canary for later access-time comparison.
 */
export async function seedCanaries(
  homeDir: string,
  canaries: CanaryFile[],
): Promise<void> {
  for (const canary of canaries) {
    const fullPath = join(homeDir, canary.relativePath);
    await mkdir(dirname(fullPath), { recursive: true });
    await writeFile(fullPath, canary.content, { mode: 0o600 });
    canary.seededAt = Date.now();
  }
}

/**
 * Scan arbitrary text for any canary tokens. Returns the list of tokens found.
 */
export function checkCanaryLeaks(
  text: string,
  canaries: CanaryFile[],
): string[] {
  const leaked: string[] = [];
  for (const canary of canaries) {
    if (text.includes(canary.token)) {
      leaked.push(canary.token);
    }
  }
  return leaked;
}

/**
 * Check whether canary files were accessed since seeding by comparing atime.
 * Returns relative paths of files whose atime changed.
 */
export async function checkCanaryAccess(
  homeDir: string,
  canaries: CanaryFile[],
): Promise<string[]> {
  const accessed: string[] = [];

  for (const canary of canaries) {
    const fullPath = join(homeDir, canary.relativePath);
    try {
      const s = await stat(fullPath);
      const atimeMs = s.atimeMs;
      // If atime is notably after seed time, the file was read.
      // Use a small tolerance (100ms) to avoid false positives from the seed write itself.
      if (canary.seededAt && atimeMs > canary.seededAt + 100) {
        accessed.push(canary.relativePath);
      }
    } catch {
      // File may have been deleted by the server -- also suspicious
      accessed.push(canary.relativePath);
    }
  }

  return accessed;
}
