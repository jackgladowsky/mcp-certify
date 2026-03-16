import type { AuthConfig } from '../types.js';

export function hasAuthConfig(auth?: AuthConfig): boolean {
  return Boolean(
    auth?.bearerToken ||
      auth?.basic ||
      (auth?.headers && auth.headers.length > 0) ||
      (auth?.env && Object.keys(auth.env).length > 0) ||
      auth?.oauth,
  );
}

export function applyAuthEnv(
  baseEnv: Record<string, string> | undefined,
  auth?: AuthConfig,
): Record<string, string> | undefined {
  if (!auth?.env || Object.keys(auth.env).length === 0) {
    return baseEnv;
  }

  return {
    ...(baseEnv ?? {}),
    ...auth.env,
  };
}

export function buildRequestInit(auth?: AuthConfig): RequestInit | undefined {
  const headers = buildAuthHeaders(auth);
  if (headers.length === 0) {
    return undefined;
  }

  return {
    headers: Object.fromEntries(headers.map((header) => [header.name, header.value])),
  };
}

export function describeAuthConfig(auth?: AuthConfig): string {
  if (!hasAuthConfig(auth)) {
    return 'No authentication configured';
  }

  const parts: string[] = [];
  if (auth?.bearerToken) parts.push('bearer token');
  if (auth?.basic) parts.push('basic auth');
  if (auth?.headers?.length) parts.push(`${auth.headers.length} custom header(s)`);
  if (auth?.env && Object.keys(auth.env).length > 0) {
    parts.push(`${Object.keys(auth.env).length} auth env var(s)`);
  }
  if (auth?.oauth) parts.push('oauth config placeholder');
  if (auth?.required) parts.push('auth required');
  return parts.join(', ');
}

function buildAuthHeaders(auth?: AuthConfig): Array<{ name: string; value: string }> {
  const headers: Array<{ name: string; value: string }> = [];

  if (auth?.bearerToken) {
    headers.push({
      name: 'Authorization',
      value: `Bearer ${auth.bearerToken}`,
    });
  }

  if (auth?.basic) {
    const token = Buffer.from(
      `${auth.basic.username}:${auth.basic.password}`,
      'utf-8',
    ).toString('base64');
    headers.push({
      name: 'Authorization',
      value: `Basic ${token}`,
    });
  }

  for (const header of auth?.headers ?? []) {
    headers.push(header);
  }

  return headers;
}
