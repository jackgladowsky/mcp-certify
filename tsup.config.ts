import { readFileSync } from 'node:fs';
import { defineConfig } from 'tsup';

const packageJson = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as {
  version: string;
};

export default defineConfig({
  entry: ['src/cli.ts'],
  format: ['esm'],
  target: 'node20',
  clean: true,
  dts: false,
  sourcemap: true,
  define: {
    __TOOL_VERSION__: JSON.stringify(packageJson.version),
  },
  banner: {
    js: '#!/usr/bin/env node',
  },
});
