import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

export const TOOL_VERSION: string = require('../package.json').version;
