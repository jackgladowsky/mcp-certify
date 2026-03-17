# TODOS

## P1: Add CI/CD pipeline

**What:** GitHub Actions workflow that runs `npm test` and `npm run build` on every push and PR.

**Why:** mcp-certify is a security tool — shipping broken code without noticing undermines its credibility. Currently tests only run when someone manually types `npm test`.

**Context:** 62 tests across unit/integration/e2e, all passing. Build is a single `tsup` step (~14ms). The workflow should be straightforward: checkout → Node 20 setup → npm ci → npm run build → npm test. Consider also running `npm run typecheck` in CI.

**Effort:** S (< 1 hour)
**Depends on:** Nothing — can be done independently.
