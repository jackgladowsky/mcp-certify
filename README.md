# mcp-certify

`mcp-certify` is a CLI that tests an MCP server for protocol health, security hygiene, operability, and runtime risk, then returns a pass/fail certification decision with evidence.

## Install

```bash
npm install -g mcp-certify
```

For a one-off run against the latest published version:

```bash
npx mcp-certify@latest --version
```

Node.js `20+` is required.

Optional dependencies:

- `trivy` for supply-chain scanning
- `opa` for custom Rego policy evaluation
- `mcp-validator` for optional manual protocol cross-checks outside the default scan path

To update a global install after a new npm release:

```bash
npm update -g mcp-certify
```

Before the first scan:

```bash
mcp-certify doctor
mcp-certify setup
```

## Quickstart

Scan a local stdio server:

```bash
mcp-certify node dist/index.js
```

Scan a remote HTTP MCP endpoint:

```bash
mcp-certify --url http://localhost:3000/mcp
```

Generate a badge for a README:

```bash
mcp-certify --badge node dist/index.js
```

Example output:

```text
$ mcp-certify node dist/index.js

mcp-certify v0.1.x

  Server: my-server v0.1.0

  CERTIFIED ✓

Protocol                                        100
  ○ Initialize handshake
  ○ Server info present
  ○ Capabilities declared
  ○ Tool names are unique

Security                                         95
  ▪ Cross-tool reference in read_file Cross-references can hide behavior behind another tool.
  ○ Hidden instruction scan clean

Functional                                      100
Performance                                      97

────────────────────────────────────────────────────
Score: 98/100
────────────────────────────────────────────────────
  Protocol      100  ████████████████████
  Security       95  ███████████████████░
  Functional    100  ████████████████████
  Performance    97  ████████████████████
```

## What It Checks

| Suite | Purpose | Notes |
|---|---|---|
| `Protocol` | MCP handshake, capabilities, `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`, `ping`, duplicate metadata checks | Built-in native suite |
| `Authentication` | Static bearer/basic/header auth for HTTP, env-based auth for stdio, unauthenticated access checks | Runs when auth config is provided |
| `Security` | Tool metadata poisoning, hidden instructions, bidi/zero-width chars, exfiltration patterns, dangerous names, missing schemas | Static analysis |
| `Functional` | Tool descriptions, schema shape, required-field consistency, optional shallow tool calls | Smoke-level contract checks |
| `Performance` | Cold start, list latency, ping latency, payload size | Not load testing |
| `Supply Chain` | Vulnerability, secret, and misconfiguration scanning | Uses `trivy` when installed |
| `Runtime Security` | Experimental sandbox with canary files, file access checks, network egress checks, prompt/resource runtime scenarios | Supported for stable local stdio launches only |

Certification is gate-based, not score-based. Critical findings fail certification even if the overall score looks good.

## Profiles

| Profile | Intended use | Default suites | Notes |
|---|---|---|---|
| `author-self-check` | Local development | protocol, security, functional | Fast, no runtime by default |
| `registry-screening` | Marketplace or directory screening | author-self-check + supply chain | More conservative default set |
| `enterprise-strict` | High-trust evaluation | all suites including runtime | Treats partial runtime coverage as a blocker |

## CLI Reference

### `scan` (default)

```bash
mcp-certify [options] <command...>
mcp-certify [options] --url <http-url>
```

Core flags:

| Flag | Meaning |
|---|---|
| `--url <url>` | Scan a remote HTTP MCP server instead of launching a local stdio command |
| `--timeout <ms>` | Timeout per operation |
| `--json` | Emit JSON instead of terminal output |
| `--badge` | Print a shields.io markdown badge using pass/fail and score |
| `--profile <name>` | Select a certification profile |
| `--fail-on <severity>` | Force failure on `critical|high|medium|low|info` or above |
| `--call-tools` | Call tools during testing; may have side effects |

Policy and network flags:

| Flag | Meaning |
|---|---|
| `--policy <path>` | Evaluate a custom Rego policy when OPA is installed |
| `--allow-host <host>` | Allow a host in policy/runtime checks |
| `--deny-host <host>` | Deny a host in policy/runtime checks |

Auth flags:

| Flag | Meaning |
|---|---|
| `--bearer-token <token>` | HTTP bearer token |
| `--basic-user <username>` | HTTP basic auth username |
| `--basic-pass <password>` | HTTP basic auth password |
| `--header <name:value>` | Additional HTTP header |
| `--auth-env <KEY=VALUE>` | Inject env vars for authenticated stdio servers |
| `--auth-required` | Assert that unauthenticated access should fail |

Runtime flags:

| Flag | Meaning |
|---|---|
| `--sandbox` | Run the experimental runtime sandbox suite |

`--sandbox` is experimental. It is most meaningful for stable local stdio launches like `node dist/index.js` or `python path/to/server.py`. When a package-manager launcher is only wrapping a locally installed executable, `mcp-certify` will try to unwrap and run that local executable directly for runtime coverage. Otherwise launchers such as `npx`, `npm`, `pnpm dlx`, `yarn dlx`, `bunx`, and `uvx` do not receive trustworthy runtime coverage.

When using `--url`, `mcp-certify` prints a note explaining that:

- `Supply Chain` is skipped because there is no local project tree to scan
- `Runtime Security` sandbox coverage is unavailable because the target is remote HTTP, not a local stdio launch

### `doctor`

```bash
mcp-certify doctor
mcp-certify doctor node dist/index.js
mcp-certify doctor --url http://localhost:3000/mcp
```

Checks:

- Node.js version
- optional dependencies: `trivy`, `opa`, `mcp-validator`
- Trivy DB readiness
- runtime sandbox support for the provided target
- optional target connectivity probe

### `setup`

```bash
mcp-certify setup
```

Best-effort first-run preparation:

- verifies optional dependencies
- attempts installation when a clear installer is available
- warms the Trivy vulnerability database
- reminds you of the runtime sandbox support boundary

## Coverage Notes

`mcp-certify` is intentionally asymmetric:

- Local stdio servers get the deepest coverage.
- Remote HTTP servers still get protocol, security, functional, performance, and auth checks, but not local filesystem supply-chain analysis.
- Runtime sandbox coverage is only meaningful for supported local stdio launches.

That tradeoff is deliberate. The MVP is designed to be useful and honest before it is exhaustive.

## Exit Codes

- `0`: certified
- `1`: certification failed or preflight not ready
- `2`: fatal CLI/runtime error

## Releasing

This repo publishes to npm from GitHub Actions on version tags, not on every merge to `main`.

One-time npm setup:

1. In npm package settings for `mcp-certify`, add a trusted publisher for this GitHub repository with workflow filename `publish.yml`.
2. Keep publishing tied to GitHub-hosted runners so OIDC trusted publishing works.

Release flow:

1. Bump the package version: `npm version patch` or `npm version minor` or `npm version major`
2. Push the commit and tag: `git push origin main --follow-tags`
3. GitHub Actions runs the publish workflow, verifies the `vX.Y.Z` tag matches [package.json](/Users/jackg/gladowskylabs/mcp-certify/package.json), then publishes that version to npm after build, typecheck, and tests pass

Notes:

- Installed global CLIs do not auto-update when a new npm version is published.
- The publish workflow runs from version tags only, not from manual dispatch or every merge to `main`.
