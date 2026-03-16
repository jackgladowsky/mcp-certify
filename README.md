# mcp-certify

One command to test if your MCP server actually works, is secure, and performs well.

```
$ mcp-certify npx -y @modelcontextprotocol/server-filesystem /tmp

mcp-certify v0.1.0

  Server: secure-filesystem-server v0.2.0

  CERTIFIED ✓

Protocol                                        100
  ○ Initialize handshake
  ○ Server info present
  ○ Capabilities declared
  ○ tools/list returns valid response
  ○ Ping responds

Security                                        95
  ▪ Cross-tool reference in read_file
  ○ Hidden instruction scan clean
  ○ Data exfiltration scan clean
  ○ Invisible character scan clean
  ○ All tools have input schemas

Functional                                      100
Performance                                     100

────────────────────────────────────────────────────
Score: 98/100
────────────────────────────────────────────────────
  Protocol      100  ████████████████████
  Security       95  ███████████████████░
  Functional    100  ████████████████████
  Performance   100  ████████████████████
```

## Quick Start

```bash
# Install
git clone https://github.com/jackgladowsky/mcp-certify.git
cd mcp-certify
npm install
npm run build

# Test any MCP server
node dist/cli.js <your server command here>

# Examples
node dist/cli.js npx -y @modelcontextprotocol/server-filesystem /tmp
node dist/cli.js node path/to/my-server.js
node dist/cli.js python my_server.py
node dist/cli.js --url http://localhost:3000/mcp
```

Requires Node.js 20+.

## Problem

18,000+ MCP servers exist and most are broken or insecure. Average security score across scanned servers is 34/100. Registries disclaim "community servers are untested — use at your own risk." 38% of enterprises say security concerns are blocking MCP adoption.

No comprehensive testing tool exists. The pieces are fragmented — MCP Inspector for manual debugging, mcp-validator for protocol checks, MCP-Scan (now Snyk) for security only. Nothing ties it together or makes a pass/fail certification decision.

## What it does

Connects to any MCP server (stdio or HTTP), runs automated checks across multiple suites, and outputs a certification decision with evidence.

**Certification is gate-based, not score-based.** Any critical finding fails certification. Any high finding in protocol or runtime policy fails certification. Score is secondary context.

### Suites

| Suite | What it checks |
|---|---|
| **Protocol** | Initialize handshake, capability negotiation, tools/list, resources/list, prompts/list, ping |
| **Authentication** | Static bearer/basic/header auth for HTTP servers, env-based auth for stdio servers, authenticated vs unauthenticated access checks |
| **Security** | Tool poisoning (hidden instructions, zero-width chars, bidi overrides), data exfiltration patterns, dangerous tool names, missing input schemas, cross-tool shadowing |
| **Functional** | Tool descriptions, input schema validity, required field declarations, tool name quality, optional tool calling |
| **Performance** | Cold start time, list latency, ping latency, response sizes |
| **Supply Chain** | Vulnerability scanning, secret detection, misconfiguration (via Trivy integration) |
| **Runtime Security** | Sandbox execution with canary files, secret exfiltration detection, unauthorized file access, network egress monitoring, rug pull detection |
| **Manifest Diff** | Snapshot server metadata, diff against baseline to detect description/schema changes over time |

### Severity levels

- **● Critical** — Tool poisoning, canary token leaked, zero-width character injection
- **▲ High** — Exfiltration patterns, unauthorized file access, unapproved network egress
- **■ Medium** — Missing input schemas, dangerous tool names, invalid schemas
- **▪ Low** — Long descriptions, cross-tool references, slow responses
- **○ Info** — Passing checks

## Usage

```bash
# Test a stdio server
mcp-certify node my-server.js

# Test an HTTP server
mcp-certify --url http://localhost:3000/mcp

# JSON output for CI/CD
mcp-certify --json node my-server.js

# Actually call tools during testing (may have side effects)
mcp-certify --call-tools node my-server.js

# Run in sandbox with runtime security testing
mcp-certify --sandbox node my-server.js

# Fail on any medium or above finding
mcp-certify --fail-on medium node my-server.js

# Use a certification profile
mcp-certify --profile enterprise-strict node my-server.js

# Diff against a saved baseline
mcp-certify --baseline ./baseline.json node my-server.js

# Evaluate metadata against a custom Rego policy
mcp-certify --policy ./policy.rego node my-server.js

# Allow or deny specific hosts in policy checks
mcp-certify --allow-host api.github.com --deny-host example.net node my-server.js

# Test an authenticated stdio server
mcp-certify --auth-env MCP_CERTIFY_TOKEN=letmein --auth-required node my-server.js

# Test an authenticated HTTP server
mcp-certify --bearer-token "$TOKEN" --auth-required --url http://localhost:3000/mcp
```

Exit codes: `0` = certified, `1` = certification failed, `2` = fatal error.

## Architecture

```
src/
  cli.ts                          CLI entry point
  connect.ts                      Transport factory (stdio, HTTP, SSE fallback)
  runner.ts                       Orchestrates suites, evaluates gate rules
  reporter.ts                     Terminal + JSON output
  types/
    findings.ts                   Finding, Artifact, SuiteEvidence, Severity
    report.ts                     Blocker, CertificationDecision, GateRule
  suites/
    protocol.ts                   Protocol compliance checks
    authentication.ts             Auth config and unauthenticated access checks
    security.ts                   Static security scanning
    functional.ts                 Schema and metadata validation
    performance.ts                Latency and size benchmarks
    supplyChain.ts                Trivy-based dependency scanning
    runtimeSecurity.ts            Sandbox harness orchestrator
    manifestDiff.ts               Snapshot and diff server metadata
  integrations/
    mcp-validator.ts              Janix-ai/mcp-validator adapter
    trivy.ts                      Aqua Trivy adapter
    opa.ts                        OPA policy engine (built-in JS fallback)
  runtime/
    harness.ts                    Sandbox runner (isolated HOME, env, proxy)
    canaries.ts                   Fake credential files with detection tokens
    networkCapture.ts             HTTP/HTTPS capture proxy
    scenarios/
      secretExfil.ts              Detect server reading seeded secrets
      fileRead.ts                 Detect unauthorized file access
      networkEgress.ts            Detect unapproved outbound requests
      promptInjection.ts          Detect runtime description changes (rug pulls)
      resourceExfil.ts            Detect sensitive data in resources
  policy/
    default.rego                  Default OPA policy rules
  profiles/
    presets.ts                    author-self-check, registry-screening, enterprise-strict
fixtures/
  servers/
    vulnerable-server.ts          Intentionally broken (tool poisoning, exfil, injection)
    safe-server.ts                Reference implementation (100/100)
```

## Integrations (optional, not required)

The CLI works standalone. These external tools add depth when installed:

- **[mcp-validator](https://github.com/Janix-ai/mcp-validator)** — deeper protocol compliance testing (Python)
- **[Trivy](https://trivy.dev)** — vulnerability, secret, and misconfiguration scanning
- **[OPA](https://www.openpolicyagent.org)** — custom policy evaluation (built-in JS rules work without it)

## Certification profiles

| Profile | Suites | Thresholds |
|---|---|---|
| `author-self-check` | protocol, security, functional | Lenient, no sandbox |
| `registry-screening` | + supply chain, manifest diff | Moderate, minScore 75 |
| `enterprise-strict` | All including runtime | Zero tolerance, requires sandbox |

## Who uses it

- **MCP server authors** — run in CI to catch issues before publishing
- **Enterprise teams** — vet third-party servers before connecting to internal systems
- **Registry operators** — integrate quality scores into marketplaces

## Competitive landscape

| Tool | Coverage |
|---|---|
| MCP Inspector (official) | Manual debugging only |
| mcp-validator | Protocol compliance only |
| MCP Evals | LLM-scored quality, requires OpenAI key |
| MCP-Scan (now Snyk) | Security scanning only |
| **mcp-certify** | Protocol + security + functional + performance + supply chain + runtime sandbox + manifest diffing, unified certification decision |

## Status

Active development. Built for the [General Intelligence Fellowship](https://www.generalintelligence.com/).
