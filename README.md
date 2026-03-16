# mcp-certify

One command to test if your MCP server actually works, is secure, and performs well.

```bash
npx mcp-certify ./my-server
```

## Problem

There are 18,000+ MCP servers and most of them are broken or insecure. The average server scores 34/100 on security. Registries disclaim "community servers are untested — use at your own risk." 38% of enterprises say quality/security concerns are blocking MCP adoption.

No tool exists that comprehensively tests an MCP server across all the dimensions that matter.

## What it does

Runs automated tests across four dimensions and outputs a composite quality score:

- **Protocol compliance** — Does it implement MCP correctly? JSON-RPC format, session management, capability negotiation, transport support (stdio, SSE, streamable-http)
- **Functional correctness** — Do the tools actually work? Input/output contract testing, error handling, edge cases, idempotency
- **Security** — Tool poisoning, prompt injection in descriptions, data exfiltration patterns, dependency vulnerabilities, rug pull detection (description changes after approval)
- **Performance** — Latency, token consumption, cold start time, concurrent request handling

Outputs a score (0-100), detailed breakdown, and a certification badge for your README.

## Who uses it

- **MCP server authors** — run in CI to catch issues before publishing
- **Enterprise teams** — vet third-party servers before connecting to internal systems
- **Registry operators** — integrate quality scores into marketplaces (Smithery, PulseMCP, official registry)

## Business model

- Free open-source CLI + GitHub Action
- Paid SaaS tier for continuous monitoring, team dashboards, historical analytics
- Enterprise tier for private registry scanning, custom policies, compliance reporting
- Certification badges (paid by server authors/registries)

## Competitive landscape

| Tool | Coverage |
|---|---|
| MCP Inspector (official) | Manual debugging only, no automation |
| mcp-validator | Protocol compliance only |
| MCP Evals | LLM-scored quality, requires OpenAI key |
| MCP-Scan (now Snyk) | Security scanning only |
| **mcp-certify** | All four dimensions, unified score, CI/CD native |

## Market context

- MCP ecosystem: 100 servers (Nov 2024) → 18,000+ (Mar 2026)
- 97M+ monthly SDK downloads
- Adopted by Anthropic, OpenAI, Google, Microsoft, AWS, Cloudflare, Block, Bloomberg
- MCP donated to Linux Foundation (AAIF) — protocol is here to stay
- Precedent: Socket.dev ($65M raised, 300%+ YoY growth) did this for npm. Snyk ($408M revenue) did it for dependencies.

## Tech stack (planned)

- TypeScript (matches MCP SDK ecosystem)
- CLI via commander/oclif
- GitHub Action for CI/CD distribution
- Web dashboard (React or Next.js) for SaaS tier

## Status

Early development. Built for the [General Intelligence Fellowship](https://www.generalintelligence.com/).
