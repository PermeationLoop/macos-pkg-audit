# pkg-audit

Agentic security audit tool for macOS `.pkg` installer files. Runs in a Docker container on Linux — no macOS required.

Uses a multi-agent LLM workflow to recursively extract, inspect, and score `.pkg` files for security risks. Produces a structured JSON report and a human-readable Markdown summary.

## Quick Start

```bash
# 1. Build the image
docker build -t pkg-audit .

# 2. Create your .env file
cp .env.example .env
# Edit .env with your API keys

# 3. Run the audit
docker run --rm --env-file .env \
  -v ./your-sample.pkg:/input/input.pkg:ro \
  -v ./out:/output \
  pkg-audit
```

On completion, reports are written to `./out/report.json` and `./out/report.md`.

## What It Checks

| Dimension | Weight | What's Inspected |
|-----------|--------|------------------|
| Script Danger | 30% | RCE patterns, persistence, privilege escalation, data exfiltration, obfuscation |
| Signature Trust | 25% | CMS signature presence (Linux-limited; full chain validation needs macOS) |
| Payload Paths | 25% | LaunchDaemons, LaunchAgents, privileged helpers, /tmp abuse, SSH backdoors |
| File Permissions | 10% | setuid/setgid binaries, world-writable files |
| Binary Risk | 10% | Hardcoded URLs/IPs, keychain references, suspicious strings |

Risk score: **Low (0–25) / Medium (26–50) / High (51–75) / Critical (76–100)**

## LLM Provider Options

The tool uses `docker-agent` to orchestrate multiple LLM agents. You can use Anthropic, OpenAI, or any compatible API endpoint (OpenRouter, LiteLLM, local proxy).

### Standard Anthropic

```bash
docker run --rm \
  -v ./target.pkg:/input/input.pkg:ro \
  -v ./out:/output \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  pkg-audit
```

### Standard OpenAI

```bash
docker run --rm \
  -v ./target.pkg:/input/input.pkg:ro \
  -v ./out:/output \
  -e OPENAI_API_KEY=sk-... \
  pkg-audit
```

### OpenRouter (Anthropic-compatible mode)

```bash
docker run --rm \
  -v ./target.pkg:/input/input.pkg:ro \
  -v ./out:/output \
  -e ANTHROPIC_API_KEY=$OPENROUTER_API_KEY \
  -e ANTHROPIC_BASE_URL=https://openrouter.ai/api/v1/anthropic \
  pkg-audit
```

### OpenRouter (OpenAI-compatible mode)

```bash
docker run --rm \
  -v ./target.pkg:/input/input.pkg:ro \
  -v ./out:/output \
  -e OPENAI_API_KEY=$OPENROUTER_API_KEY \
  -e OPENAI_BASE_URL=https://openrouter.ai/api/v1 \
  pkg-audit
```

### Custom Self-Hosted LLM

```bash
docker run --rm \
  -v ./target.pkg:/input/input.pkg:ro \
  -v ./out:/output \
  -e ANTHROPIC_API_KEY=sk-local \
  -e ANTHROPIC_BASE_URL=https://your-litellm.example.com \
  pkg-audit
```

### Using `--env-file`

Set all variables in `.env` and pass the file:

```bash
docker run --rm --env-file .env \
  -v ./target.pkg:/input/input.pkg:ro \
  -v ./out:/output \
  pkg-audit
```

## Commands

```bash
# Build the Docker image
docker build -t pkg-audit .

# Run an audit (basic)
docker run --rm --env-file .env \
  -v /path/to/target.pkg:/input/input.pkg:ro \
  -v ./out:/output \
  pkg-audit

# Run with custom work directory (default: /tmp/pkg-audit)
docker run --rm --env-file .env \
  -v /path/to/target.pkg:/input/input.pkg:ro \
  -v ./out:/output \
  pkg-audit /input/input.pkg /output /custom/work
```

## File Structure

```
.
├── Dockerfile              # Debian-based image with xar, 7z, cpio, openssl
├── entrypoint.sh           # Container entrypoint — copies pkg, runs audit
├── cagent.yaml             # Agent definitions (orchestrator + 4 sub-agents)
├── SKILL.md                # Domain knowledge: pkg format, malware patterns, scoring
├── requirements.txt        # Python deps for MCP server
├── .env.example            # Environment variable reference
├── tools/
│   └── mcp_server.py       # FastMCP server — 11 tools for extraction & analysis
├── rules/
│   ├── suspicious_commands.yaml  # Regex patterns for malicious script commands
│   ├── risk_paths.yaml           # Path risk classification rules
│   └── scoring.yaml              # Risk scoring weights & thresholds
├── templates/              # (reserved for future templating)
└── .github/workflows/      # CI/CD
```

## MCP Tools

The Python MCP server (`tools/mcp_server.py`) exposes these tools:

| Tool | Description |
|------|-------------|
| `expand_pkg` | Recursively extract .pkg (XAR + gzip/cpio) |
| `read_script` | Read installer script contents |
| `apply_rules_to_script` | Pattern-match scripts against known malicious commands |
| `classify_path` | Classify an install path by risk level |
| `read_bom` | Parse Bill of Materials (best-effort on Linux) |
| `read_distribution` | Read Distribution.xml metadata |
| `read_package_info` | Read PackageInfo.xml metadata |
| `check_signature` | Inspect XAR CMS signature via openssl |
| `analyze_binary` | Extract strings, URLs, IPs from binaries |
| `read_plist` | Parse .plist files (binary and XML) |
| `generate_report` | Generate final report.json and report.md |

## Docker Image

Built on `python:3.11-slim` with these system dependencies:

- **p7zip-full** — XAR archive extraction (replaces the broken Debian `xar` package)
- **cpio** — Payload/Scripts decompression
- **openssl** — CMS signature inspection
- **file, binutils** — Binary type detection
- **docker-agent** — LLM agent orchestrator

## Platform Limitations

The audit runs on **Linux**. The following checks are limited:

- **Signature chain validation** — Only CMS structure inspection; full Apple CA chain and Gatekeeper verification requires macOS.
- **Notarization verification** — Not available on Linux.
- **BOM parsing** — Best-effort binary extraction; full metadata (permissions, checksums) requires `lsbom` on macOS.
- **Mach-O analysis** — Strings-only inspection; entitlement and per-binary code signing checks require macOS.

For complete trust validation, run on a macOS runner.
