#!/usr/bin/env bash
# PKG Security Audit — Docker Entrypoint
#
# Usage:
#   docker build -t pkg-audit .
#   docker run --rm \
#     -v /path/to/target.pkg:/input/pkg:ro \
#     -v $(pwd)/output:/output \
#     -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
#     pkg-audit
#
# Output: ./output/report.json, ./output/report.md

set -euo pipefail

PKG_PATH="${1:-/input/pkg.pkg}"
OUTPUT_DIR="${2:-/output}"
WORK_DIR="${3:-/tmp/pkg-audit}"

echo "=== PKG Audit Tool v1.0 ==="
echo "Package: ${PKG_PATH}"
echo "Output:  ${OUTPUT_DIR}"
echo "Work:    ${WORK_DIR}"

if [ ! -f "${PKG_PATH}" ]; then
    echo "ERROR: Package not found at ${PKG_PATH}"
    echo "Usage: docker run --rm -v /path/to/pkg:/input/pkg:ro -v \$PWD/output:/output pkg-audit"
    exit 1
fi

mkdir -p "${OUTPUT_DIR}" "${WORK_DIR}"

# Copy pkg to writable work dir (handles read-only mounts)
cp "${PKG_PATH}" "${WORK_DIR}/target.pkg"

# Verify docker-agent is available
if ! command -v docker-agent &>/dev/null; then
    echo "ERROR: docker-agent not found in PATH"
    exit 1
fi

echo "=== Starting security audit ==="
echo ""

# Run the audit. docker-agent will:
#  - Read /app/cagent.yaml for agent definitions
#  - Auto-start the MCP server defined in toolset config
#  - Orchestrator agent spawns sub-agents in parallel
#  - All tools (expand_pkg, check_signature, etc.) are MCP tools
cd /app
docker-agent run \
    /app/cagent.yaml \
    --exec \
    --yolo \
    --working-dir "${WORK_DIR}" \
    "Perform a full security audit on the macOS pkg installer at ${WORK_DIR}/target.pkg.

     Follow the SKILL.md at /app/SKILL.md for methodology and domain knowledge.

     CRITICAL INSTRUCTIONS:
     1. Use the expand_pkg tool to extract: expand_pkg('${WORK_DIR}/target.pkg', '${WORK_DIR}/extracted')
     2. Use check_signature on the original pkg: check_signature('${WORK_DIR}/target.pkg')
     3. Spawn the signature-auditor, payload-inspector, script-analyzer, and
        binary-inspector sub-agents IN PARALLEL. Give each clear paths to analyze
        from the extracted directory at ${WORK_DIR}/extracted.
     4. Collect all findings from all sub-agents.
     5. Call generate_report with ALL findings: generate_report('${WORK_DIR}/target.pkg', <findings_json>, '${OUTPUT_DIR}')
     6. Use the MCP tools from the 'pkg-audit' server for ALL file operations.
        Do NOT try to read files directly."

RC=$?

echo ""
echo "=== Audit complete (exit code: ${RC}) ==="

# Show results
if [ -f "${OUTPUT_DIR}/report.json" ]; then
    echo "Reports generated:"
    echo "  JSON: ${OUTPUT_DIR}/report.json"
    echo "  MD:   ${OUTPUT_DIR}/report.md"
    echo ""
    echo "Executive summary:"
    python3 -c "
import json
with open('${OUTPUT_DIR}/report.json') as f:
    r = json.load(f)
ra = r.get('risk_assessment', {})
print(f\"  Score: {ra.get('overall_score', '?')}/100 ({ra.get('severity', '?')})\")
print(f\"  Findings: {len(r.get('findings', []))} total\")
for f in r.get('findings', [])[:3]:
    print(f\"    [{f.get('severity','?')}] {f.get('description','?')[:100]}\")
" 2>/dev/null || true
else
    echo "WARNING: No report generated. Check docker-agent output above for errors."
fi

exit ${RC}
