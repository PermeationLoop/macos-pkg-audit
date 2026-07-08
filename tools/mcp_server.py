#!/usr/bin/env python3
"""MCP server providing tools for macOS pkg security audit.

This server is designed to be used by docker-agent agents during the audit workflow.
Provides tools for: pkg extraction, payload inspection, script analysis,
binary inspection, and report generation.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("pkg-audit")

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def _load_yaml(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


@mcp.tool()
def expand_pkg(pkg_path: str, output_dir: str) -> str:
    """Expand a macOS .pkg installer file recursively into an output directory.

    Handles flat packages (XAR archives), component packages, and distribution packages.
    Recursively expands nested .pkg files found inside payloads.

    Args:
        pkg_path: Absolute path to the .pkg file to expand
        output_dir: Absolute path where expanded contents will be written

    Returns:
        JSON string with expansion summary: directory tree, component list, script paths
    """
    pkg_path = os.path.abspath(pkg_path)
    output_dir = os.path.abspath(output_dir)
    # pkgutil requires the directory NOT to exist; remove it if present
    import shutil
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)

    result = {
        "output_dir": output_dir,
        "components": [],
        "scripts": [],
        "distribution": None,
        "payload_files": [],
        "errors": [],
    }

    # Check if xar is available (Linux) or use pkgutil (macOS)
    xar_available = subprocess.run(["which", "xar"], capture_output=True).returncode == 0
    pkgutil_available = subprocess.run(["which", "pkgutil"], capture_output=True).returncode == 0

    if pkgutil_available:
        # macOS: use pkgutil --expand-full (recursive)
        r = subprocess.run(
            ["pkgutil", "--expand-full", pkg_path, output_dir],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            result["errors"].append(f"pkgutil expand: {r.stderr.strip()}")
    elif xar_available:
        # Linux: use xar + gzip + cpio
        # Step 1: extract xar
        r = subprocess.run(
            ["xar", "-xf", pkg_path, "-C", output_dir],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            result["errors"].append(f"xar extract: {r.stderr.strip()}")
            return json.dumps(result, indent=2)

        # Step 2: find and expand Payload files
        for root, dirs, files in os.walk(output_dir):
            if "Payload" in files:
                payload_path = os.path.join(root, "Payload")
                payload_dir = os.path.join(root, "Payload_expanded")
                os.makedirs(payload_dir, exist_ok=True)

                # Decompress gzip
                cpio_path = payload_path + ".cpio"
                r = subprocess.run(
                    f"gzip -dc '{payload_path}' > '{cpio_path}'",
                    shell=True, capture_output=True, text=True,
                )
                if r.returncode == 0:
                    # Extract cpio
                    r = subprocess.run(
                        f"cpio -i -D '{payload_dir}' < '{cpio_path}'",
                        shell=True, capture_output=True, text=True,
                    )
                    if r.returncode != 0:
                        result["errors"].append(f"cpio extract {payload_path}: {r.stderr.strip()}")
                    os.remove(cpio_path)
                else:
                    # Try tar format (newer macOS)
                    r = subprocess.run(
                        ["tar", "-xf", payload_path, "-C", payload_dir],
                        capture_output=True, text=True,
                    )
                    if r.returncode != 0:
                        result["errors"].append(f"tar extract {payload_path}: {r.stderr.strip()}")
    else:
        result["errors"].append("Neither pkgutil (macOS) nor xar (Linux) available")

    # Scan the expanded directory for structure
    for root, dirs, files in os.walk(output_dir):
        rel = os.path.relpath(root, output_dir)
        for f in files:
            fpath = os.path.join(rel, f) if rel != "." else f
            result["payload_files"].append(fpath)

            if f == "Distribution":
                result["distribution"] = os.path.join(root, f)
            elif f in ("preinstall", "postinstall", "preupgrade", "postupgrade",
                       "preremove", "postremove"):
                result["scripts"].append({
                    "path": os.path.join(root, f),
                    "type": f,
                    "component": os.path.basename(os.path.dirname(root)) if "Scripts" in rel else "root",
                })
            elif f == "PackageInfo":
                result["components"].append({"package_info": os.path.join(root, f), "dir": root})

    # Also find scripts in Scripts directories that have non-standard names
    for root, dirs, files in os.walk(output_dir):
        if os.path.basename(root) == "Scripts":
            for f in files:
                script_path = os.path.join(root, f)
                if not any(s["path"] == script_path for s in result["scripts"]):
                    result["scripts"].append({
                        "path": script_path,
                        "type": f,
                        "component": os.path.basename(os.path.dirname(root)),
                    })

    return json.dumps(result, indent=2)


@mcp.tool()
def read_script(script_path: str) -> str:
    """Read the full contents of an installer script file.

    Args:
        script_path: Absolute path to the script file (preinstall, postinstall, etc.)

    Returns:
        The script content as a string, or error message if unreadable
    """
    try:
        with open(script_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        # Detect shebang
        first_line = content.split("\n")[0].strip() if content else ""
        shebang = first_line if first_line.startswith("#!") else "none"
        # Detect if binary
        if "\x00" in content[:4096]:
            return json.dumps({
                "error": "File appears to be binary, not a readable script",
                "path": script_path,
                "size": os.path.getsize(script_path),
            }, indent=2)
        return json.dumps({
            "path": script_path,
            "shebang": shebang,
            "size": len(content),
            "lines": content.count("\n") + 1,
            "content": content,
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "path": script_path}, indent=2)


@mcp.tool()
def apply_rules_to_script(script_text: str) -> str:
    """Apply suspicious command pattern rules to script content and return matches.

    Uses the suspicious_commands.yaml ruleset. Each rule is a regex pattern
    categorized by severity (critical, high, medium, low).

    Args:
        script_text: The full text content of a shell script

    Returns:
        JSON string with matched rules, categorized by severity
    """
    rules = _load_yaml(RULES_DIR / "suspicious_commands.yaml")
    findings: dict[str, list[dict[str, Any]]] = {
        "critical": [], "high": [], "medium": [], "low": []
    }

    lines = script_text.split("\n")
    for pattern in rules.get("patterns", []):
        try:
            regex = re.compile(pattern["pattern"])
            for i, line in enumerate(lines, 1):
                if regex.search(line):
                    findings[pattern["severity"]].append({
                        "rule_id": pattern["id"],
                        "description": pattern["description"],
                        "line": i,
                        "matched_text": line.strip()[:200],
                    })
        except re.error:
            continue

    # Summary
    summary = {sev: len(items) for sev, items in findings.items()}
    total = sum(summary.values())
    return json.dumps({
        "total_matches": total,
        "summary": summary,
        "findings": findings,
    }, indent=2)


@mcp.tool()
def classify_path(install_path: str) -> str:
    """Classify an install path by risk level using the risk_paths.yaml rules.

    Args:
        install_path: The file install path (e.g., '/Library/LaunchDaemons/com.example.plist')

    Returns:
        JSON string with risk classification and reason
    """
    rules = _load_yaml(RULES_DIR / "risk_paths.yaml")
    path = install_path.rstrip("/")

    # Check path prefixes (longest match first)
    path_rules = sorted(
        rules.get("paths", []),
        key=lambda r: len(r.get("prefix", "").rstrip("/")),
        reverse=True,
    )
    for rule in path_rules:
        prefix = rule["prefix"].rstrip("/")
        if path.startswith(prefix):
            return json.dumps({
                "path": install_path,
                "risk": rule["risk"],
                "reason": rule["reason"],
                "matched_prefix": prefix,
            }, indent=2)

    # Check file type by extension
    ext = os.path.splitext(path)[1].lower()
    for ft in rules.get("file_types", []):
        if ext == ft["extension"]:
            return json.dumps({
                "path": install_path,
                "risk": ft["risk"],
                "reason": ft["reason"],
                "matched_extension": ext,
            }, indent=2)

    return json.dumps({
        "path": install_path,
        "risk": "info",
        "reason": "No specific risk rules matched",
    }, indent=2)


@mcp.tool()
def read_bom(bom_path: str) -> str:
    """Read and parse a Bill of Materials (BOM) file from an expanded pkg.

    Uses lsbom on macOS, or reads the binary BOM format directly on Linux.

    Args:
        bom_path: Absolute path to the BOM file

    Returns:
        JSON string with file entries including path, permissions, owner, group
    """
    try:
        # Try lsbom first
        r = subprocess.run(["lsbom", bom_path], capture_output=True, text=True)
        if r.returncode == 0:
            entries = []
            for line in r.stdout.strip().split("\n"):
                if line.strip():
                    parts = line.split("\t")
                    if len(parts) >= 3:
                        entries.append({
                            "path": parts[0],
                            "mode": parts[1] if len(parts) > 1 else "unknown",
                            "owner_group": parts[2] if len(parts) > 2 else "0/0",
                        })
            return json.dumps({
                "bom_path": bom_path,
                "entry_count": len(entries),
                "entries": entries,
            }, indent=2)
        else:
            # Fallback: try to read as raw binary and extract paths
            with open(bom_path, "rb") as f:
                data = f.read()
            # Extract readable strings as paths
            paths = []
            current = bytearray()
            for b in data:
                if 32 <= b < 127:
                    current.append(b)
                else:
                    if len(current) > 3:
                        s = current.decode("ascii", errors="ignore")
                        if s.startswith("./") or s.startswith("/"):
                            paths.append(s)
                    current = bytearray()
            return json.dumps({
                "bom_path": bom_path,
                "raw_size": len(data),
                "extracted_paths": paths[:500],
                "path_count": len(paths),
                "note": "Limited parsing (lsbom not available on Linux)",
            }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "bom_path": bom_path}, indent=2)


@mcp.tool()
def read_distribution(dist_path: str) -> str:
    """Read and return the contents of a Distribution XML file from a distribution package.

    Args:
        dist_path: Absolute path to the Distribution file

    Returns:
        JSON string with parsed contents including: package references, options,
        title, auth requirement, welcome/bg resources
    """
    try:
        with open(dist_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        # Extract key information with regex (avoid XML parsing issues)
        info: dict[str, Any] = {
            "path": dist_path,
            "size": len(content),
            "raw_xml": content,
        }
        # Check for auth="Root"
        if 'auth="Root"' in content:
            info["requires_root"] = True
        if 'auth="' in content:
            import re as _re
            m = _re.search(r'auth="(\w+)"', content)
            if m:
                info["auth"] = m.group(1)
        # Extract package references
        import re as _re
        pkg_refs = _re.findall(r'<pkg-ref[^>]+id="([^"]+)"', content)
        if pkg_refs:
            info["component_ids"] = pkg_refs
        # Check for installer plugin scripts
        if "<script" in content:
            info["has_installer_script"] = True
        # Check for JavaScript in Distribution
        if "function" in content and ("javascript" in content.lower() or "system.run" in content):
            info["has_javascript"] = True
        # Check for title
        m = _re.search(r'<title[^>]*>(.*?)</title>', content, _re.DOTALL)
        if m:
            info["title"] = m.group(1).strip()
        return json.dumps(info, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "path": dist_path}, indent=2)


@mcp.tool()
def read_package_info(pkg_info_path: str) -> str:
    """Read and parse a PackageInfo XML file from a component package.

    Args:
        pkg_info_path: Absolute path to the PackageInfo file

    Returns:
        JSON string with package metadata: identifier, version, install-location,
        overwrite-permissions, etc.
    """
    try:
        with open(pkg_info_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        import re as _re
        info: dict[str, Any] = {"path": pkg_info_path}
        m = _re.search(r'identifier="([^"]+)"', content)
        if m:
            info["identifier"] = m.group(1)
        m = _re.search(r'version="([^"]+)"', content)
        if m:
            info["version"] = m.group(1)
        m = _re.search(r'install-location="([^"]*)"', content)
        info["install_location"] = m.group(1) if m else "/"
        # Check for overwrite-permissions
        if "overwrite-permissions" in content:
            info["overwrite_permissions"] = True
        if "relocatable" in content:
            info["relocatable"] = True
        # Get payload size
        m = _re.search(r'payload\s+size="(\d+)"', content)
        if m:
            info["payload_size_bytes"] = int(m.group(1))
        return json.dumps(info, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "path": pkg_info_path}, indent=2)


@mcp.tool()
def check_signature(pkg_path: str) -> str:
    """Check the code signing status of a pkg file.

    Uses pkgutil --check-signature on macOS or inspects XAR CMS signature on Linux.

    Args:
        pkg_path: Absolute path to the .pkg file

    Returns:
        JSON string with signature status, certificate chain, notarization info
    """
    result: dict[str, Any] = {"path": pkg_path, "platform": sys.platform}

    # Try pkgutil first (macOS)
    r = subprocess.run(
        ["pkgutil", "--check-signature", pkg_path],
        capture_output=True, text=True,
    )
    if r.returncode == 0:
        output = r.stdout + r.stderr
        result["raw_output"] = output
        # Parse key fields
        if "Status: signed" in output:
            result["status"] = "signed"
        elif "Status: revoked" in output:
            result["status"] = "revoked"
        else:
            result["status"] = "unsigned_or_error"

        if "Notarization: trusted" in output:
            result["notarization"] = "trusted"
        elif "Notarization:" in output:
            result["notarization"] = "untrusted"

        # Extract signer
        import re as _re
        m = _re.search(r'Developer ID Installer:\s*(.+?)\s*\(', output)
        if m:
            result["signer"] = m.group(1).strip()
        return json.dumps(result, indent=2)

    # Linux fallback: try openssl CMS inspection
    try:
        subprocess.run(["which", "openssl"], capture_output=True, check=True)
        r = subprocess.run(
            ["openssl", "cms", "-verify", "-noverify", "-in", pkg_path,
             "-inform", "DER", "-noout"],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            result["status"] = "signed (limited Linux check)"
        else:
            r2 = subprocess.run(
                ["openssl", "cms", "-cmsout", "-print", "-in", pkg_path,
                 "-inform", "DER"],
                capture_output=True, text=True,
            )
            result["raw_output"] = r2.stdout[:2000] if r2.stdout else r2.stderr[:2000]
            result["status"] = "inspectable (Linux, limited check)"
    except Exception:
        result["status"] = "uncheckable_linux"
        result["note"] = "Full signature validation requires macOS (pkgutil + spctl)"

    return json.dumps(result, indent=2)


@mcp.tool()
def analyze_binary(binary_path: str) -> str:
    """Analyze a binary file from a pkg payload.

    Extracts: file type, architecture, printable strings (truncated),
    linked libraries, and basic Mach-O structure info.

    Args:
        binary_path: Absolute path to the binary file

    Returns:
        JSON string with analysis results
    """
    result: dict[str, Any] = {
        "path": binary_path,
        "size_bytes": os.path.getsize(binary_path),
    }

    # File type detection
    r = subprocess.run(["file", "-b", binary_path], capture_output=True, text=True)
    result["file_type"] = r.stdout.strip()

    # Extract strings (first 200 — enough to catch URLs, paths, suspicious patterns)
    try:
        r = subprocess.run(
            ["strings", "-n", "5", binary_path],
            capture_output=True, text=True, timeout=15,
        )
        strings = r.stdout.strip().split("\n")
        result["strings_count"] = len(strings)
        # Filter interesting strings
        urls = [s for s in strings if re.search(r'https?://', s)]
        ips = [s for s in strings if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', s)]
        suspicious = [s for s in strings if re.search(
            r'(com\.apple\.(launchd|system)|key.?chain|admin|root|sudo|spctl|csrutil)',
            s, re.IGNORECASE,
        )]
        result["url_found"] = urls[:20]
        result["ip_found"] = ips[:10]
        result["suspicious_strings"] = suspicious[:30]
    except Exception as e:
        result["strings_error"] = str(e)

    # Try otool -L on macOS
    r = subprocess.run(["which", "otool"], capture_output=True, text=True)
    if r.returncode == 0:
        r = subprocess.run(
            ["otool", "-L", binary_path],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            libs = r.stdout.strip().split("\n")[1:]  # skip first line
            result["linked_libraries"] = [l.strip().split(" (")[0].strip() for l in libs if l.strip()]

    return json.dumps(result, indent=2)


@mcp.tool()
def read_plist(plist_path: str) -> str:
    """Read a .plist file and convert to readable JSON. Handles binary and XML plists.

    Args:
        plist_path: Absolute path to the .plist file

    Returns:
        JSON string with parsed plist content
    """
    try:
        r = subprocess.run(
            ["plutil", "-convert", "json", "-o", "-", plist_path],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            data = json.loads(r.stdout)
            return json.dumps({"path": plist_path, "content": data}, indent=2)
    except Exception:
        pass
    try:
        # Fallback for Linux: try plistlib
        import plistlib
        with open(plist_path, "rb") as f:
            data = plistlib.load(f)
        return json.dumps({"path": plist_path, "content": data}, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e), "path": plist_path}, indent=2)


@mcp.tool()
def generate_report(
    package_path: str,
    findings_json: str,
    output_dir: str,
) -> str:
    """Generate the final security audit report in JSON and Markdown formats.

    Args:
        package_path: Original pkg file path (for metadata)
        findings_json: JSON string containing all audit findings from all agents
        output_dir: Directory where report files will be written

    Returns:
        JSON string with paths to generated report files
    """
    import datetime
    os.makedirs(output_dir, exist_ok=True)

    findings = json.loads(findings_json) if isinstance(findings_json, str) else findings_json

    # Build structured report
    report = {
        "audit_metadata": {
            "package": os.path.basename(package_path),
            "package_path": package_path,
            "audit_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "audit_environment": sys.platform,
            "audit_tool": "pkg-audit v1.0",
            "macos_features_unavailable": (
                [] if sys.platform == "darwin"
                else ["signature_chain_validation", "gatekeeper_check", "notarization_verify"]
            ),
        },
        "findings": findings.get("findings", []),
        "signature": findings.get("signature", {}),
        "scripts_analyzed": findings.get("scripts_analyzed", []),
        "payload_analysis": findings.get("payload_analysis", {}),
    }

    # Compute risk score
    scoring_rules = _load_yaml(RULES_DIR / "scoring.yaml")
    score_breakdown = {
        "signature_trust": {"score": 0, "max": scoring_rules["weights"]["signature_trust"], "findings": []},
        "payload_paths": {"score": 0, "max": scoring_rules["weights"]["payload_paths"], "findings": []},
        "script_danger": {"score": 0, "max": scoring_rules["weights"]["script_danger"], "findings": []},
        "binary_risk": {"score": 0, "max": scoring_rules["weights"]["binary_risk"], "findings": []},
        "file_permissions": {"score": 0, "max": scoring_rules["weights"]["file_permissions"], "findings": []},
    }

    severity_weights = scoring_rules["finding_severity_weights"]
    max_findings = scoring_rules["max_findings_per_severity"]

    for finding in report["findings"]:
        sev = finding.get("severity", "low")
        dim = finding.get("dimension", "script_danger")
        if dim in score_breakdown:
            weight = severity_weights.get(sev, 1)
            score_breakdown[dim]["score"] += weight
            score_breakdown[dim]["findings"].append(finding)

    # Normalize each dimension
    overall = 0
    for dim, data in score_breakdown.items():
        max_weight = scoring_rules["weights"][dim]
        # Cap at dimension max
        data["score"] = min(data["score"], max_weight)
        overall += data["score"]
        # Normalized percentage
        data["percentage"] = round((data["score"] / max_weight) * 100, 1) if max_weight > 0 else 0

    overall = min(overall, 100)

    # Determine severity
    thresholds = scoring_rules["severity_thresholds"]
    if overall <= thresholds["low_max"]:
        severity = "low"
    elif overall <= thresholds["medium_max"]:
        severity = "medium"
    elif overall <= thresholds["high_max"]:
        severity = "high"
    else:
        severity = "critical"

    report["risk_assessment"] = {
        "overall_score": overall,
        "severity": severity,
        "score_breakdown": score_breakdown,
    }

    # Write JSON report
    json_path = os.path.join(output_dir, "report.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    # Generate Markdown report
    md_lines = []
    pkg_name = os.path.basename(package_path)
    md_lines.append(f"# PKG Security Audit Report")
    md_lines.append(f"")
    md_lines.append(f"**Package:** `{pkg_name}`")
    md_lines.append(f"**Audit Date:** {report['audit_metadata']['audit_timestamp']}")
    md_lines.append(f"**Audit Platform:** {sys.platform}")
    md_lines.append(f"")

    # Executive summary
    md_lines.append(f"## Executive Summary")
    md_lines.append(f"")
    sev_emoji = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}
    md_lines.append(f"| Metric | Value |")
    md_lines.append(f"|--------|-------|")
    md_lines.append(f"| **Overall Risk Score** | **{overall}/100** |")
    md_lines.append(f"| **Severity** | {sev_emoji.get(severity, '⚪')} **{severity.upper()}** |")
    sig_status = report.get("signature", {}).get("status", "unknown")
    md_lines.append(f"| **Signature Status** | {sig_status} |")
    total_findings = len(report["findings"])
    critical_count = sum(1 for f in report["findings"] if f.get("severity") == "critical")
    high_count = sum(1 for f in report["findings"] if f.get("severity") == "high")
    md_lines.append(f"| **Total Findings** | {total_findings} ({critical_count} critical, {high_count} high) |")
    md_lines.append(f"")

    # Score breakdown
    md_lines.append(f"### Score Breakdown")
    md_lines.append(f"")
    md_lines.append(f"| Dimension | Score | Max | % |")
    md_lines.append(f"|-----------|-------|-----|---|")
    for dim, data in score_breakdown.items():
        dim_label = dim.replace("_", " ").title()
        md_lines.append(f"| {dim_label} | {data['score']} | {data['max']} | {data['percentage']}% |")
    md_lines.append(f"")

    # Findings
    md_lines.append(f"## Findings")
    md_lines.append(f"")
    if not report["findings"]:
        md_lines.append(f"*No security issues found.*")
    else:
        for sev_level in ["critical", "high", "medium", "low"]:
            sev_findings = [f for f in report["findings"] if f.get("severity") == sev_level]
            if sev_findings:
                md_lines.append(f"### {sev_level.upper()} ({len(sev_findings)})")
                md_lines.append(f"")
                for finding in sev_findings:
                    md_lines.append(f"- **{finding.get('rule_id', finding.get('id', '?'))}**: {finding.get('description', 'No description')}")
                    if finding.get("location"):
                        md_lines.append(f"  - Location: `{finding['location']}`")
                    if finding.get("detail"):
                        md_lines.append(f"  - Detail: {finding['detail']}")
                    md_lines.append(f"")

    # Signature details
    if report.get("signature"):
        sig = report["signature"]
        md_lines.append(f"## Signature Information")
        md_lines.append(f"")
        md_lines.append(f"| Field | Value |")
        md_lines.append(f"|-------|-------|")
        for k, v in sig.items():
            if k != "raw_output":
                md_lines.append(f"| {k} | {v} |")
        md_lines.append(f"")

    # Recommendations
    md_lines.append(f"## Recommendations")
    md_lines.append(f"")
    if severity == "critical":
        md_lines.append(f"- **DO NOT INSTALL** this package. It exhibits critical security risks.")
        md_lines.append(f"- Report this package to the software vendor immediately.")
        md_lines.append(f"- If already installed, consider isolating the affected system.")
    elif severity == "high":
        md_lines.append(f"- **Strongly reconsider** installing this package.")
        md_lines.append(f"- Contact the vendor about the flagged items before proceeding.")
        md_lines.append(f"- If installation is required, monitor system behavior closely post-install.")
    elif severity == "medium":
        md_lines.append(f"- **Review findings carefully** before installing.")
        md_lines.append(f"- Verify the package source and signature manually.")
        md_lines.append(f"- Consider testing in an isolated environment first.")
    else:
        md_lines.append(f"- **Low risk.** Standard caution advised when installing third-party software.")
        md_lines.append(f"- Verify you downloaded from the official source.")
    md_lines.append(f"")

    if report["audit_metadata"].get("macos_features_unavailable"):
        md_lines.append(f"### Platform Limitations")
        md_lines.append(f"")
        md_lines.append(f"Audit ran on `{sys.platform}`. The following checks were limited:")
        for feat in report["audit_metadata"]["macos_features_unavailable"]:
            md_lines.append(f"- {feat.replace('_', ' ').title()}")
        md_lines.append(f"")
        md_lines.append(f"Run on macOS for full signature chain validation and Gatekeeper assessment.")
        md_lines.append(f"")

    md_path = os.path.join(output_dir, "report.md")
    with open(md_path, "w") as f:
        f.write("\n".join(md_lines))

    return json.dumps({
        "json_report": json_path,
        "markdown_report": md_path,
        "overall_score": overall,
        "severity": severity,
    }, indent=2)


if __name__ == "__main__":
    mcp.run()
