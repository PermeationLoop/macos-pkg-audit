#!/usr/bin/env python3
"""MCP server providing tools for macOS pkg security audit.

Runs on Linux (Docker). Uses 7z/xar/cpio for extraction, openssl for
signature inspection, and pure Python for BOM/plist parsing.
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("pkg-audit")
RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def _load_yaml(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


# ── extraction ────────────────────────────────────────────────────────

@mcp.tool()
def expand_pkg(pkg_path: str, output_dir: str) -> str:
    """Expand a macOS .pkg file recursively into an output directory.

    Handles flat packages (XAR archives). Extracts Payload (gzip+cpio/tar)
    and enumerates Distribution, PackageInfo, Scripts, and BOM files.

    Args:
        pkg_path: Absolute path to the .pkg file
        output_dir: Absolute path where expanded contents are written
    """
    pkg_path = os.path.abspath(pkg_path)
    output_dir = os.path.abspath(output_dir)

    result = {
        "output_dir": output_dir,
        "components": [],
        "scripts": [],
        "distribution": None,
        "payload_files": [],
        "errors": [],
    }

    # ── validate input ──
    if not os.path.isfile(pkg_path):
        result["errors"].append(f"File not found: {pkg_path}")
        return json.dumps(result, indent=2)

    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    # ── Step 1: extract xar archive ──
    r = subprocess.run(
        ["7z", "x", "-txar", pkg_path, f"-o{output_dir}"],
        capture_output=True, text=True,
    )
    if r.returncode not in (0, 1):
        result["errors"].append(f"7z extract failed: {r.stderr.strip()} {r.stdout.strip()}")
        return json.dumps(result, indent=2)

    # ── Step 2: expand any gzip+cpio archives (Payload, Scripts) ──
    for root, dirs, files in os.walk(output_dir):
        for fname in files:
            if fname not in ("Payload", "Scripts"):
                continue
            archive_path = os.path.join(root, fname)
            # Check if it's actually gzip (some Payloads are tar)
            r = subprocess.run(["file", "-b", archive_path],
                               capture_output=True, text=True)
            ft = r.stdout.lower()

            archive_dir = os.path.join(root, f"{fname}_expanded")
            os.makedirs(archive_dir, exist_ok=True)

            if "gzip" in ft:
                cpio_tmp = archive_path + ".cpio"
                rc = subprocess.run(
                    f"gzip -dc '{archive_path}' > '{cpio_tmp}'",
                    shell=True, capture_output=True, text=True,
                ).returncode
                if rc == 0 and os.path.getsize(cpio_tmp) > 0:
                    r2 = subprocess.run(
                        f"cpio -i -D '{archive_dir}' < '{cpio_tmp}'",
                        shell=True, capture_output=True, text=True,
                    )
                    if r2.returncode != 0:
                        result["errors"].append(
                            f"cpio failed for {archive_path}: {r2.stderr.strip()}"
                        )
                    os.remove(cpio_tmp)
                else:
                    if os.path.exists(cpio_tmp):
                        os.remove(cpio_tmp)
                    # try tar as fallback
                    r2 = subprocess.run(
                        ["tar", "-xf", archive_path, "-C", archive_dir],
                        capture_output=True, text=True,
                    )
                    if r2.returncode != 0:
                        result["errors"].append(
                            f"tar failed for {archive_path}: {r2.stderr.strip()}"
                        )
            elif "tar" in ft or "POSIX tar" in r.stdout:
                r2 = subprocess.run(
                    ["tar", "-xf", archive_path, "-C", archive_dir],
                    capture_output=True, text=True,
                )
                if r2.returncode != 0:
                    result["errors"].append(
                        f"tar failed for {archive_path}: {r2.stderr.strip()}"
                    )

    # ── Step 3: scan the resulting tree ──
    for root, dirs, files in os.walk(output_dir):
        rel = os.path.relpath(root, output_dir)
        for f in files:
            fpath = os.path.join(rel, f) if rel != "." else f
            result["payload_files"].append(fpath)

            if f == "Distribution":
                result["distribution"] = os.path.join(root, f)
            elif f in (
                "preinstall", "postinstall", "preupgrade", "postupgrade",
                "preremove", "postremove",
            ):
                result["scripts"].append({
                    "path": os.path.join(root, f),
                    "type": f,
                    "component": os.path.basename(os.path.dirname(root))
                    if "Scripts" in rel else "root",
                })
            elif f == "PackageInfo":
                result["components"].append({
                    "package_info": os.path.join(root, f),
                    "dir": root,
                })

    # Pick up scripts with non-standard names inside Scripts/ dirs
    for root, dirs, files in os.walk(output_dir):
        if os.path.basename(root) != "Scripts":
            continue
        for f in files:
            sp = os.path.join(root, f)
            if not any(s["path"] == sp for s in result["scripts"]):
                result["scripts"].append({
                    "path": sp,
                    "type": f,
                    "component": os.path.basename(os.path.dirname(root)),
                })

    return json.dumps(result, indent=2)


# ── script analysis ────────────────────────────────────────────────────

@mcp.tool()
def read_script(script_path: str) -> str:
    """Read the full contents of an installer script file.

    Args:
        script_path: Absolute path to the script
    """
    try:
        with open(script_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        first_line = content.split("\n")[0].strip() if content else ""
        shebang = first_line if first_line.startswith("#!") else "none"
        if "\x00" in content[:4096]:
            return json.dumps({
                "error": "Binary file, not a readable script",
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
    """Apply suspicious command patterns to script content.

    Uses the suspicious_commands.yaml ruleset. Returns matches
    categorized by severity.
    """
    rules = _load_yaml(RULES_DIR / "suspicious_commands.yaml")
    findings: dict[str, list[dict[str, Any]]] = {
        "critical": [], "high": [], "medium": [], "low": [],
    }
    lines = script_text.split("\n")
    for pat in rules.get("patterns", []):
        try:
            regex = re.compile(pat["pattern"])
            for i, line in enumerate(lines, 1):
                if regex.search(line):
                    findings[pat["severity"]].append({
                        "rule_id": pat["id"],
                        "description": pat["description"],
                        "line": i,
                        "matched_text": line.strip()[:200],
                    })
        except re.error:
            continue
    summary = {sev: len(items) for sev, items in findings.items()}
    return json.dumps({
        "total_matches": sum(summary.values()),
        "summary": summary,
        "findings": findings,
    }, indent=2)


# ── path / bom / metadata ─────────────────────────────────────────────

@mcp.tool()
def classify_path(install_path: str) -> str:
    """Classify an install path by risk level.

    Uses risk_paths.yaml rules. Checks path prefixes and file extensions.
    """
    rules = _load_yaml(RULES_DIR / "risk_paths.yaml")
    path = install_path.rstrip("/")
    path_rules = sorted(
        rules.get("paths", []),
        key=lambda r: len(r.get("prefix", "").rstrip("/")),
        reverse=True,
    )
    for rule in path_rules:
        if path.startswith(rule["prefix"].rstrip("/")):
            return json.dumps({
                "path": install_path,
                "risk": rule["risk"],
                "reason": rule["reason"],
                "matched_prefix": rule["prefix"].rstrip("/"),
            }, indent=2)
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
    """Parse a BOM (Bill of Materials) file.

    On Linux this does a best-effort binary parse to extract file paths.
    """
    try:
        with open(bom_path, "rb") as f:
            data = f.read()
        # Walk through the binary BOM and pull out ASCII paths
        paths: list[str] = []
        current = bytearray()
        for b in data:
            if 32 <= b < 127:
                current.append(b)
            else:
                s = current.decode("ascii", errors="ignore")
                if len(s) > 3 and (s.startswith("./") or s.startswith("/")):
                    paths.append(s)
                current = bytearray()
        # Catch last segment
        s = current.decode("ascii", errors="ignore")
        if len(s) > 3 and (s.startswith("./") or s.startswith("/")):
            paths.append(s)

        return json.dumps({
            "bom_path": bom_path,
            "raw_size": len(data),
            "extracted_paths": paths[:500],
            "path_count": len(paths),
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "bom_path": bom_path}, indent=2)


@mcp.tool()
def read_distribution(dist_path: str) -> str:
    """Read a Distribution XML file from a distribution package.

    Extracts: component IDs, auth requirement, JavaScript usage, title.
    """
    try:
        with open(dist_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        info: dict[str, Any] = {
            "path": dist_path,
            "size": len(content),
        }
        if 'auth="Root"' in content:
            info["requires_root"] = True
        m = re.search(r'auth="(\w+)"', content)
        if m:
            info["auth"] = m.group(1)
        pkg_refs = re.findall(r'<pkg-ref[^>]+id="([^"]+)"', content)
        if pkg_refs:
            info["component_ids"] = pkg_refs
        if "<script" in content:
            info["has_installer_script"] = True
        if "function" in content and (
            "javascript" in content.lower() or "system.run" in content
        ):
            info["has_javascript"] = True
        m = re.search(r'<title[^>]*>(.*?)</title>', content, re.DOTALL)
        if m:
            info["title"] = m.group(1).strip()
        return json.dumps(info, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "path": dist_path}, indent=2)


@mcp.tool()
def read_package_info(pkg_info_path: str) -> str:
    """Read a PackageInfo XML file from a component package.

    Extracts: identifier, version, install-location, permissions flags.
    """
    try:
        with open(pkg_info_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        info: dict[str, Any] = {"path": pkg_info_path}
        for key, pat in [
            ("identifier", r'identifier="([^"]+)"'),
            ("version", r'version="([^"]+)"'),
        ]:
            m = re.search(pat, content)
            if m:
                info[key] = m.group(1)
        m = re.search(r'install-location="([^"]*)"', content)
        info["install_location"] = m.group(1) if m else "/"
        if "overwrite-permissions" in content:
            info["overwrite_permissions"] = True
        if "relocatable" in content:
            info["relocatable"] = True
        m = re.search(r'payload\s+size="(\d+)"', content)
        if m:
            info["payload_size_bytes"] = int(m.group(1))
        return json.dumps(info, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "path": pkg_info_path}, indent=2)


# ── signature (Linux) ─────────────────────────────────────────────────

@mcp.tool()
def check_signature(pkg_path: str) -> str:
    """Inspect the XAR CMS signature of a pkg file using openssl.

    Limited Linux check — full Apple chain validation is NOT possible.
    Reports whether a CMS signature is present and dumps its content.
    """
    result: dict[str, Any] = {
        "path": pkg_path,
        "platform": "linux",
        "signature_support": "limited",
        "note": "Full Apple certificate chain and notarization validation requires macOS",
    }
    if not os.path.isfile(pkg_path):
        result["status"] = "file_not_found"
        return json.dumps(result, indent=2)

    try:
        subprocess.run(["which", "openssl"], capture_output=True, check=True)
        # verify CMS structure
        r = subprocess.run(
            ["openssl", "cms", "-verify", "-noverify", "-in", pkg_path,
             "-inform", "DER", "-noout"],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            result["status"] = "signed_cms_present"
        else:
            # try to dump whatever CMS data is there
            r2 = subprocess.run(
                ["openssl", "cms", "-cmsout", "-print", "-in", pkg_path,
                 "-inform", "DER"],
                capture_output=True, text=True, timeout=10,
            )
            if r2.returncode == 0 and r2.stdout.strip():
                result["status"] = "cms_content_extracted"
                result["raw_output"] = r2.stdout[:3000]
            else:
                result["status"] = "no_cms_signature_found"
                result["raw_output"] = (
                    r2.stderr.strip() if r2.stderr else r.stderr.strip()
                )[:2000]
    except Exception as e:
        result["status"] = "uncheckable"
        result["error"] = str(e)

    return json.dumps(result, indent=2)


# ── binary analysis ────────────────────────────────────────────────────

@mcp.tool()
def analyze_binary(binary_path: str) -> str:
    """Analyze a binary file from a pkg payload.

    Extracts: file type, printable strings, URLs/IPs found in strings.
    """
    result: dict[str, Any] = {
        "path": binary_path,
        "size_bytes": os.path.getsize(binary_path),
    }
    r = subprocess.run(["file", "-b", binary_path], capture_output=True, text=True)
    result["file_type"] = r.stdout.strip()

    try:
        r = subprocess.run(
            ["strings", "-n", "5", binary_path],
            capture_output=True, text=True, timeout=15,
        )
        strings = r.stdout.strip().split("\n")
        result["strings_count"] = len(strings)
        result["url_found"] = [
            s for s in strings if re.search(r'https?://', s)
        ][:20]
        result["ip_found"] = [
            s for s in strings
            if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', s)
        ][:10]
        result["suspicious_strings"] = [
            s for s in strings
            if re.search(
                r'(com\.apple\.(launchd|system)|key.?chain|admin|root|sudo|spctl|csrutil)',
                s, re.IGNORECASE,
            )
        ][:30]
    except Exception as e:
        result["strings_error"] = str(e)

    return json.dumps(result, indent=2)


# ── plist ──────────────────────────────────────────────────────────────

@mcp.tool()
def read_plist(plist_path: str) -> str:
    """Read a .plist file and convert to JSON. Handles binary and XML plists."""
    try:
        import plistlib
        with open(plist_path, "rb") as f:
            data = plistlib.load(f)
        return json.dumps({"path": plist_path, "content": data}, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e), "path": plist_path}, indent=2)


# ── report generation ──────────────────────────────────────────────────

@mcp.tool()
def generate_report(
    package_path: str,
    findings_json: str,
    output_dir: str,
) -> str:
    """Generate the final security audit report (JSON + Markdown).

    Args:
        package_path: Original pkg file path
        findings_json: JSON string of all audit findings
        output_dir: Directory for report files

    Returns:
        JSON with paths to report.json and report.md
    """
    import datetime

    os.makedirs(output_dir, exist_ok=True)
    findings = json.loads(findings_json) if isinstance(findings_json, str) else findings_json

    report = {
        "audit_metadata": {
            "package": os.path.basename(package_path),
            "package_path": package_path,
            "audit_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "audit_environment": "linux",
            "audit_tool": "pkg-audit v1.0",
        },
        "findings": findings.get("findings", []),
        "signature": findings.get("signature", {}),
        "scripts_analyzed": findings.get("scripts_analyzed", []),
        "payload_analysis": findings.get("payload_analysis", {}),
    }

    # ── risk scoring ──
    scoring_rules = _load_yaml(RULES_DIR / "scoring.yaml")
    weights = scoring_rules["weights"]
    sev_w = scoring_rules["finding_severity_weights"]

    score_breakdown = {
        dim: {"score": 0, "max": weights[dim], "findings": []}
        for dim in weights
    }

    # category → dimension fallback mapping
    _category_to_dim = {
        "code_signing": "signature_trust",
        "payload": "payload_paths",
        "installer_script": "script_danger",
        "supply_chain": "script_danger",
        "auto_update": "script_danger",
        "privilege_escalation": "file_permissions",
        "binary_analysis": "binary_risk",
    }

    for finding in report["findings"]:
        dim = finding.get("dimension") or _category_to_dim.get(
            finding.get("category", ""), "script_danger"
        )
        if dim in score_breakdown:
            sev = (finding.get("severity") or "low").lower()
            w = sev_w.get(sev, 1)
            score_breakdown[dim]["score"] += w
            score_breakdown[dim]["findings"].append(finding)

    overall = 0
    for dim, data in score_breakdown.items():
        data["score"] = min(data["score"], weights[dim])
        overall += data["score"]
        data["percentage"] = round(
            (data["score"] / weights[dim]) * 100, 1
        ) if weights[dim] > 0 else 0

    overall = min(overall, 100)
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

    # ── write JSON ──
    json_path = os.path.join(output_dir, "report.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    # ── write Markdown ──
    pkg_name = os.path.basename(package_path)
    sev_emoji = {"low": "\U0001f7e2", "medium": "\U0001f7e1",
                 "high": "\U0001f7e0", "critical": "\U0001f534"}
    emoji = sev_emoji.get(severity, "\u26aa")

    total_f = len(report["findings"])
    crit = sum(1 for f in report["findings"] if (f.get("severity") or "").lower() == "critical")
    high = sum(1 for f in report["findings"] if (f.get("severity") or "").lower() == "high")

    md = [
        f"# PKG Security Audit Report",
        f"",
        f"**Package:** `{pkg_name}`",
        f"**Audit Date:** {report['audit_metadata']['audit_timestamp']}",
        f"**Audit Platform:** Linux (xar/cpio extraction)",
        f"",
        f"## Executive Summary",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| **Overall Risk Score** | **{overall}/100** |",
        f"| **Severity** | {emoji} **{severity.upper()}** |",
        f"| **Signature Status** | {findings.get('signature', {}).get('status', 'unknown')} |",
        f"| **Total Findings** | {total_f} ({crit} critical, {high} high) |",
        f"",
        f"### Score Breakdown",
        f"",
        f"| Dimension | Score | Max | % |",
        f"|-----------|-------|-----|---|",
    ]
    for dim, data in score_breakdown.items():
        md.append(
            f"| {dim.replace('_', ' ').title()} | {data['score']} | "
            f"{data['max']} | {data['percentage']}% |"
        )
    md.append("")

    # ── findings ──
    md.append("## Findings")
    md.append("")
    if not report["findings"]:
        md.append("*No security issues found.*")
    else:
        for sev in ("critical", "high", "medium", "low", "info"):
            sf = [f for f in report["findings"] if (f.get("severity") or "").lower() == sev]
            if not sf:
                continue
            md.append(f"### {sev.upper()} ({len(sf)})")
            md.append("")
            for finding in sf:
                rid = finding.get("rule_id", "?")
                title = finding.get("title") or finding.get("description", "No description")
                md.append(f"- **{rid}**: {title}")
                desc = finding.get("description")
                if desc and desc != title:
                    md.append(f"  - {desc}")
                impact = finding.get("impact")
                if impact:
                    md.append(f"  - Impact: {impact}")
                remediation = finding.get("remediation")
                if remediation:
                    md.append(f"  - Remediation: {remediation}")
                if finding.get("location"):
                    md.append(f"  - Location: `{finding['location']}`")
                md.append("")

    # ── signature ──
    sig = findings.get("signature", {})
    if sig:
        md.append("## Signature Information")
        md.append("")
        md.append("| Field | Value |")
        md.append("|-------|-------|")
        for k, v in sig.items():
            if k != "raw_output":
                md.append(f"| {k} | {v} |")
        md.append("")

    # ── recommendations ──
    md.append("## Recommendations")
    md.append("")
    recs = {
        "critical": [
            "- **DO NOT INSTALL.** Critical security risks detected.",
            "- Report to the software vendor immediately.",
            "- Isolate any system where this package was installed.",
        ],
        "high": [
            "- **Strongly reconsider** installing this package.",
            "- Contact the vendor about flagged items before proceeding.",
            "- If unavoidable, monitor system behavior post-install.",
        ],
        "medium": [
            "- **Review findings carefully** before installing.",
            "- Verify package source and signature manually.",
            "- Test in an isolated environment first.",
        ],
        "low": [
            "- **Low risk.** Standard caution advised.",
            "- Verify you downloaded from the official source.",
        ],
    }
    md.extend(recs.get(severity, recs["low"]))
    md.append("")

    # ── platform note ──
    md.append("### Platform Limitations")
    md.append("")
    md.append(
        "Audit ran on **Linux**. The following checks are limited:\n"
        "- **Signature chain validation**: only CMS structure inspection; "
        "full Apple CA chain and Gatekeeper verification requires macOS.\n"
        "- **Notarization verification**: not available on Linux.\n"
        "- **BOM parsing**: best-effort binary extraction; full metadata "
        "(permissions, checksums) requires `lsbom` on macOS.\n"
        "- For complete trust validation, run the audit on a macOS runner."
    )
    md.append("")

    md_path = os.path.join(output_dir, "report.md")
    with open(md_path, "w") as f:
        f.write("\n".join(md))

    return json.dumps({
        "json_report": json_path,
        "markdown_report": md_path,
        "overall_score": overall,
        "severity": severity,
    }, indent=2)


if __name__ == "__main__":
    mcp.run()
