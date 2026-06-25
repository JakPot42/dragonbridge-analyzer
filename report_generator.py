"""Report generator -- demo text or Claude narrative synthesis (P68)."""
from __future__ import annotations

import os

from config import ATTRIBUTION_DISCLAIMER, CLAUDE_MODEL
from models import AnalysisReport
from seed_data import DEMO_REPORT_TEXT, DEMO_SETS


class ReportGeneratorError(Exception):
    pass


def generate_report(
    report: AnalysisReport,
    *,
    demo_mode: bool = True,
) -> tuple[str, list[str]]:
    """Return (brief_text, action_items) for an AnalysisReport.

    Demo mode for alpha-7: returns pre-baked DEMO_REPORT_TEXT.
    Demo mode for other sets: assembles structured text from report data.
    Live mode: calls Claude for narrative synthesis.
    """
    if demo_mode:
        if report.set_name == "alpha-7":
            return DEMO_REPORT_TEXT, _extract_action_items(DEMO_REPORT_TEXT)
        brief = _assemble_brief(report)
        return brief, _build_action_items(report)

    return _generate_with_claude(report)


def _extract_action_items(text: str) -> list[str]:
    items = []
    in_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if "RECOMMENDED NEXT STEPS" in stripped:
            in_section = True
            continue
        if in_section and stripped.startswith(("1.", "2.", "3.", "4.", "5.")):
            items.append(stripped)
    return items[:5]


def _build_action_items(report: AnalysisReport) -> list[str]:
    items = []
    matched = [r for r in report.check_results if r.matched]
    if report.tier in ("CRITICAL", "HIGH"):
        items.append(
            f"[{report.tier}] {report.matched_count} of {report.assessable_count} "
            "indicators matched -- preserve all sample metadata before further analysis"
        )
    if report.tier in ("CRITICAL", "HIGH", "MEDIUM"):
        items.append(
            "Submit sample set to relevant platform trust-and-safety teams "
            "with indicator report attached"
        )
    network = next((r for r in matched if r.indicator_id == "DB-IND-011"), None)
    if network:
        items.append(
            "[DB-IND-011] Closed amplification network detected -- "
            "map full sharing graph to identify seeder accounts"
        )
    seed = next((r for r in matched if r.indicator_id == "DB-IND-012"), None)
    if seed:
        items.append(
            "[DB-IND-012] Low-authority seed domain detected -- "
            "document domain for infrastructure correlation"
        )
    return items


def _assemble_brief(report: AnalysisReport) -> str:
    matched = [r for r in report.check_results if r.data_available and r.matched]
    absent = [r for r in report.check_results if r.data_available and not r.matched]
    no_data = [r for r in report.check_results if not r.data_available]

    lines = [
        "UNCLASSIFIED // FOR OFFICIAL USE ONLY -- NOT FOR DISTRIBUTION",
        "OPEN-SOURCE PATTERN ANALYSIS MEMORANDUM",
        "",
        "TO: Threat Intelligence Team",
        "FROM: P68 Dragonbridge/Spamouflage Behavioral Fingerprint Analyzer",
        f"RE: CIB Pattern Assessment -- {report.set_name}",
        f"DATE: {report.prepared_date}",
        "",
        "=" * 68,
        "FRAMING: PATTERN IDENTIFICATION ONLY -- NOT AN ATTRIBUTION CLAIM",
        "=" * 68,
        "",
        ATTRIBUTION_DISCLAIMER,
        "",
        "=" * 68,
        "I. EXECUTIVE SUMMARY",
        "=" * 68,
        "",
        f"COORDINATION PATTERN TIER: {report.tier}",
        f"Score: {report.score:.1f} / 100.0 -- {report.matched_count} of "
        f"{report.assessable_count} assessable indicators PRESENT",
        f"Content Set: {report.set_name} | Samples: {report.sample_count}",
        f"Date: {report.prepared_date}",
        "",
        "=" * 68,
        f"II. MATCHED INDICATORS ({report.matched_count} of {report.assessable_count})",
        "=" * 68,
        "",
    ]

    for r in matched:
        lines += [
            f"[PRESENT] {r.indicator_id} -- {r.indicator_name}",
            f"  Category: {r.category}",
            f"  Evidence: {r.evidence}",
            f"  Citation: {r.source_citation}",
            "",
        ]

    if absent:
        lines += ["=" * 68, "III. ABSENT INDICATORS", "=" * 68, ""]
        for r in absent:
            lines += [f"[ABSENT] {r.indicator_id} -- {r.indicator_name}", ""]

    if no_data:
        lines += ["=" * 68, "IV. NOT ASSESSED (insufficient data)", "=" * 68, ""]
        for r in no_data:
            lines += [
                f"[NOT ASSESSED] {r.indicator_id} -- {r.indicator_name}",
                f"  Reason: {r.evidence}",
                "",
            ]

    lines += [
        "=" * 68,
        "V. DISCLAIMER",
        "=" * 68,
        "",
        ATTRIBUTION_DISCLAIMER,
        "",
        "Assessment Tool: P68 Dragonbridge/Spamouflage Behavioral Fingerprint Analyzer",
    ]
    return "\n".join(lines)


def _generate_with_claude(report: AnalysisReport) -> tuple[str, list[str]]:
    """Call Claude to synthesize a narrative analysis."""
    import anthropic

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise ReportGeneratorError("ANTHROPIC_API_KEY not set")

    matched = [r for r in report.check_results if r.data_available and r.matched]
    findings_text = "\n".join(
        f"  - {r.indicator_id} ({r.indicator_name}): {r.evidence[:120]}"
        for r in matched
    )

    prompt = f"""You are an open-source influence-operation researcher writing a
pattern analysis memo. Use ONLY ASCII characters. Never make attribution claims.

CONTENT SET: {report.set_name}
TIER: {report.tier}
SCORE: {report.score:.1f}/100 ({report.matched_count} of {report.assessable_count} indicators)
DATE: {report.prepared_date}

MATCHED INDICATORS:
{findings_text}

Write a 5-section pattern analysis memo (ASCII only, use -- not em dashes):
I. Executive Summary
II. Indicator Findings Summary (bullet each matched indicator with citation)
III. Pattern Assessment (what the co-occurrence of these indicators means)
IV. Analyst Confidence and Limitations
V. Recommended Next Steps

CRITICAL RULES:
- Use ASCII only -- no Unicode characters
- Start memo with framing: PATTERN IDENTIFICATION ONLY -- NOT AN ATTRIBUTION CLAIM
- Never name any government, country, or specific actor as responsible
- Every indicator citation must reference only public reports
- Emphasize that pattern match does not equal attribution
"""

    try:
        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )
        brief_text = msg.content[0].text.strip()
    except Exception as e:
        raise ReportGeneratorError(f"Claude report generation failed: {e}") from e

    return brief_text, _build_action_items(report)
