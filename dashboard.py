"""Rich CLI display -- Dragonbridge/Spamouflage Behavioral Fingerprint Analyzer (P68).

ASCII-safe: no Unicode box-drawing characters (cp1252 Windows terminal compatibility).
"""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from config import ATTRIBUTION_DISCLAIMER, TIER_COLORS
from models import AnalysisReport, CheckResult, ContentSample, FingerprintIndicator

console = Console()


def _tier_color(tier: str) -> str:
    return TIER_COLORS.get(tier, "white")


def _score_bar(score: float, width: int = 20) -> str:
    filled = int((score / 100.0) * width)
    return "[" + "#" * filled + "." * (width - filled) + "]"


def print_disclaimer() -> None:
    console.print(f"\n[dim]{ATTRIBUTION_DISCLAIMER}[/dim]")


def print_indicator(ind: FingerprintIndicator) -> None:
    console.print(f"\n[bold]{ind.indicator_id}[/bold] -- {ind.name}")
    console.print(f"  Category:   {ind.category}")
    console.print(f"  Description: {ind.description[:140]}")
    console.print(f"  Threshold:  {ind.threshold_description}")
    console.print(f"  Requires:   {', '.join(ind.check_requires) or 'text only'}")
    console.print(f"  Citation:   {ind.source_citation}")


def print_indicators_table(indicators: list[FingerprintIndicator]) -> None:
    tbl = Table(box=box.SIMPLE, show_header=True)
    tbl.add_column("ID", style="bold")
    tbl.add_column("Name")
    tbl.add_column("Category", justify="center")
    tbl.add_column("Source Report")
    tbl.add_column("Requires Data")

    for ind in indicators:
        requires = ", ".join(ind.check_requires) if ind.check_requires else "text only"
        tbl.add_row(
            ind.indicator_id,
            ind.name,
            ind.category,
            ind.source_report,
            requires,
        )
    console.print(tbl)
    console.print(f"[dim]{len(indicators)} indicators[/dim]")


def print_sample(sample: ContentSample) -> None:
    console.print(f"\n[bold]{sample.sample_id}[/bold]")
    console.print(f"  Platform: {sample.platform} | Language: {sample.language}")
    if sample.timestamp:
        console.print(f"  Timestamp: {sample.timestamp}")
    console.print(f"  Hashtags ({len(sample.hashtags)}): {', '.join(sample.hashtags[:5])}"
                  + ("..." if len(sample.hashtags) > 5 else ""))
    if sample.follower_count is not None:
        console.print(f"  Followers: {sample.follower_count:,} | "
                      f"Engagement: {sample.engagement_count}")
    text_preview = sample.text[:120].replace("\n", " ")
    console.print(f"  Text: {text_preview}...")


def print_check_results_table(results: list[CheckResult]) -> None:
    tbl = Table(box=box.SIMPLE, show_header=True)
    tbl.add_column("Indicator ID", style="bold")
    tbl.add_column("Name")
    tbl.add_column("Category", justify="center")
    tbl.add_column("Result", justify="center")
    tbl.add_column("Data", justify="center")

    for r in results:
        if not r.data_available:
            result_str = "[dim]NOT ASSESSED[/dim]"
        elif r.matched:
            result_str = "[red bold]PRESENT[/red bold]"
        else:
            result_str = "[green]ABSENT[/green]"
        data_str = "OK" if r.data_available else "[dim]--[/dim]"
        tbl.add_row(r.indicator_id, r.indicator_name, r.category, result_str, data_str)
    console.print(tbl)


def print_analysis_summary(report: AnalysisReport) -> None:
    tier_color = _tier_color(report.tier)
    bar = _score_bar(report.score)
    console.print(
        f"\n[bold]CIB Pattern Analysis:[/bold] {report.set_name}"
    )
    console.print(
        f"  Score: [{tier_color}]{report.score:.1f}/100[/{tier_color}]  "
        f"{bar}  [{tier_color}]{report.tier}[/{tier_color}]"
    )
    console.print(
        f"  Indicators: {report.matched_count} matched / "
        f"{report.assessable_count} assessable / 12 total"
    )
    console.print(f"  Samples: {report.sample_count}")
    print_disclaimer()


def print_report(report: AnalysisReport) -> None:
    if report.brief_text:
        console.print(
            Panel(report.brief_text, title="CIB Pattern Analysis Report", expand=True)
        )
