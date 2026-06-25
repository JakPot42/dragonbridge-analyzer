"""CLI entry point -- Dragonbridge/Spamouflage Behavioral Fingerprint Analyzer (P68).

FRAMING: Pattern identification tool using public takedown reports.
Does NOT make attribution claims. Every indicator cites a public source.

Commands:
  analyze     Analyze a content set (demo or from JSON file)
  indicators  List all 12 documented fingerprint indicators
  indicator   Show detail for a single indicator
  report      Generate full analyst report for a demo set
  demo        Run full demonstration across all 3 demo content sets
"""
from __future__ import annotations

import json
import sys

import click
from rich.console import Console

from config import DEMO_MODE, DEMO_SET_NAMES, DEMO_SET_HIGH
from content_analyzer import analyze_content_set
from dashboard import (
    console,
    print_analysis_summary,
    print_check_results_table,
    print_disclaimer,
    print_indicator,
    print_indicators_table,
    print_report,
    print_sample,
)
from fingerprint_db import (
    all_indicators,
    demo_set_names,
    get_demo_set,
    get_indicator,
    indicators_by_category,
)
from models import ContentSample
from report_generator import generate_report, ReportGeneratorError
from seed_data import DEMO_REPORT_TEXT


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _samples_from_json(path: str) -> list[ContentSample]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        samples_raw = data.get("samples", [])
        if not samples_raw:
            console.print(f"[red]No 'samples' key found in {path}[/red]")
            sys.exit(1)
        return [ContentSample(**s) for s in samples_raw]
    except FileNotFoundError:
        console.print(f"[red]File not found: {path}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error reading {path}: {e}[/red]")
        sys.exit(1)


def _resolve_set(demo_name: str | None) -> tuple[str, list[ContentSample]]:
    if not demo_name:
        demo_name = DEMO_SET_HIGH
    samples = get_demo_set(demo_name)
    if samples is None:
        names = ", ".join(demo_set_names())
        console.print(f"[red]Demo set '{demo_name}' not found. Valid: {names}[/red]")
        sys.exit(1)
    return demo_name, samples


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.option("--live", is_flag=True, default=False, help="Live mode (requires ANTHROPIC_API_KEY)")
@click.pass_context
def cli(ctx: click.Context, live: bool) -> None:
    """P68 Dragonbridge/Spamouflage Behavioral Fingerprint Analyzer.

    Checks content samples against documented behavioral fingerprints from
    public takedown reports (Meta ATRs, Google/Mandiant, Stanford SIO).

    FRAMING: Pattern identification only. Does NOT make attribution claims.
    Every indicator cites the specific public report that documented it.
    """
    ctx.ensure_object(dict)
    ctx.obj["demo_mode"] = not live


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--set", "set_name", default=None, help="Demo set name (default: alpha-7)")
@click.option("--input", "input_file", default=None, help="JSON file with content samples")
@click.option("--verbose", is_flag=True, default=False, help="Show evidence for each indicator")
@click.pass_context
def analyze(ctx: click.Context, set_name: str | None, input_file: str | None, verbose: bool) -> None:
    """Analyze a content set against all 12 fingerprint indicators."""
    if input_file:
        samples = _samples_from_json(input_file)
        name = input_file
    else:
        name, samples = _resolve_set(set_name)

    console.print(f"\n[bold]Analyzing:[/bold] {name} ({len(samples)} samples)")
    print_disclaimer()

    report = analyze_content_set(samples, set_name=name)
    print_analysis_summary(report)

    console.print("\n[bold]Indicator Results:[/bold]")
    print_check_results_table(report.check_results)

    if verbose:
        console.print("\n[bold]Evidence Detail:[/bold]")
        for r in report.check_results:
            status = "PRESENT" if r.matched else ("NOT ASSESSED" if not r.data_available else "ABSENT")
            console.print(f"\n  [bold]{r.indicator_id}[/bold] [{status}]")
            console.print(f"    {r.evidence}")
            console.print(f"    Cite: {r.source_citation[:100]}")


# ---------------------------------------------------------------------------
# indicators
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--category", default=None, help="Filter by category: CONTENT/TIMING/ACCOUNT/NETWORK")
@click.pass_context
def indicators(ctx: click.Context, category: str | None) -> None:
    """List all 12 documented Dragonbridge/Spamouflage behavioral indicators."""
    if category:
        inds = indicators_by_category(category)
        if not inds:
            console.print(f"[red]No indicators for category '{category}'[/red]")
            return
    else:
        inds = all_indicators()

    print_indicators_table(inds)
    print_disclaimer()


# ---------------------------------------------------------------------------
# indicator
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("indicator_id")
@click.pass_context
def indicator(ctx: click.Context, indicator_id: str) -> None:
    """Show full detail for a single indicator (e.g. DB-IND-001)."""
    ind = get_indicator(indicator_id)
    if ind is None:
        valid = ", ".join(i.indicator_id for i in all_indicators())
        console.print(f"[red]Indicator '{indicator_id}' not found. Valid: {valid}[/red]")
        return
    print_indicator(ind)
    print_disclaimer()


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--set", "set_name", default=None, help="Demo set name (default: alpha-7)")
@click.option("--input", "input_file", default=None, help="JSON file with content samples")
@click.pass_context
def report(ctx: click.Context, set_name: str | None, input_file: str | None) -> None:
    """Generate full analyst report for a content set."""
    demo_mode = ctx.obj["demo_mode"]

    if input_file:
        samples = _samples_from_json(input_file)
        name = input_file
    else:
        name, samples = _resolve_set(set_name)

    analysis = analyze_content_set(samples, set_name=name)

    try:
        brief_text, action_items = generate_report(analysis, demo_mode=demo_mode)
    except ReportGeneratorError as e:
        console.print(f"[red]Report generation failed: {e}[/red]")
        return

    analysis.brief_text = brief_text
    print_report(analysis)

    if action_items:
        console.print("\n[bold]Recommended Next Steps:[/bold]")
        for item in action_items:
            console.print(f"  {item}")


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------

@cli.command()
@click.pass_context
def demo(ctx: click.Context) -> None:
    """Run full demonstration across all 3 demo content sets.

    Set 1: alpha-7         -- CRITICAL (12/12 indicators)
    Set 2: organic-baseline -- MINIMAL  (0/12 indicators)
    Set 3: borderline-medium -- MEDIUM  (5/12 indicators)
    """
    console.print("\n[bold]P68 Dragonbridge/Spamouflage Behavioral Fingerprint Analyzer[/bold]")
    console.print("[bold]DEMONSTRATION MODE -- 3 demo content sets[/bold]")
    print_disclaimer()

    for demo_name in demo_set_names():
        samples = get_demo_set(demo_name)
        assert samples is not None

        console.print(f"\n{'=' * 68}")
        console.print(f"[bold]Set: {demo_name}[/bold] ({len(samples)} samples)")
        console.print(f"{'=' * 68}")

        report_data = analyze_content_set(samples, set_name=demo_name)
        print_analysis_summary(report_data)
        print_check_results_table(report_data.check_results)

    console.print(f"\n{'=' * 68}")
    console.print("[bold]FULL REPORT -- alpha-7 (CRITICAL tier)[/bold]")
    console.print(f"{'=' * 68}")
    console.print(DEMO_REPORT_TEXT)

    console.print("\n[dim]Run 'analyze --set <name> --verbose' for indicator evidence detail.[/dim]")
    console.print("[dim]Run 'indicators' to see all 12 documented fingerprint indicators.[/dim]")
    print_disclaimer()


if __name__ == "__main__":
    cli()
