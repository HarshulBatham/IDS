# local/cli/commands.py
"""
AeroGuard IDS - CLI Commands

Provides command-line interface for capture, analysis, and calibration.
Supports both interactive and scripted usage.
"""

import sys
import json
import logging
from pathlib import Path
from typing import Optional

try:
    import click
except ImportError:
    print("Error: Click is required for CLI. Install with: pip install click")
    sys.exit(1)

from local.cli.orchestrator import AnalysisOrchestrator

logger = logging.getLogger(__name__)


@click.group()
@click.option(
    "-v", "--verbose", is_flag=True, help="Enable verbose logging"
)
@click.pass_context
def cli(ctx, verbose):
    """
    AeroGuard IDS - Local Network Intrusion Detection System.

    Capture, analyze, and report on network traffic anomalies.
    All processing is performed locally without cloud dependencies.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose


@cli.command()
@click.pass_context
def list_interfaces(ctx):
    """List available network interfaces for capture."""
    verbose = ctx.obj.get("verbose", False)
    orchestrator = AnalysisOrchestrator(verbose=verbose)

    interfaces = orchestrator.list_interfaces()

    if not interfaces:
        click.echo("No active network interfaces found.")
        return

    click.echo(f"\nFound {len(interfaces)} active interface(s):\n")
    for iface in interfaces:
        click.echo(
            f"  {iface['name']:20} | IP: {iface['ip']:15} | "
            f"MTU: {iface['mtu']:4} | Wireless: {'Yes' if iface['is_wireless'] else 'No'}"
        )
    click.echo()


@cli.command()
@click.option(
    "-i",
    "--interface",
    required=True,
    help="Network interface (e.g., eth0, wlan0)",
)
@click.pass_context
def validate(ctx, interface):
    """Validate that an interface is capture-ready."""
    verbose = ctx.obj.get("verbose", False)
    orchestrator = AnalysisOrchestrator(verbose=verbose)

    is_valid = orchestrator.validate_interface(interface)
    sys.exit(0 if is_valid else 1)


@cli.command()
@click.option(
    "-i",
    "--interface",
    required=True,
    help="Network interface to capture from",
)
@click.option(
    "-d",
    "--duration",
    type=int,
    default=60,
    help="Capture duration in seconds (default: 60)",
)
@click.option(
    "-m",
    "--method",
    type=click.Choice(["scapy"]),
    default="scapy",
    help="Capture method: scapy (pure Python packet capture via Scapy)",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    help="Output PCAP file path (auto-generated if not specified)",
)
@click.pass_context
def capture(ctx, interface, duration, method, output):
    """Capture network traffic to PCAP file (using pure Python by default)."""
    verbose = ctx.obj.get("verbose", False)
    orchestrator = AnalysisOrchestrator(verbose=verbose)

    # Validate interface first
    if not orchestrator.validate_interface(interface):
        click.echo(
            f"Error: Interface '{interface}' is not ready. "
            "You may need to run with elevated privileges.",
            err=True,
        )
        sys.exit(1)

    # Perform capture
    result = orchestrator.capture_traffic(
        interface=interface,
        duration_seconds=duration,
        method=method,
        output_path=Path(output) if output else None,
    )

    if result["status"] == "success":
        click.echo(f"\n✓ Capture successful!")
        click.echo(f"  File: {result['pcap_path']}")
        click.echo(f"  Packets: {result.get('packet_count', 'unknown')}")
        click.echo(f"  Duration: {result['duration']}s\n")
        sys.exit(0)
    else:
        click.echo(f"\n✗ Capture failed: {result.get('error')}\n", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "-p",
    "--pcap",
    type=click.Path(exists=True),
    required=True,
    help="Path to PCAP file to analyze",
)
@click.option(
    "-b",
    "--baseline",
    type=click.Path(exists=True),
    help="Path to trained baseline model (.pkl)",
)
@click.option(
    "-c",
    "--contamination",
    type=float,
    default=0.1,
    help="Expected anomaly rate (0.0-1.0, default: 0.1)",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    help="Output JSON report path (default: analysis_<timestamp>.json)",
)
@click.pass_context
def detect(ctx, pcap, baseline, contamination, output):
    """Detect anomalies in a PCAP file."""
    verbose = ctx.obj.get("verbose", False)
    orchestrator = AnalysisOrchestrator(verbose=verbose)

    # Perform detection
    result = orchestrator.detect_anomalies(
        pcap_path=pcap,
        baseline_model_path=baseline,
        contamination=contamination,
    )

    if result["status"] == "success":
        click.echo(f"\n✓ Analysis complete!")
        click.echo(f"  Threat Level: {result['threat_level'].upper()}")
        click.echo(
            f"  Anomalies: {result['anomalous_count']}/{result['total_flows']} "
            f"({result['anomaly_percent']:.1f}%)"
        )

        # Save report if output specified
        if output:
            if orchestrator.save_analysis_report(result, output):
                click.echo(f"  Report: {output}")
        else:
            # Print JSON to stdout
            click.echo("\nDetailed Results:")
            click.echo(json.dumps(result, indent=2))

        click.echo()
        sys.exit(0)
    else:
        click.echo(f"\n✗ Analysis failed: {result.get('error')}\n", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "-i",
    "--interface",
    required=True,
    help="Network interface to capture from",
)
@click.option(
    "-d",
    "--duration",
    type=int,
    default=60,
    help="Baseline capture duration in seconds (default: 60)",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    help="Output model path (default: ~/.aerosguard/baseline.pkl)",
)
@click.pass_context
def calibrate(ctx, interface, duration, output):
    """Calibrate baseline traffic model for anomaly detection."""
    verbose = ctx.obj.get("verbose", False)
    orchestrator = AnalysisOrchestrator(verbose=verbose)

    # Validate interface first
    if not orchestrator.validate_interface(interface):
        click.echo(
            f"Error: Interface '{interface}' is not ready. "
            "You may need to run with elevated privileges.",
            err=True,
        )
        sys.exit(1)

    result = orchestrator.calibrate_baseline(
        interface=interface,
        duration_seconds=duration,
        output_model_path=output,
    )

    if result["status"] == "success":
        click.echo(f"\n✓ Baseline calibration complete!")
        click.echo(f"  Model: {result['model_path']}")
        click.echo(f"  Samples: {result['training_samples']}")
        click.echo(f"  Training Time: {result['training_time']:.2f}s\n")
        sys.exit(0)
    else:
        click.echo(f"\n✗ Calibration failed: {result.get('error')}\n", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "-i",
    "--interface",
    required=True,
    help="Network interface to capture from",
)
@click.option(
    "-d",
    "--duration",
    type=int,
    default=60,
    help="Capture duration in seconds (default: 60)",
)
@click.option(
    "-b",
    "--baseline",
    type=click.Path(exists=True),
    help="Path to baseline model (if not provided, will use captured data as baseline)",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    help="Output report path (default: analysis_<timestamp>.json)",
)
@click.pass_context
def run(ctx, interface, duration, baseline, output):
    """
    Full pipeline: capture traffic → detect anomalies → generate report.

    This is the main workflow: calibrate baseline once, then run this
    against live or suspected traffic with the baseline model.
    """
    verbose = ctx.obj.get("verbose", False)
    orchestrator = AnalysisOrchestrator(verbose=verbose)

    # Validate interface
    if not orchestrator.validate_interface(interface):
        click.echo(
            f"Error: Interface '{interface}' is not ready. "
            "You may need to run with elevated privileges.",
            err=True,
        )
        sys.exit(1)

    # Step 1: Capture
    click.echo("\n" + "=" * 60)
    click.echo("STEP 1: CAPTURE TRAFFIC")
    click.echo("=" * 60)
    capture_result = orchestrator.capture_traffic(
        interface=interface,
        duration_seconds=duration,
        method="scapy",
    )

    if capture_result["status"] != "success":
        click.echo(
            f"Error: Capture failed - {capture_result.get('error')}", err=True
        )
        sys.exit(1)

    pcap_path = capture_result["pcap_path"]
    click.echo(f"\n✓ Captured {capture_result.get('packet_count', '?')} packets")

    # Step 2: Detect
    click.echo("\n" + "=" * 60)
    click.echo("STEP 2: DETECT ANOMALIES")
    click.echo("=" * 60)
    analysis_result = orchestrator.detect_anomalies(
        pcap_path=pcap_path,
        baseline_model_path=baseline,
        contamination=0.1,
    )

    if analysis_result["status"] != "success":
        click.echo(f"Error: Analysis failed - {analysis_result.get('error')}", err=True)
        sys.exit(1)

    click.echo(f"\n✓ Analysis complete!")
    click.echo(f"  Threat Level: {analysis_result['threat_level'].upper()}")
    click.echo(
        f"  Anomalies: {analysis_result['anomalous_count']}"
        f"/{analysis_result['total_flows']} "
        f"({analysis_result['anomaly_percent']:.1f}%)"
    )

    # Step 3: Save report
    click.echo("\n" + "=" * 60)
    click.echo("STEP 3: GENERATE REPORT")
    click.echo("=" * 60)

    if output:
        report_path = output
    else:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = str(orchestrator.cache_dir / f"analysis_{timestamp}.json")

    if orchestrator.save_analysis_report(analysis_result, report_path):
        click.echo(f"\n✓ Report saved: {report_path}\n")
        sys.exit(0)
    else:
        click.echo(f"\nError: Failed to save report to {report_path}", err=True)
        sys.exit(1)


def main():
    """Entry point for CLI."""
    cli(obj={})


if __name__ == "__main__":
    main()
