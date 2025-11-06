#!/usr/bin/env python3

import argparse
import socket
import time
import threading
import logging
import sys
import os
from ftplib import FTP
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    MofNCompleteColumn
)
from rich.panel import Panel
from rich.table import Table
from rich.traceback import install
from rich.logging import RichHandler
from rich import print as rprint
from rich.layout import Layout
from rich.live import Live
from rich.tree import Tree
from rich.syntax import Syntax
from rich.align import Align
from datetime import datetime
from rich.prompt import Prompt
from rich.style import Style
from rich.text import Text
from rich.box import HEAVY, ROUNDED

# Install rich traceback handler
install(show_locals=True)

# Initialize rich console
console = Console()

# Configure logging with rich handler
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(rich_tracebacks=True, markup=True)]
)

logger = logging.getLogger("ftp_destroyer")

class FTPDestroyer:
    def __init__(self, timeout=3, max_workers=20, output_file="vuln.txt"):
        """Initialize FTP Destroyer with custom settings."""
        self.timeout = timeout
        self.max_workers = max_workers
        self.output_file = output_file
        self.successful_targets = []
        self.failed_targets = []
        self.current_target = None
        self.stats = {
            "total": 0,
            "success": 0,
            "failed": 0,
            "start_time": None,
            "end_time": None,
            "current_speed": 0,
            "avg_speed": 0,
            "remaining_time": 0
        }
        self.event_log = []
        self.max_event_log = 8
        self.layout = self._create_layout()

    def _create_layout(self):
        """Create the main layout for the display."""
        layout = Layout()
        
        # Split layout vertically
        layout.split(
            Layout(name="header", size=5),
            Layout(name="main"),
            Layout(name="footer", size=12)
        )
        
        # Split main section horizontally
        layout["main"].split_row(
            Layout(name="progress", ratio=2),
            Layout(name="stats", ratio=1)
        )

        # Split footer horizontally into current target and event log
        layout["footer"].split_row(
            Layout(name="current", ratio=1),
            Layout(name="events", ratio=2)
        )
        
        return layout

    def generate_banner(self):
        """Generate the application banner."""
        banner_text = """
╭══════════════════════════════════════════════════════════╮
│        [bold cyan]FTP LOGIN DESTROYER[/bold cyan] [bold magenta]2.0[/bold magenta]            │
│        [bright_black]Enhanced Security Scanner • 2025[/bright_black]          │
│           Created with [red]❤[/red] by Security Research            │
╰══════════════════════════════════════════════════════════╯
"""
        return Panel(
            Align.center(banner_text, vertical="middle"),
            style="bold blue",
            border_style="blue",
            box=HEAVY,
            padding=(0, 2)
        )

    def generate_stats_panel(self):
        """Generate the statistics panel with improved layout."""
        stats_table = Table(
            show_header=True,
            header_style="bold cyan",
            box=ROUNDED,
            show_edge=True,
            border_style="cyan",
            pad_edge=True,
            padding=(0, 2)
        )
        
        stats_table.add_column("Metric", justify="left", style="cyan")
        stats_table.add_column("Value", justify="right", style="green")
        
        stats_table.add_row("Total Targets", f"[cyan]{self.stats['total']}[/cyan]")
        stats_table.add_row("Successful", f"[green]{self.stats['success']}[/green]")
        stats_table.add_row("Failed", f"[red]{self.stats['failed']}[/red]")
        
        if self.stats['total'] > 0:
            success_rate = (self.stats['success'] / self.stats['total']) * 100
            stats_table.add_row("Success Rate", f"[yellow]{success_rate:.1f}%[/yellow]")
        
        if self.stats['current_speed'] > 0:
            stats_table.add_row("Current Speed", f"[magenta]{self.stats['current_speed']:.1f} t/s[/magenta]")
            stats_table.add_row("Average Speed", f"[magenta]{self.stats['avg_speed']:.1f} t/s[/magenta]")

        return Panel(
            stats_table,
            title="[bold cyan]Scan Statistics[/bold cyan]",
            border_style="cyan",
            box=ROUNDED,
            padding=(1, 2)
        )

    def generate_current_target_panel(self):
        """Generate the current target information panel with improved layout."""
        if not self.current_target:
            content = "[yellow]Initializing scan...[/yellow]"
        else:
            content = Table.grid(padding=(0, 1))
            content.add_column(style="bold cyan", justify="left")
            content.add_column(style="yellow")
            content.add_row("Target:", self.current_target)
            content.add_row("Port:", "21")
            content.add_row("Status:", "[bold green]Scanning...[/bold green]")

        return Panel(
            content,
            title="[bold yellow]Current Target[/bold yellow]",
            border_style="yellow",
            box=ROUNDED,
            padding=(1, 2)
        )

    def generate_event_log_panel(self):
        """Generate a live event log panel of recent scan results."""
        table = Table(
            show_header=True,
            header_style="bold magenta",
            box=ROUNDED,
            border_style="magenta",
            pad_edge=False
        )
        table.add_column("Time", style="bright_black")
        table.add_column("Host", style="cyan")
        table.add_column("Result", justify="right")

        if not self.event_log:
            table.add_row("-", "-", "[yellow]waiting...[/yellow]")
        else:
            for event in reversed(self.event_log[-self.max_event_log:]):
                table.add_row(event["time"], event["host"], event["result"]) 

        return Panel(
            table,
            title="[bold magenta]Live Events[/bold magenta]",
            border_style="magenta",
            box=ROUNDED,
            padding=(0, 1)
        )

    def _log_event(self, host, ok, message=""):
        timestamp = datetime.now().strftime("%H:%M:%S")
        result_text = f"[green]OK[/green] {message}" if ok else f"[red]FAIL[/red] {message}"
        self.event_log.append({
            "time": timestamp,
            "host": host,
            "result": result_text
        })
        if len(self.event_log) > self.max_event_log * 2:
            self.event_log = self.event_log[-self.max_event_log:]

    def is_port_open(self, hostname, port):
        """Check if specified port is open."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((hostname, port))
                return True
        except Exception as e:
            logger.debug(f"Port check failed for {hostname}: {str(e)}")
            return False

    def test_ftp_credentials(self, hostname, username="anonymous", password="anonymous"):
        """Test FTP connection and anonymous login."""
        self.current_target = hostname
        
        if not self.is_port_open(hostname, 21):
            self.failed_targets.append({
                "host": hostname,
                "error": "Port 21 closed",
                "timestamp": datetime.now()
            })
            self._log_event(hostname, False, "port 21 closed")
            return False

        try:
            with FTP() as ftp:
                ftp.connect(hostname, timeout=self.timeout)
                ftp.login(username, password)
                
                # Get additional server info
                server_info = {
                    "host": hostname,
                    "banner": ftp.getwelcome(),
                    "current_dir": ftp.pwd(),
                    "system_type": ftp.system(),
                    "features": ftp.features() if hasattr(ftp, 'features') else None,
                    "timestamp": datetime.now()
                }
                
                # Try to get list of files
                try:
                    files = []
                    ftp.dir(files.append)
                    server_info["files"] = files[:5]  # Store first 5 files only
                except:
                    server_info["files"] = []
                
                self.successful_targets.append(server_info)
                self._log_event(hostname, True, "anonymous login allowed")
                return True
                
        except Exception as e:
            self.failed_targets.append({
                "host": hostname,
                "error": str(e),
                "timestamp": datetime.now()
            })
            self._log_event(hostname, False, str(e))
            return False

    def save_html_report(self):
        """Generate and save HTML report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"ftp_scan_report_{timestamp}.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>FTP Scan Report - {timestamp}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f0f0f0; }}
                .success {{ color: green; }}
                .fail {{ color: red; }}
                .container {{ margin: 20px 0; padding: 20px; border-radius: 5px; background-color: white; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                .stats {{ display: flex; justify-content: space-around; flex-wrap: wrap; }}
                .stat-box {{ 
                    padding: 20px;
                    margin: 10px;
                    min-width: 200px;
                    border-radius: 5px;
                    background-color: white;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    text-align: center;
                }}
                .target-info {{
                    border-left: 4px solid;
                    padding: 10px;
                    margin: 10px 0;
                }}
                .success-info {{ border-color: green; }}
                .fail-info {{ border-color: red; }}
                pre {{ background: #f5f5f5; padding: 10px; border-radius: 4px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>FTP Login Destroyer Scan Report</h1>
                <p>Scan Time: {datetime.now()}</p>
                <p>Duration: {self.stats['end_time'] - self.stats['start_time']}</p>
            </div>
            
            <div class="stats">
                <div class="stat-box">
                    <h3>Total Targets</h3>
                    <p>{self.stats['total']}</p>
                </div>
                <div class="stat-box">
                    <h3>Successful</h3>
                    <p class="success">{self.stats['success']}</p>
                </div>
                <div class="stat-box">
                    <h3>Failed</h3>
                    <p class="fail">{self.stats['failed']}</p>
                </div>
                <div class="stat-box">
                    <h3>Success Rate</h3>
                    <p>{(self.stats['success']/self.stats['total'])*100:.2f}%</p>
                </div>
            </div>
            
            <div class="container">
                <h2>Successful Targets</h2>
                {''.join([f"""
                <div class="target-info success-info">
                    <h3>{target['host']}</h3>
                    <pre>{target['banner']}</pre>
                    <p><strong>System Type:</strong> {target['system_type']}</p>
                    <p><strong>Initial Directory:</strong> {target['current_dir']}</p>
                    <p><strong>Timestamp:</strong> {target['timestamp']}</p>
                    {'<div><strong>Sample Files:</strong><ul>' + ''.join([f'<li>{file}</li>' for file in target['files']]) + '</ul></div>' if target['files'] else ''}
                </div>
                """ for target in self.successful_targets])}
            </div>
            
            <div class="container">
                <h2>Failed Targets</h2>
                {''.join([f"""
                <div class="target-info fail-info">
                    <h3>{target['host']}</h3>
                    <p><strong>Error:</strong> {target['error']}</p>
                    <p><strong>Timestamp:</strong> {target['timestamp']}</p>
                </div>
                """ for target in self.failed_targets])}
            </div>
        </body>
        </html>
        """
        
        with open(report_file, "w") as f:
            f.write(html_content)

        # Save vulnerable targets to the output file
        with open(self.output_file, "w") as f:
            for target in self.successful_targets:
                f.write(f"{target['host']}\n")

        return report_file

    def process_targets(self, targets):
        """Process the list of targets with improved progress display."""
        self.stats["total"] = len(targets)
        self.stats["start_time"] = datetime.now()
        start_time = time.time()
        completed = 0

        progress_cols = [
            SpinnerColumn(style="magenta"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(
                bar_width=None,
                style="cyan",
                complete_style="green",
                finished_style="green"
            ),
            MofNCompleteColumn(),
            TextColumn("•"),
            TimeElapsedColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
        ]

        # Create progress
        progress = Progress(
            *progress_cols,
            expand=True,
            transient=False
        )
        
        # Add progress to the layout
        self.layout["progress"].update(progress)
        
        # Create a single Live display
        with Live(
            self.layout,
            refresh_per_second=10,
            screen=True,
            console=console
        ) as live:
            # Add the scanning task with enhanced display
            scan_task = progress.add_task(
                "\n[bold cyan]╭──────────────── FTP Scan Progress ──────────────────╮\n"
                "│                 Scanning targets...                 │\n"
                "╰─────────────────────────────────────────────────────╯[/bold cyan]\n",
                total=len(targets)
            )
            
            # Update initial layout
            self.layout["header"].update(self.generate_banner())
            self.layout["stats"].update(self.generate_stats_panel())
            self.layout["current"].update(self.generate_current_target_panel())
            self.layout["events"].update(self.generate_event_log_panel())

            # Start processing targets
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                for target in targets:
                    futures.append(executor.submit(self.test_ftp_credentials, target))

                for future in as_completed(futures):
                    completed += 1
                    progress.advance(scan_task)
                    
                    # Update statistics
                    elapsed = time.time() - start_time
                    self.stats["current_speed"] = completed / elapsed if elapsed > 0 else 0
                    self.stats["avg_speed"] = completed / elapsed if elapsed > 0 else 0
                    
                    # Update layout components
                    self.layout["stats"].update(self.generate_stats_panel())
                    self.layout["current"].update(self.generate_current_target_panel())
                    self.layout["events"].update(self.generate_event_log_panel())
                    
                    # Refresh the display
                    live.refresh()

            # Complete the progress
            progress.stop()

        self.stats["end_time"] = datetime.now()
        self.stats["success"] = len(self.successful_targets)
        self.stats["failed"] = len(self.failed_targets)

        # Print final detailed tables after live UI closes
        if self.successful_targets:
            success_table = Table(title="Successful Targets", box=ROUNDED, header_style="bold green")
            success_table.add_column("Host", style="cyan")
            success_table.add_column("System", style="green")
            success_table.add_column("Dir", style="yellow")
            for t in self.successful_targets:
                success_table.add_row(t["host"], str(t.get("system_type", "-")), str(t.get("current_dir", "-")))
            console.print(success_table)

        if self.failed_targets:
            fail_table = Table(title="Failed Targets", box=ROUNDED, header_style="bold red")
            fail_table.add_column("Host", style="cyan")
            fail_table.add_column("Error", style="red")
            for t in self.failed_targets:
                fail_table.add_row(t["host"], str(t.get("error", "-")))
            console.print(fail_table)

def main():
    """Main entry point of the script."""
    parser = argparse.ArgumentParser(
        description="[bold cyan]FTP Login Destroyer - Advanced FTP Scanner[/bold cyan]",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--target", help="Single target hostname or IP")
    group.add_argument("-l", "--list", help="File containing target list (one per line)")
    parser.add_argument("-w", "--workers", type=int, default=20, help="Number of concurrent workers (default: 20)")
    parser.add_argument("-o", "--output", default="vuln.txt", help="Output file for vulnerable targets (default: vuln.txt)")
    parser.add_argument("--timeout", type=int, default=3, help="Connection timeout in seconds (default: 3)")
    
    args = parser.parse_args()

    try:
        # Initialize FTP Destroyer
        destroyer = FTPDestroyer(
            timeout=args.timeout,
            max_workers=args.workers,
            output_file=args.output
        )

        # Process targets
        targets = []
        if args.target:
            targets = [args.target.strip()]
        else:
            try:
                with open(args.list, "r") as f:
                    targets = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                console.print(f"[red]Error: Target file '{args.list}' not found.[/red]")
                sys.exit(1)

        # Remove any http:// or https:// prefixes
        targets = [t.replace("http://", "").replace("https://", "").rstrip("/") for t in targets]
        
        # Initialize scan
        with console.status("[bold green]Initializing scan...", spinner="dots"):
            time.sleep(1)
        
        # Process targets
        destroyer.process_targets(targets)
        
        # Generate final report
        report_file = destroyer.save_html_report()
        
        # Final summary
        console.print("\n[bold green]Scan Complete![/bold green]")
        console.print(Panel(
            f"""
            [green]Total Targets Scanned: {destroyer.stats['total']}
            Successful Targets: {destroyer.stats['success']}
            Failed Targets: {destroyer.stats['failed']}
            Success Rate: {(destroyer.stats['success']/destroyer.stats['total'])*100:.2f}%[/green]
            
            [cyan]HTML Report: {report_file}
            Vulnerable Targets: {args.output}[/cyan]
            """,
            title="[bold]Scan Summary[/bold]",
            border_style="green",
            padding=(1, 2)
        ))

    except KeyboardInterrupt:
        console.print("\n[red]Scan interrupted by user. Saving partial results...[/red]")
        destroyer.save_html_report()
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]An error occurred: {str(e)}[/red]")
        logger.exception("An unexpected error occurred")
        sys.exit(1)

if __name__ == "__main__":
    main()
