"""
Security check command implementation
"""

import os
from typing import List

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ...core.analyzer import LambdaAnalyzer, AnalysisResult, SecurityIssue
from ..main import format_security_summary

console = Console()


class SecurityCommand:
    """Handler for the security-check command"""

    @staticmethod
    def register_parser(subparsers):
        """Register the security-check command parser"""
        security_parser = subparsers.add_parser(
            'security-check',
            help='Perform security analysis on Lambda functions'
        )
        security_parser.add_argument('path', help='Path to Python file or directory')
        security_parser.add_argument(
            '--config', '-c',
            help='Path to configuration file'
        )
        security_parser.add_argument(
            '--severity',
            choices=['high', 'medium', 'low'],
            help='Only show issues of specified severity and above'
        )
        security_parser.add_argument(
            '--format',
            choices=['console', 'json', 'summary'],
            default='console',
            help='Output format'
        )
        security_parser.add_argument(
            '--fail-on-high',
            action='store_true',
            help='Exit with code 1 if high severity issues found'
        )

    @staticmethod
    def execute(args) -> int:
        """Execute the security-check command"""
        try:
            with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
            ) as progress:
                task = progress.add_task("Performing security analysis...", total=None)

                analyzer = LambdaAnalyzer(config_path=args.config)

                if os.path.isfile(args.path):
                    results = [analyzer.analyze_file(args.path)]
                elif os.path.isdir(args.path):
                    results = analyzer.analyze_directory(args.path, recursive=True)
                else:
                    console.print(f"❌ [red]Path not found: {args.path}[/red]")
                    return 2

                progress.update(task, completed=1, total=1)

                # Filter by severity if specified
                if args.severity:
                    results = SecurityCommand._filter_by_severity(results, args.severity)

                console.print("\n🔒 [bold blue]Security Analysis Results[/bold blue]")
                console.print("=" * 40)

                if args.format == 'console':
                    return SecurityCommand._display_console_security(results, args)
                elif args.format == 'summary':
                    return SecurityCommand._display_security_summary(results, args)
                elif args.format == 'json':
                    return SecurityCommand._display_json_security(results, args)

        except Exception as e:
            console.print(f"\n❌ [red]Security analysis failed: {str(e)}[/red]")
            if hasattr(args, 'verbose') and args.verbose:
                console.print_exception()
            return 1

    @staticmethod
    def _filter_by_severity(results: List[AnalysisResult], min_severity: str) -> List[AnalysisResult]:
        """Filter results to only include specified severity and above"""
        severity_levels = {'low': 0, 'medium': 1, 'high': 2}
        min_level = severity_levels[min_severity]

        filtered_results = []
        for result in results:
            filtered_issues = [
                issue for issue in result.security_issues
                if severity_levels.get(issue.severity, 0) >= min_level
            ]
            if filtered_issues:
                # Create new result with filtered issues
                filtered_result = AnalysisResult(
                    file_path=result.file_path,
                    services=result.services,
                    api_calls=result.api_calls,
                    iam_policy=result.iam_policy,
                    environment_variables=result.environment_variables,
                    triggers=result.triggers,
                    security_issues=filtered_issues,
                    recommendations=result.recommendations,
                    confidence_score=result.confidence_score
                )
                filtered_results.append(filtered_result)

        return filtered_results

    @staticmethod
    def _display_console_security(results: List[AnalysisResult], args) -> int:
        """Display security results in console format"""
        format_security_summary(results)

        # Display detailed issues
        console.print(f"\n📋 [bold]Detailed Issues:[/bold]")

        total_high_issues = 0
        for result in results:
            if result.security_issues:
                console.print(f"\n📄 [cyan]{result.file_path}[/cyan]")
                for issue in result.security_issues:
                    severity_icon = {"high": "🔴", "medium": "🟡", "low": "🔵"}[issue.severity]
                    line_info = f" (line {issue.line_number})" if issue.line_number else ""
                    console.print(f"   {severity_icon} {issue.message}{line_info}")
                    if issue.suggestion:
                        console.print(f"      💡 [dim]{issue.suggestion}[/dim]")

                    if issue.severity == 'high':
                        total_high_issues += 1

        # Return appropriate exit code
        if args.fail_on_high and total_high_issues > 0:
            console.print(f"\n❌ [red]Found {total_high_issues} high severity issues[/red]")
            return 1

        return 0

    @staticmethod
    def _display_security_summary(results: List[AnalysisResult], args) -> int:
        """Display security summary table"""
        table = Table(title="Security Analysis Summary")
        table.add_column("File", style="cyan")
        table.add_column("High", justify="right", style="red")
        table.add_column("Medium", justify="right", style="yellow")
        table.add_column("Low", justify="right", style="blue")
        table.add_column("Total", justify="right", style="bold")

        total_high = 0
        total_medium = 0
        total_low = 0

        for result in results:
            high = len([i for i in result.security_issues if i.severity == 'high'])
            medium = len([i for i in result.security_issues if i.severity == 'medium'])
            low = len([i for i in result.security_issues if i.severity == 'low'])

            total_high += high
            total_medium += medium
            total_low += low

            table.add_row(
                os.path.basename(result.file_path),
                str(high) if high > 0 else "-",
                str(medium) if medium > 0 else "-",
                str(low) if low > 0 else "-",
                str(high + medium + low)
            )

        # Add totals row
        table.add_section()
        table.add_row(
            "[bold]TOTAL[/bold]",
            f"[bold]{total_high}[/bold]" if total_high > 0 else "-",
            f"[bold]{total_medium}[/bold]" if total_medium > 0 else "-",
            f"[bold]{total_low}[/bold]" if total_low > 0 else "-",
            f"[bold]{total_high + total_medium + total_low}[/bold]"
        )

        console.print(table)

        if args.fail_on_high and total_high > 0:
            return 1
        return 0

    @staticmethod
    def _display_json_security(results: List[AnalysisResult], args) -> int:
        """Display security results in JSON format"""
        import json

        data = {
            "summary": {
                "total_files": len(results),
                "files_with_issues": len([r for r in results if r.security_issues]),
                "total_high": sum(len([i for i in r.security_issues if i.severity == 'high']) for r in results),
                "total_medium": sum(len([i for i in r.security_issues if i.severity == 'medium']) for r in results),
                "total_low": sum(len([i for i in r.security_issues if i.severity == 'low']) for r in results),
            },
            "files": []
        }

        for result in results:
            if result.security_issues:
                file_data = {
                    "file_path": result.file_path,
                    "issues": [
                        {
                            "severity": issue.severity,
                            "message": issue.message,
                            "line_number": issue.line_number,
                            "suggestion": issue.suggestion
                        }
                        for issue in result.security_issues
                    ]
                }
                data["files"].append(file_data)

        console.print_json(data=data)

        if args.fail_on_high and data["summary"]["total_high"] > 0:
            return 1
        return 0