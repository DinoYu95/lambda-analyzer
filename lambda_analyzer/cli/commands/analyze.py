"""
Analyze command implementation
"""

import os
import json
from typing import List

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ...core.analyzer import LambdaAnalyzer, AnalysisResult

console = Console()


class AnalyzeCommand:
    """Handler for the analyze command"""

    @staticmethod
    def register_parser(subparsers):
        """Register the analyze command parser"""
        analyze_parser = subparsers.add_parser(
            'analyze',
            help='Analyze Lambda function(s) for AWS service usage and generate IAM policies'
        )
        analyze_parser.add_argument('path', help='Path to Python file or directory')
        analyze_parser.add_argument(
            '--recursive', '-r',
            action='store_true',
            help='Analyze directory recursively'
        )
        analyze_parser.add_argument(
            '--config', '-c',
            help='Path to configuration file'
        )
        analyze_parser.add_argument(
            '--output', '-o',
            help='Output file for results (JSON format)'
        )
        analyze_parser.add_argument(
            '--format',
            choices=['console', 'json', 'summary'],
            default='console',
            help='Output format'
        )
        analyze_parser.add_argument(
            '--filter-services',
            nargs='+',
            help='Filter results to specific AWS services'
        )
        analyze_parser.add_argument(
            '--min-confidence',
            type=float,
            default=0.0,
            help='Minimum confidence score for results (0.0-1.0)'
        )

    @staticmethod
    def execute(args) -> int:
        """Execute the analyze command"""
        try:
            with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
            ) as progress:
                task = progress.add_task("Analyzing Lambda functions...", total=None)

                analyzer = LambdaAnalyzer(config_path=args.config)

                if os.path.isfile(args.path):
                    result = analyzer.analyze_file(args.path)
                    results = [result]
                    progress.update(task, completed=1, total=1)

                elif os.path.isdir(args.path):
                    results = analyzer.analyze_directory(args.path, recursive=args.recursive)
                    progress.update(task, completed=len(results), total=len(results))

                else:
                    console.print(f"❌ [red]Path not found: {args.path}[/red]")
                    return 2

                # Filter results
                filtered_results = AnalyzeCommand._filter_results(results, args)

                # Display results
                if args.format == 'console':
                    AnalyzeCommand._display_console_results(filtered_results, args)
                elif args.format == 'summary':
                    AnalyzeCommand._display_summary(filtered_results)
                elif args.format == 'json':
                    AnalyzeCommand._display_json_results(filtered_results)

                # Save to file if requested
                if args.output:
                    AnalyzeCommand._save_results(filtered_results, args.output)
                    console.print(f"\n💾 Results saved to {args.output}")

                return 0

        except Exception as e:
            console.print(f"\n❌ [red]Analysis failed: {str(e)}[/red]")
            if hasattr(args, 'verbose') and args.verbose:
                console.print_exception()
            return 1

    @staticmethod
    def _filter_results(results: List[AnalysisResult], args) -> List[AnalysisResult]:
        """Filter results based on command line arguments"""
        filtered = results

        # Filter by confidence score
        if args.min_confidence > 0:
            filtered = [r for r in filtered if r.confidence_score >= args.min_confidence]

        # Filter by services
        if args.filter_services:
            service_filter = set(s.lower() for s in args.filter_services)
            filtered = [
                r for r in filtered
                if any(service in service_filter for service in r.services)
            ]

        return filtered

    @staticmethod
    def _display_console_results(results: List[AnalysisResult], args) -> None:
        """Display results in console format"""
        if not results:
            console.print("📭 [yellow]No results to display after filtering[/yellow]")
            return

        if len(results) > 1:
            # Display summary first for multiple files
            console.print(f"\n📊 [bold blue]Analysis Summary[/bold blue]")
            console.print(f"Analyzed {len(results)} files")

            all_services = set()
            total_issues = 0

            for result in results:
                all_services.update(result.services)
                total_issues += len(result.security_issues)

            if all_services:
                console.print(f"AWS Services found: {', '.join(sorted(all_services))}")
            if total_issues > 0:
                console.print(f"⚠️ {total_issues} security issues found")

        from ..main import format_analysis_result
        # Display individual results
        for result in results:
            format_analysis_result(result, verbose=getattr(args, 'verbose', False))

    @staticmethod
    def _display_summary(results: List[AnalysisResult]) -> None:
        """Display summary format"""
        if not results:
            console.print("📭 [yellow]No results to display[/yellow]")
            return

        from rich.table import Table

        table = Table(title="Lambda Analysis Summary")
        table.add_column("File", style="cyan", no_wrap=True)
        table.add_column("Services", style="green")
        table.add_column("Confidence", justify="right")
        table.add_column("Issues", justify="right", style="red")

        for result in results:
            services_str = ", ".join(result.services) if result.services else "None"
            if len(services_str) > 30:
                services_str = services_str[:27] + "..."

            confidence_str = f"{result.confidence_score:.2f}"
            issues_count = len(result.security_issues)
            issues_str = str(issues_count) if issues_count > 0 else "-"

            table.add_row(
                os.path.basename(result.file_path),
                services_str,
                confidence_str,
                issues_str
            )

        console.print(table)

    @staticmethod
    def _display_json_results(results: List[AnalysisResult]) -> None:
        """Display results in JSON format"""
        json_data = []
        for result in results:
            json_data.append({
                'file_path': result.file_path,
                'services': result.services,
                'api_calls': result.api_calls,
                'iam_policy': result.iam_policy,
                'environment_variables': result.environment_variables,
                'triggers': result.triggers,
                'security_issues': [
                    {
                        'severity': issue.severity,
                        'message': issue.message,
                        'line_number': issue.line_number,
                        'suggestion': issue.suggestion
                    }
                    for issue in result.security_issues
                ],
                'recommendations': result.recommendations,
                'confidence_score': result.confidence_score
            })

        console.print_json(data=json_data)

    @staticmethod
    def _save_results(results: List[AnalysisResult], output_path: str) -> None:
        """Save results to file"""
        data = []
        for result in results:
            data.append({
                'file_path': result.file_path,
                'services': result.services,
                'api_calls': result.api_calls,
                'iam_policy': result.iam_policy,
                'environment_variables': result.environment_variables,
                'triggers': result.triggers,
                'security_issues': [
                    {
                        'severity': issue.severity,
                        'message': issue.message,
                        'line_number': issue.line_number,
                        'suggestion': issue.suggestion
                    }
                    for issue in result.security_issues
                ],
                'recommendations': result.recommendations,
                'confidence_score': result.confidence_score
            })

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)