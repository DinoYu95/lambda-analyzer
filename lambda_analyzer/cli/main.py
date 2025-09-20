# lambda_analyzer/cli/main.py
"""
Main CLI entry point for Lambda Analyzer
"""

import argparse
import sys
import os
import json
from pathlib import Path
from typing import List

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich.tree import Tree

from ..core.analyzer import LambdaAnalyzer, AnalysisResult, SecurityIssue

console = Console()

def format_analysis_result(result: AnalysisResult, verbose: bool = False) -> None:
    """Format and display analysis results using Rich"""

    # Header with file path
    console.print(f"\n📊 [bold blue]Analysis Results for {result.file_path}[/bold blue]")
    console.print("=" * min(60, len(result.file_path) + 25))

    # Services section
    if result.services:
        console.print(f"\n🔍 [bold green]Detected AWS Services:[/bold green]")
        for service in result.services:
            # Get service display name from mappings
            from ..utils.aws_mappings import AWS_SERVICE_MAPPINGS
            service_name = AWS_SERVICE_MAPPINGS.get('boto3.client', {}).get(service, {}).get('service_name', service.upper())
            console.print(f"  • {service_name}")

    # API Calls section (verbose mode)
    if verbose and result.api_calls:
        console.print(f"\n🔧 [bold cyan]API Calls by Service:[/bold cyan]")
        for service, methods in result.api_calls.items():
            console.print(f"  📋 {service.upper()}:")
            for method in methods:
                console.print(f"    • {method}")

    # Triggers section
    if result.triggers:
        console.print(f"\n📡 [bold yellow]Inferred Triggers:[/bold yellow]")
        for trigger in result.triggers:
            confidence_color = "green" if trigger['confidence'] == 'high' else "yellow"
            console.print(f"  • {trigger['type'].replace('_', ' ').title()} ([{confidence_color}]{trigger['confidence']}[/{confidence_color}])")

    # IAM Policy section
    if result.iam_policy and result.iam_policy.get('Statement'):
        console.print(f"\n🛡️ [bold cyan]Required IAM Permissions:[/bold cyan]")
        permissions = set()
        for statement in result.iam_policy.get('Statement', []):
            permissions.update(statement.get('Action', []))

        for permission in sorted(permissions):
            console.print(f"  • {permission}")

        if verbose:
            console.print(f"\n📋 [bold dim]Full IAM Policy:[/bold dim]")
            console.print(Panel(
                json.dumps(result.iam_policy, indent=2),
                title="IAM Policy JSON",
                border_style="dim"
            ))

    # Environment Variables section
    if result.environment_variables:
        console.print(f"\n🔧 [bold magenta]Environment Variables:[/bold magenta]")
        for env_var in sorted(result.environment_variables):
            console.print(f"  • {env_var}")

    # Security Issues section
    if result.security_issues:
        console.print(f"\n⚠️ [bold red]Security Issues:[/bold red]")

        # Group by severity
        high_issues = [i for i in result.security_issues if i.severity == 'high']
        medium_issues = [i for i in result.security_issues if i.severity == 'medium']
        low_issues = [i for i in result.security_issues if i.severity == 'low']

        for severity, issues, color in [
            ('HIGH', high_issues, 'red'),
            ('MEDIUM', medium_issues, 'yellow'),
            ('LOW', low_issues, 'blue')
        ]:
            if issues:
                console.print(f"  🔸 [{color}]{severity} RISK:[/{color}]")
                for issue in issues:
                    line_info = f" (line {issue.line_number})" if issue.line_number else ""
                    console.print(f"    • {issue.message}{line_info}")
                    if issue.suggestion and verbose:
                        console.print(f"      💡 [dim]{issue.suggestion}[/dim]")

    # Recommendations section
    if result.recommendations:
        console.print(f"\n💡 [bold green]Recommendations:[/bold green]")
        for i, rec in enumerate(result.recommendations, 1):
            console.print(f"  {i}. {rec}")

    # Confidence Score
    if result.confidence_score is not None:
        confidence_color = "green" if result.confidence_score > 0.7 else "yellow" if result.confidence_score > 0.4 else "red"
        console.print(f"\n📈 [bold {confidence_color}]Confidence Score: {result.confidence_score:.2f}[/bold {confidence_color}]")

        if result.confidence_score < 0.5:
            console.print("   [dim]💡 Low confidence may indicate limited AWS service usage or complex code patterns[/dim]")

def format_security_summary(results: List[AnalysisResult]) -> None:
    """Format security analysis summary"""

    all_issues = []
    for result in results:
        all_issues.extend(result.security_issues)

    if not all_issues:
        console.print("✅ [bold green]No security issues detected![/bold green]")
        return

    # Count by severity
    high_count = len([i for i in all_issues if i.severity == 'high'])
    medium_count = len([i for i in all_issues if i.severity == 'medium'])
    low_count = len([i for i in all_issues if i.severity == 'low'])

    # Create summary table
    table = Table(title="Security Issues Summary")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Status")

    if high_count > 0:
        table.add_row("🔴 High", str(high_count), "[red]Action Required[/red]")
    if medium_count > 0:
        table.add_row("🟡 Medium", str(medium_count), "[yellow]Review Recommended[/yellow]")
    if low_count > 0:
        table.add_row("🔵 Low", str(low_count), "[blue]Consider Fixing[/blue]")

    console.print(table)

    # Detailed issues
    console.print(f"\n📋 [bold]Detailed Issues:[/bold]")

    for result in results:
        if result.security_issues:
            console.print(f"\n📄 {result.file_path}")
            for issue in result.security_issues:
                severity_icon = {"high": "🔴", "medium": "🟡", "low": "🔵"}[issue.severity]
                line_info = f" (line {issue.line_number})" if issue.line_number else ""
                console.print(f"   {severity_icon} {issue.message}{line_info}")
                if issue.suggestion:
                    console.print(f"      💡 [dim]{issue.suggestion}[/dim]")

def handle_analyze_command(args) -> int:
    """Handle the analyze command"""
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
                progress.update(task, completed=1, total=1)

                format_analysis_result(result, verbose=args.verbose)

                if args.output:
                    progress.update(task, description="Saving results...")
                    with open(args.output, 'w') as f:
                        # Convert to dict for JSON serialization
                        result_dict = {
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
                        }
                        json.dump(result_dict, f, indent=2, default=str)
                    console.print(f"\n💾 Results saved to {args.output}")

            elif os.path.isdir(args.path):
                results = analyzer.analyze_directory(args.path, recursive=args.recursive)
                progress.update(task, completed=len(results), total=len(results))

                # Display summary first
                console.print(f"\n📊 [bold blue]Directory Analysis Summary[/bold blue]")
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

                # Display individual results
                for result in results:
                    format_analysis_result(result, verbose=args.verbose)

                if args.output:
                    progress.update(task, description="Saving results...")
                    results_dict = []
                    for result in results:
                        result_dict = {
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
                        }
                        results_dict.append(result_dict)

                    with open(args.output, 'w') as f:
                        json.dump(results_dict, f, indent=2, default=str)
                    console.print(f"\n💾 Results saved to {args.output}")
            else:
                console.print(f"❌ [red]Path not found: {args.path}[/red]")
                return 2

        return 0

    except KeyboardInterrupt:
        console.print("\n❌ [red]Analysis interrupted by user[/red]")
        return 1
    except Exception as e:
        console.print(f"\n❌ [red]Analysis failed: {str(e)}[/red]")
        if args.verbose:
            console.print_exception()
        return 1

def handle_generate_template_command(args) -> int:
    """Handle the generate-template command"""
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Analyzing functions and generating template...", total=None)

            analyzer = LambdaAnalyzer(config_path=args.config)

            if os.path.isfile(args.path):
                result = analyzer.analyze_file(args.path)
                template = analyzer.generate_template(result, format=args.format, output_path=args.output)
            elif os.path.isdir(args.path):
                results = analyzer.analyze_directory(args.path)
                template = analyzer.generate_template(results, format=args.format, output_path=args.output)
            else:
                console.print(f"❌ [red]Path not found: {args.path}[/red]")
                return 2

            progress.update(task, completed=1, total=1)

            console.print(f"✅ [green]{args.format.upper()} template generated: {args.output}[/green]")

            # Show preview if requested
            if args.preview:
                console.print(f"\n📋 [bold]Template Preview:[/bold]")
                console.print(Panel(
                    template[:1000] + "..." if len(template) > 1000 else template,
                    title=f"{args.format.upper()} Template",
                    border_style="blue"
                ))

        return 0

    except Exception as e:
        console.print(f"\n❌ [red]Template generation failed: {str(e)}[/red]")
        if args.verbose:
            console.print_exception()
        return 1

def handle_security_check_command(args) -> int:
    """Handle the security-check command"""
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

            console.print("\n🔒 [bold blue]Security Analysis Results[/bold blue]")
            console.print("=" * 40)

            format_security_summary(results)

            # Check if we found any high-severity issues
            high_issues = any(
                any(issue.severity == 'high' for issue in result.security_issues)
                for result in results
            )

            return 1 if high_issues else 0

    except Exception as e:
        console.print(f"\n❌ [red]Security analysis failed: {str(e)}[/red]")
        if args.verbose:
            console.print_exception()
        return 1

def handle_init_command(args) -> int:
    """Handle the init command for interactive setup"""
    try:
        console.print("🚀 [bold blue]Lambda Analyzer Setup Wizard[/bold blue]")
        console.print("=" * 40)

        config = {
            'analysis': {},
            'template': {},
            'iam': {},
            'resources': {}
        }

        # Analysis settings
        console.print("\n📝 [bold]Analysis Settings[/bold]")

        python_version = Prompt.ask(
            "Python version",
            choices=["3.8", "3.9", "3.10", "3.11"],
            default="3.9"
        )
        config['analysis']['python_version'] = python_version

        # Template settings
        console.print("\n📋 [bold]Template Settings[/bold]")

        template_format = Prompt.ask(
            "Preferred template format",
            choices=["sam", "cloudformation"],
            default="sam"
        )
        config['template']['format'] = template_format

        memory = Prompt.ask(
            "Default Lambda memory (MB)",
            default="512"
        )
        config['template']['memory'] = int(memory)

        timeout = Prompt.ask(
            "Default Lambda timeout (seconds)",
            default="30"
        )
        config['template']['timeout'] = int(timeout)

        # IAM settings
        console.print("\n🛡️ [bold]IAM Policy Settings[/bold]")

        least_privilege = Confirm.ask(
            "Generate least-privilege policies?",
            default=True
        )
        config['iam']['least_privilege'] = least_privilege

        resource_constraints = Confirm.ask(
            "Add resource constraints to policies?",
            default=True
        )
        config['iam']['resource_constraints'] = resource_constraints

        # Security settings
        console.print("\n🔒 [bold]Security Settings[/bold]")

        check_secrets = Confirm.ask(
            "Check for hardcoded secrets?",
            default=True
        )

        check_wildcards = Confirm.ask(
            "Check for wildcard permissions?",
            default=True
        )

        config['security'] = {
            'check_hardcoded_secrets': check_secrets,
            'check_wildcard_permissions': check_wildcards,
            'check_error_handling': True
        }

        # Save configuration
        config_path = args.output or '.lambda-analyzer.yaml'

        import yaml
        with open(config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)

        console.print(f"\n✅ [green]Configuration saved to {config_path}[/green]")
        console.print("\n🎯 [bold]Next Steps:[/bold]")
        console.print("1. Run [cyan]lambda-analyzer analyze .[/cyan] to analyze your Lambda functions")
        console.print("2. Run [cyan]lambda-analyzer generate-template . --output template.yaml[/cyan] to generate infrastructure")
        console.print("3. Run [cyan]lambda-analyzer security-check .[/cyan] to check for security issues")

        return 0

    except KeyboardInterrupt:
        console.print("\n❌ [red]Setup interrupted by user[/red]")
        return 1
    except Exception as e:
        console.print(f"\n❌ [red]Setup failed: {str(e)}[/red]")
        return 1

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Lambda Analyzer - AWS Lambda static analysis tool",
        epilog="For more information, visit: https://github.com/DinoYu95/lambda-analyzer"
    )

    parser.add_argument('--version', action='version', version='%(prog)s 1.0.0')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Analyze command
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

    # Generate template command
    template_parser = subparsers.add_parser(
        'generate-template',
        help='Generate infrastructure template (SAM/CloudFormation) from analysis'
    )
    template_parser.add_argument('path', help='Path to Python file or directory')
    template_parser.add_argument(
        '--format',
        choices=['sam', 'cloudformation'],
        default='sam',
        help='Template format to generate'
    )
    template_parser.add_argument(
        '--output', '-o',
        default='template.yaml',
        help='Output template file path'
    )
    template_parser.add_argument(
        '--config', '-c',
        help='Path to configuration file'
    )
    template_parser.add_argument(
        '--preview',
        action='store_true',
        help='Show template preview in console'
    )

    # Security check command
    security_parser = subparsers.add_parser(
        'security-check',
        help='Perform security analysis on Lambda functions'
    )
    security_parser.add_argument('path', help='Path to Python file or directory')
    security_parser.add_argument(
        '--config', '-c',
        help='Path to configuration file'
    )

    # Init command
    init_parser = subparsers.add_parser(
        'init',
        help='Initialize configuration with interactive setup wizard'
    )
    init_parser.add_argument(
        '--output', '-o',
        help='Configuration file path (default: .lambda-analyzer.yaml)'
    )

    # Performance command
    perf_parser = subparsers.add_parser(
        'performance',
        help='Analyze Lambda functions for performance optimizations'
    )
    perf_parser.add_argument('path', help='Path to Python file or directory')
    perf_parser.add_argument(
        '--config', '-c',
        help='Path to configuration file'
    )

    args = parser.parse_args()

    # Show help if no command provided
    if not args.command:
        parser.print_help()
        return 0

    # Set up console settings
    if args.verbose:
        console._stderr = True

    # Handle commands
    try:
        if args.command == 'analyze':
            return handle_analyze_command(args)
        elif args.command == 'generate-template':
            return handle_generate_template_command(args)
        elif args.command == 'security-check':
            return handle_security_check_command(args)
        elif args.command == 'init':
            return handle_init_command(args)
        elif args.command == 'performance':
            # Performance analysis would be implemented here
            console.print("🚧 [yellow]Performance analysis feature coming soon![/yellow]")
            return 0
        else:
            console.print(f"❌ [red]Unknown command: {args.command}[/red]")
            return 1

    except KeyboardInterrupt:
        console.print("\n❌ [red]Operation interrupted by user[/red]")
        return 1
    except Exception as e:
        console.print(f"\n❌ [red]Unexpected error: {str(e)}[/red]")
        if args.verbose:
            console.print_exception()
        return 1

if __name__ == '__main__':
    sys.exit(main())