"""
Interactive setup wizard for Lambda Analyzer
"""

import os
import yaml
from typing import Dict, Any

from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.panel import Panel

console = Console()


class InteractiveSetup:
    """Interactive configuration setup wizard"""

    def __init__(self):
        self.config = {}

    def run(self, args) -> int:
        """Run the interactive setup wizard"""
        try:
            console.print("🚀 [bold blue]Lambda Analyzer Setup Wizard[/bold blue]")
            console.print("=" * 40)
            console.print("This wizard will help you configure Lambda Analyzer for your project.\n")

            # Analysis configuration
            self._setup_analysis_config()

            # Template configuration
            self._setup_template_config()

            # IAM configuration
            self._setup_iam_config()

            # Security configuration
            self._setup_security_config()

            # Resource configuration (optional)
            if Confirm.ask("\nWould you like to configure AWS resources?", default=False):
                self._setup_resource_config()

            # Save configuration
            config_path = args.output or '.lambda-analyzer.yaml'
            self._save_config(config_path)

            console.print(f"\n✅ [green]Configuration saved to {config_path}[/green]")
            self._display_next_steps()

            return 0

        except KeyboardInterrupt:
            console.print("\n❌ [red]Setup interrupted by user[/red]")
            return 1
        except Exception as e:
            console.print(f"\n❌ [red]Setup failed: {str(e)}[/red]")
            return 1

    def _setup_analysis_config(self):
        """Setup analysis configuration"""
        console.print("\n📝 [bold]Analysis Settings[/bold]")

        python_version = Prompt.ask(
            "Python version for your Lambda functions",
            choices=["3.8", "3.9", "3.10", "3.11"],
            default="3.9"
        )

        include_patterns = Prompt.ask(
            "File patterns to include (comma-separated)",
            default="*.py"
        ).split(',')

        exclude_patterns = Prompt.ask(
            "File patterns to exclude (comma-separated)",
            default="test_*.py,tests/,__pycache__/"
        ).split(',')

        self.config['analysis'] = {
            'python_version': python_version,
            'include_patterns': [p.strip() for p in include_patterns],
            'exclude_patterns': [p.strip() for p in exclude_patterns]
        }

    def _setup_template_config(self):
        """Setup template generation configuration"""
        console.print("\n📋 [bold]Template Settings[/bold]")

        template_format = Prompt.ask(
            "Preferred infrastructure template format",
            choices=["sam", "cloudformation"],
            default="sam"
        )

        runtime = Prompt.ask(
            "Default Lambda runtime",
            default=f"python{self.config['analysis']['python_version']}"
        )

        memory = IntPrompt.ask(
            "Default Lambda memory (MB)",
            default=512
        )

        timeout = IntPrompt.ask(
            "Default Lambda timeout (seconds)",
            default=30
        )

        self.config['template'] = {
            'format': template_format,
            'runtime': runtime,
            'memory': memory,
            'timeout': timeout
        }

    def _setup_iam_config(self):
        """Setup IAM policy configuration"""
        console.print("\n🛡️ [bold]IAM Policy Settings[/bold]")

        least_privilege = Confirm.ask(
            "Generate least-privilege IAM policies?",
            default=True
        )

        resource_constraints = Confirm.ask(
            "Add resource ARN constraints to policies?",
            default=True
        )

        optimize_policies = Confirm.ask(
            "Automatically optimize and consolidate policies?",
            default=True
        )

        self.config['iam'] = {
            'least_privilege': least_privilege,
            'resource_constraints': resource_constraints,
            'optimize': optimize_policies
        }

    def _setup_security_config(self):
        """Setup security analysis configuration"""
        console.print("\n🔒 [bold]Security Settings[/bold]")

        check_secrets = Confirm.ask(
            "Check for hardcoded secrets and credentials?",
            default=True
        )

        check_wildcards = Confirm.ask(
            "Check for overly permissive wildcard permissions?",
            default=True
        )

        check_error_handling = Confirm.ask(
            "Check for missing error handling around AWS calls?",
            default=True
        )

        self.config['security'] = {
            'check_hardcoded_secrets': check_secrets,
            'check_wildcard_permissions': check_wildcards,
            'check_error_handling': check_error_handling
        }

    def _setup_resource_config(self):
        """Setup AWS resource configuration"""
        console.print("\n🏗️ [bold]AWS Resources Configuration[/bold]")

        resources = {}

        # DynamoDB tables
        if Confirm.ask("Configure DynamoDB tables?", default=False):
            resources['dynamodb'] = self._configure_dynamodb()

        # S3 buckets
        if Confirm.ask("Configure S3 buckets?", default=False):
            resources['s3'] = self._configure_s3()

        # SNS topics
        if Confirm.ask("Configure SNS topics?", default=False):
            resources['sns'] = self._configure_sns()

        if resources:
            self.config['resources'] = resources

    def _configure_dynamodb(self) -> Dict[str, Any]:
        """Configure DynamoDB tables"""
        tables = []

        while True:
            console.print(f"\n📊 [cyan]Configuring DynamoDB Table {len(tables) + 1}[/cyan]")

            name = Prompt.ask("Table name")
            hash_key = Prompt.ask("Primary key (hash key) name", default="id")
            hash_key_type = Prompt.ask("Primary key type", choices=["S", "N", "B"], default="S")

            range_key = None
            range_key_type = None
            if Confirm.ask("Does this table have a sort key (range key)?", default=False):
                range_key = Prompt.ask("Sort key name")
                range_key_type = Prompt.ask("Sort key type", choices=["S", "N", "B"], default="S")

            billing_mode = Prompt.ask(
                "Billing mode",
                choices=["PAY_PER_REQUEST", "PROVISIONED"],
                default="PAY_PER_REQUEST"
            )

            table_config = {
                'name': name,
                'hash_key': hash_key,
                'hash_key_type': hash_key_type,
                'billing_mode': billing_mode
            }

            if range_key:
                table_config['range_key'] = range_key
                table_config['range_key_type'] = range_key_type

            tables.append(table_config)

            if not Confirm.ask("Add another DynamoDB table?", default=False):
                break

        return {'tables': tables}

    def _configure_s3(self) -> Dict[str, Any]:
        """Configure S3 buckets"""
        buckets = []

        while True:
            console.print(f"\n🪣 [cyan]Configuring S3 Bucket {len(buckets) + 1}[/cyan]")

            name = Prompt.ask("Bucket name")
            versioning = Confirm.ask("Enable versioning?", default=True)
            encryption = Confirm.ask("Enable encryption?", default=True)
            public_access = Confirm.ask("Allow public access?", default=False)

            bucket_config = {
                'name': name,
                'versioning': versioning,
                'encryption': encryption,
                'public_access': public_access
            }

            buckets.append(bucket_config)

            if not Confirm.ask("Add another S3 bucket?", default=False):
                break

        return {'buckets': buckets}

    def _configure_sns(self) -> Dict[str, Any]:
        """Configure SNS topics"""
        topics = []

        while True:
            console.print(f"\n📢 [cyan]Configuring SNS Topic {len(topics) + 1}[/cyan]")

            name = Prompt.ask("Topic name")
            encryption = Confirm.ask("Enable encryption?", default=True)

            topic_config = {
                'name': name,
                'encryption': encryption
            }

            topics.append(topic_config)

            if not Confirm.ask("Add another SNS topic?", default=False):
                break

        return {'topics': topics}

    def _save_config(self, config_path: str):
        """Save configuration to YAML file"""
        with open(config_path, 'w') as f:
            yaml.dump(
                self.config,
                f,
                default_flow_style=False,
                sort_keys=False,
                indent=2
            )

    def _display_next_steps(self):
        """Display next steps after configuration"""
        console.print("\n🎯 [bold]Next Steps:[/bold]")

        steps = [
            "1. Run [cyan]lambda-analyzer analyze .[/cyan] to analyze your Lambda functions",
            "2. Run [cyan]lambda-analyzer generate-template . --output template.yaml[/cyan] to generate infrastructure",
            "3. Run [cyan]lambda-analyzer security-check .[/cyan] to check for security issues",
            "4. Review and customize the generated configuration file as needed"
        ]

        for step in steps:
            console.print(f"   {step}")

        console.print(f"\n💡 [dim]You can edit the configuration file anytime to adjust settings.[/dim]")
