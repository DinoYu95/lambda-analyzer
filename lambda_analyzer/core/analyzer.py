"""
Main Lambda Analyzer implementation
"""

import ast
import os
import json
import yaml
from typing import Dict, List, Optional,Union
from dataclasses import dataclass
from pathlib import Path
import re

from .ast_parser import ASTAnalyzer
from .service_detector import AWSServiceDetector
from .policy_generator import IAMPolicyGenerator


@dataclass
class SecurityIssue:
    """Security issue found during analysis"""
    severity: str  # 'high', 'medium', 'low'
    message: str
    line_number: Optional[int] = None
    suggestion: Optional[str] = None


@dataclass
class AnalysisResult:
    """Container for analysis results"""
    file_path: str
    services: List[str]
    api_calls: Dict[str, List[str]]
    iam_policy: Dict
    environment_variables: List[str]
    triggers: List[Dict]
    security_issues: List[SecurityIssue]
    recommendations: List[str]
    confidence_score: float  # 0-1 confidence in the analysis


class LambdaAnalyzer:
    """Main analyzer class for Lambda functions"""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the Lambda Analyzer

        Args:
            config_path: Optional path to YAML configuration file
        """
        self.config = self._load_config(config_path)
        self.service_detector = AWSServiceDetector()
        self.policy_generator = IAMPolicyGenerator(self.config)

    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load configuration from file or use defaults"""
        default_config = {
            'analysis': {
                'python_version': '3.9',
                'include_patterns': ['*.py'],
                'exclude_patterns': ['test_*.py', 'tests/', '__pycache__/']
            },
            'iam': {
                'least_privilege': True,
                'resource_constraints': True,
                'generate_resource_arns': False
            },
            'security': {
                'check_hardcoded_secrets': True,
                'check_wildcard_permissions': True,
                'check_error_handling': True
            },
            'template': {
                'format': 'sam',
                'runtime': 'python3.9',
                'timeout': 30,
                'memory': 512
            }
        }

        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    # Simple merge - in production would be more sophisticated
                    for key, value in user_config.items():
                        if key in default_config and isinstance(value, dict):
                            default_config[key].update(value)
                        else:
                            default_config[key] = value
            except Exception as e:
                print(f"Warning: Could not load config file {config_path}: {e}")

        return default_config

    def analyze_file(self, file_path: str) -> AnalysisResult:
        """
        Analyze a single Python Lambda file

        Args:
            file_path: Path to the Python file to analyze

        Returns:
            AnalysisResult containing all analysis findings
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()

            return self._analyze_code(code, file_path)

        except FileNotFoundError:
            return self._create_error_result(
                file_path, f'File not found: {file_path}'
            )
        except UnicodeDecodeError:
            return self._create_error_result(
                file_path, f'Cannot decode file: {file_path}'
            )
        except Exception as e:
            return self._create_error_result(
                file_path, f'Unexpected error: {str(e)}'
            )

    def analyze_directory(self, dir_path: str, recursive: bool = True) -> List[AnalysisResult]:
        """
        Analyze all Python files in a directory

        Args:
            dir_path: Directory path to analyze
            recursive: Whether to analyze subdirectories

        Returns:
            List of AnalysisResult objects
        """
        results = []
        path = Path(dir_path)

        if not path.exists():
            return [self._create_error_result(dir_path, 'Directory not found')]

        pattern = '**/*.py' if recursive else '*.py'

        for py_file in path.glob(pattern):
            if self._should_include_file(str(py_file)):
                result = self.analyze_file(str(py_file))
                results.append(result)

        return results

    def _should_include_file(self, file_path: str) -> bool:
        """Check if file should be included in analysis based on config patterns"""
        file_name = os.path.basename(file_path)

        # Check exclude patterns first
        for pattern in self.config['analysis']['exclude_patterns']:
            if self._match_pattern(pattern, file_name) or self._match_pattern(pattern, file_path):
                return False

        # Check include patterns
        for pattern in self.config['analysis']['include_patterns']:
            if self._match_pattern(pattern, file_name):
                return True

        return False

    def _match_pattern(self, pattern: str, text: str) -> bool:
        """Simple pattern matching with * wildcard support"""
        pattern_regex = pattern.replace('*', '.*').replace('?', '.')
        return bool(re.match(pattern_regex, text))

    def _analyze_code(self, code: str, file_path: str) -> AnalysisResult:
        """Perform comprehensive static analysis on Python code"""
        try:
            # Parse the Python code into AST
            tree = ast.parse(code)
            ast_analyzer = ASTAnalyzer()

            # Add parent references for better context analysis
            self._add_parent_references(tree)

            # Visit all AST nodes to extract information
            ast_analyzer.visit(tree)

            # Detect AWS services and API calls
            services, api_calls = self.service_detector.detect_services(ast_analyzer)

            # Generate IAM policy from detected API calls
            iam_policy = self.policy_generator.generate_policy(api_calls)

            # Detect Lambda triggers from event access patterns
            triggers = self.service_detector.detect_triggers(
                ast_analyzer.event_accesses, code
            )

            # Perform security analysis
            security_issues = self._analyze_security(ast_analyzer, code)

            # Generate recommendations
            recommendations = self._generate_recommendations(
                ast_analyzer, services, api_calls
            )

            # Calculate confidence score
            confidence = self._calculate_confidence_score(ast_analyzer, services)

            return AnalysisResult(
                file_path=file_path,
                services=services,
                api_calls=api_calls,
                iam_policy=iam_policy,
                environment_variables=list(ast_analyzer.environment_variables),
                triggers=triggers,
                security_issues=security_issues,
                recommendations=recommendations,
                confidence_score=confidence
            )

        except SyntaxError as e:
            return AnalysisResult(
                file_path=file_path,
                services=[],
                api_calls={},
                iam_policy={},
                environment_variables=[],
                triggers=[],
                security_issues=[SecurityIssue(
                    'high',
                    f'Python syntax error: {str(e)}',
                    e.lineno,
                    'Fix Python syntax errors before analysis'
                )],
                recommendations=[],
                confidence_score=0.0
            )
        except Exception as e:
            return self._create_error_result(file_path, f'Analysis failed: {str(e)}')

    def _add_parent_references(self, tree: ast.AST) -> None:
        """Add parent references to AST nodes for context analysis"""
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                child.parent = node

    def _analyze_security(self, ast_analyzer: ASTAnalyzer, code: str) -> List[SecurityIssue]:
        """Perform security analysis on the code"""
        issues = []

        if not self.config['security']['check_hardcoded_secrets']:
            return issues

        # Check for hardcoded AWS credentials
        secret_patterns = [
            (r'AKIA[A-Z0-9]{16}', 'AWS Access Key ID detected'),
            (r'[A-Za-z0-9+/]{40}', 'Potential AWS Secret Key detected'),
            (r'password\s*=\s*["\'][^"\']+["\']', 'Hardcoded password detected'),
            (r'api_key\s*=\s*["\'][^"\']+["\']', 'Hardcoded API key detected'),
            (r'secret\s*=\s*["\'][^"\']+["\']', 'Hardcoded secret detected'),
        ]

        for pattern, message in secret_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                line_no = code[:match.start()].count('\n') + 1
                issues.append(SecurityIssue(
                    severity='high',
                    message=message,
                    line_number=line_no,
                    suggestion='Use AWS Secrets Manager or environment variables'
                ))

        # Check for overly permissive wildcard usage
        if self.config['security']['check_wildcard_permissions']:
            if '*' in str(ast_analyzer.api_calls):
                issues.append(SecurityIssue(
                    severity='medium',
                    message='Consider using specific resource ARNs instead of wildcards',
                    suggestion='Restrict IAM policies to specific resources when possible'
                ))

        # Check for missing error handling
        if self.config['security']['check_error_handling']:
            if 'try:' not in code and len(ast_analyzer.api_calls) > 0:
                issues.append(SecurityIssue(
                    severity='low',
                    message='No error handling detected for AWS API calls',
                    suggestion='Add try/except blocks around AWS service calls'
                ))

        return issues

    def _generate_recommendations(self, ast_analyzer: ASTAnalyzer,
                                  services: List[str], api_calls: Dict) -> List[str]:
        """Generate optimization and best practice recommendations"""
        recommendations = []

        # Cold start optimization
        if len(ast_analyzer.service_clients) > 2:
            recommendations.append(
                "Consider initializing AWS clients outside the Lambda handler "
                "to reduce cold start time"
            )

        # DynamoDB specific recommendations
        if 'dynamodb' in services:
            dynamodb_calls = api_calls.get('dynamodb', [])
            if 'scan' in dynamodb_calls:
                recommendations.append(
                    "DynamoDB Scan operations can be expensive. Consider using "
                    "Query with appropriate indexes instead"
                )
            if len(dynamodb_calls) > 3 and 'batch_get_item' not in dynamodb_calls:
                recommendations.append(
                    "Consider using DynamoDB batch operations for better performance"
                )

        # S3 specific recommendations
        if 's3' in services:
            s3_calls = api_calls.get('s3', [])
            if 'list_objects' in s3_calls or 'list_objects_v2' in s3_calls:
                recommendations.append(
                    "Use pagination for S3 list operations with large datasets"
                )
            recommendations.append(
                "Consider implementing exponential backoff for S3 operations"
            )

        # Memory and architecture recommendations
        if len(services) > 4:
            recommendations.append(
                "This Lambda function uses many AWS services. Consider breaking "
                "it into smaller, more focused functions"
            )

        if len(ast_analyzer.environment_variables) > 10:
            recommendations.append(
                "Consider consolidating environment variables or using "
                "AWS Systems Manager Parameter Store"
            )

        # Security recommendations
        if ast_analyzer.environment_variables:
            recommendations.append(
                "Consider using AWS Secrets Manager for sensitive configuration values"
            )

        return recommendations

    def _calculate_confidence_score(self, ast_analyzer: ASTAnalyzer,
                                    services: List[str]) -> float:
        """Calculate confidence score for the analysis (0.0 to 1.0)"""
        score_components = []

        # High confidence if we found boto3 client/resource creation
        if ast_analyzer.service_clients:
            score_components.append(0.8)

        # Medium-high confidence if we found AWS API calls
        if ast_analyzer.api_calls:
            score_components.append(0.6)

        # Medium confidence if we found AWS-related imports
        aws_imports = [imp for imp in ast_analyzer.imports.values()
                       if 'boto3' in imp or 'aws' in imp.lower()]
        if aws_imports:
            score_components.append(0.4)

        # Boost for environment variables (common in Lambda)
        if ast_analyzer.environment_variables:
            score_components.append(0.1)

        # Boost for event access patterns (indicates Lambda function)
        if ast_analyzer.event_accesses:
            score_components.append(0.1)

        # Boost for lambda_handler function name
        if hasattr(ast_analyzer, 'function_names') and 'lambda_handler' in ast_analyzer.function_names:
            score_components.append(0.1)

        return min(sum(score_components), 1.0) if score_components else 0.0

    def generate_template(self, results: Union[AnalysisResult, List[AnalysisResult]],
                          format: str = 'sam', output_path: Optional[str] = None) -> str:
        """Generate infrastructure template from analysis results"""
        if isinstance(results, AnalysisResult):
            results = [results]

        if format.lower() == 'sam':
            template = self._generate_sam_template(results)
        elif format.lower() == 'cloudformation':
            template = self._generate_cloudformation_template(results)
        else:
            raise ValueError(f"Unsupported template format: {format}")

        if output_path:
            with open(output_path, 'w') as f:
                f.write(template)

        return template

    def _generate_sam_template(self, results: List[AnalysisResult]) -> str:
        """Generate SAM template from analysis results"""
        template = {
            'AWSTemplateFormatVersion': '2010-09-09',
            'Transform': 'AWS::Serverless-2016-10-31',
            'Resources': {}
        }

        # Mapping env vars -> logical resource names
        env_var_to_resource = {
            'TABLE_NAME': 'UserTable',
            'BACKUP_BUCKET': 'BackupBucket',
            'SNS_TOPIC': 'NotificationTopic',
        }

        for result in results:
            # Name function based on filename (e.g., multi_service.py -> MultiServiceFunction)
            base_name = Path(result.file_path).stem
            function_name = base_name.title().replace('_', '') + 'Function'

            function_resource = {
                'Type': 'AWS::Serverless::Function',
                'Properties': {
                    'CodeUri': '.',
                    'Handler': f"{base_name}.lambda_handler",
                    'Runtime': f"python{self.config['analysis']['python_version']}",
                    'Environment': {
                        'Variables': {}
                    }
                }
            }

            # Add environment variables
            for env_var in result.environment_variables:
                ref_name = env_var_to_resource.get(env_var, f"{env_var}Parameter")
                function_resource['Properties']['Environment']['Variables'][env_var] = f"!Ref {ref_name}"

            # Add IAM policies
            if result.iam_policy.get('Statement'):
                policies = []
                for statement in result.iam_policy['Statement']:
                    actions = statement['Action']
                    if isinstance(actions, str):
                        actions = [actions]
                    for action in actions:
                        if 'dynamodb:PutItem' in action:
                            policies.append({'DynamoDBWritePolicy': {'TableName': '!Ref UserTable'}})
                        elif 's3:PutObject' in action:
                            policies.append({'S3WritePolicy': {'BucketName': '!Ref BackupBucket'}})
                        elif 'sns:Publish' in action:
                            policies.append({'SNSPublishMessagePolicy': {'TopicName': '!Ref NotificationTopic'}})
                if policies:
                    function_resource['Properties']['Policies'] = policies

            # Add event sources if any
            if result.triggers:
                events = {}
                for i, trigger in enumerate(result.triggers):
                    event_name = f"{trigger['type'].title()}Event{i + 1}"
                    if trigger['type'] == 's3':
                        events[event_name] = {
                            'Type': 'S3',
                            'Properties': {
                                'Bucket': '!Ref BackupBucket',
                                'Event': 's3:ObjectCreated:*'
                            }
                        }
                    elif trigger['type'] == 'api_gateway':
                        events[event_name] = {
                            'Type': 'Api',
                            'Properties': {
                                'Path': '/api',
                                'Method': 'post'
                            }
                        }
                if events:
                    function_resource['Properties']['Events'] = events

            template['Resources'][function_name] = function_resource

        # Add shared resources if needed
        all_services = set()
        for result in results:
            all_services.update(result.services)

        if 'dynamodb' in all_services:
            template['Resources']['UserTable'] = {
                'Type': 'AWS::DynamoDB::Table',
                'Properties': {
                    'BillingMode': 'PAY_PER_REQUEST',
                    'AttributeDefinitions': [{
                        'AttributeName': 'id',
                        'AttributeType': 'S'
                    }],
                    'KeySchema': [{
                        'AttributeName': 'id',
                        'KeyType': 'HASH'
                    }]
                }
            }

        if 's3' in all_services:
            template['Resources']['BackupBucket'] = {
                'Type': 'AWS::S3::Bucket'
            }

        if 'sns' in all_services:
            template['Resources']['NotificationTopic'] = {
                'Type': 'AWS::SNS::Topic'
            }

        return yaml.dump(template, default_flow_style=False, sort_keys=False)

    def _generate_cloudformation_template(self, results: List[AnalysisResult]) -> str:
        """Generate CloudFormation template"""
        # Similar to SAM but without Transform and using full CloudFormation resources
        template = {
            'AWSTemplateFormatVersion': '2010-09-09',
            'Description': 'Lambda functions generated by Lambda Analyzer',
            'Resources': {}
        }

        for i, result in enumerate(results):
            function_name = f"LambdaFunction{i + 1}" if len(results) > 1 else "LambdaFunction"

            # Create IAM role
            role_name = f"{function_name}Role"
            template['Resources'][role_name] = {
                'Type': 'AWS::IAM::Role',
                'Properties': {
                    'AssumeRolePolicyDocument': {
                        'Version': '2012-10-17',
                        'Statement': [{
                            'Effect': 'Allow',
                            'Principal': {'Service': 'lambda.amazonaws.com'},
                            'Action': 'sts:AssumeRole'
                        }]
                    },
                    'ManagedPolicyArns': [
                        'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
                    ],
                    'Policies': []
                }
            }

            # Add custom policies from analysis
            if result.iam_policy.get('Statement'):
                template['Resources'][role_name]['Properties']['Policies'].append({
                    'PolicyName': f"{function_name}Policy",
                    'PolicyDocument': result.iam_policy
                })

            # Create Lambda function
            template['Resources'][function_name] = {
                'Type': 'AWS::Lambda::Function',
                'Properties': {
                    'FunctionName': function_name,
                    'Runtime': f"python{self.config['analysis']['python_version']}",
                    'Handler': f"{Path(result.file_path).stem}.lambda_handler",
                    'Role': f"!GetAtt {role_name}.Arn",
                    'Code': {
                        'ZipFile': '# Placeholder - replace with actual code'
                    },
                    'Environment': {
                        'Variables': {}
                    }
                }
            }

            # Add environment variables
            for env_var in result.environment_variables:
                template['Resources'][function_name]['Properties']['Environment']['Variables'][
                    env_var] = f"!Ref {env_var}Parameter"

        return yaml.dump(template, default_flow_style=False, sort_keys=False)

    def _create_error_result(self, file_path: str, error_message: str) -> AnalysisResult:
        """Create an AnalysisResult for error cases"""
        return AnalysisResult(
            file_path=file_path,
            services=[],
            api_calls={},
            iam_policy={},
            environment_variables=[],
            triggers=[],
            security_issues=[SecurityIssue('high', error_message)],
            recommendations=[],
            confidence_score=0.0
        )


# Simple CLI for testing
def main():
    """Simple CLI entry point for testing the core analyzer"""
    import sys

    if len(sys.argv) != 2:
        print("Usage: python -m lambda_analyzer.core.analyzer <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    analyzer = LambdaAnalyzer()
    result = analyzer.analyze_file(file_path)

    print(f"Analysis Results for {file_path}")
    print("=" * 50)
    print(f"Services: {result.services}")
    print(f"IAM Policy: {json.dumps(result.iam_policy, indent=2)}")
    print(f"Environment Variables: {result.environment_variables}")
    print(f"Confidence Score: {result.confidence_score:.2f}")

    if result.security_issues:
        print(f"Security Issues: {len(result.security_issues)}")
        for issue in result.security_issues:
            print(f"  - {issue.severity.upper()}: {issue.message}")

    if result.recommendations:
        print("Recommendations:")
        for rec in result.recommendations:
            print(f"  - {rec}")


if __name__ == '__main__':
    main()