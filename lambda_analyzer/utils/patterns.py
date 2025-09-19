"""
Common Lambda patterns and best practices detection
"""

import re
from typing import Dict, List, Tuple, Set
from dataclasses import dataclass


@dataclass
class Pattern:
    """Lambda code pattern definition"""
    name: str
    description: str
    regex: str
    recommendation: str
    severity: str  # 'info', 'warning', 'error'
    category: str


# Common Lambda anti-patterns and best practices
LAMBDA_PATTERNS = [
    Pattern(
        name="cold_start_initialization",
        description="AWS client initialization inside handler function",
        regex=r"def\s+lambda_handler.*?:\s*(?:[^{]*?)boto3\.(client|resource)",
        recommendation="Move AWS client initialization outside the handler function to reduce cold start time",
        severity="warning",
        category="performance"
    ),
    Pattern(
        name="hardcoded_region",
        description="Hardcoded AWS region in client creation",
        regex=r"region_name\s*=\s*['\"][a-z]+-[a-z]+-\d+['\"]",
        recommendation="Use environment variables or AWS SDK default region configuration",
        severity="warning",
        category="configuration"
    ),
    Pattern(
        name="missing_error_handling",
        description="AWS API calls without error handling",
        regex=r"(?<!try:\s{0,50})\w+\.(get_|put_|delete_|create_|update_|describe_)[a-zA-Z_]+\([^)]*\)(?!\s*except)",
        recommendation="Wrap AWS API calls in try-except blocks for better error handling",
        severity="info",
        category="reliability"
    ),
    Pattern(
        name="synchronous_processing",
        description="Synchronous processing of multiple items in a loop",
        regex=r"for\s+\w+\s+in.*?:\s*(?:[^{]*?)\w+\.(get_|put_|delete_|send_|receive_)",
        recommendation="Consider using batch operations or async processing for better performance",
        severity="info",
        category="performance"
    ),
    Pattern(
        name="inefficient_dynamodb_scan",
        description="Using DynamoDB scan operation",
        regex=r"\w+\.scan\s*\(",
        recommendation="Consider using Query with appropriate indexes instead of Scan for better performance",
        severity="warning",
        category="performance"
    ),
    Pattern(
        name="large_response_construction",
        description="Constructing large response bodies",
        regex=r"['\"]body['\"]\s*:\s*json\.dumps\([^)]{100,}",
        recommendation="Consider streaming large responses or implementing pagination",
        severity="info",
        category="performance"
    ),
    Pattern(
        name="missing_environment_validation",
        description="Using environment variables without validation",
        regex=r"os\.environ\[['\"][^'\"]+['\"]\](?!\s*or\s)",
        recommendation="Use os.environ.get() with default values or validate environment variables",
        severity="warning",
        category="reliability"
    ),
    Pattern(
        name="inefficient_s3_operations",
        description="S3 operations without multipart upload consideration",
        regex=r"s3.*\.put_object\([^)]*Body\s*=.*\)",
        recommendation="Consider using multipart upload for large S3 objects",
        severity="info",
        category="performance"
    ),
    Pattern(
        name="missing_lambda_context_usage",
        description="Lambda handler not using context parameter",
        regex=r"def\s+lambda_handler\s*\([^)]*context[^)]*\):(?:(?!context).)*?return",
        recommendation="Consider using Lambda context for timeout management and request tracking",
        severity="info",
        category="best_practice"
    ),
    Pattern(
        name="inefficient_logging",
        description="Using print() instead of structured logging",
        regex=r"print\s*\(",
        recommendation="Use Python logging module for better log management and structured output",
        severity="info",
        category="observability"
    ),
    Pattern(
        name="missing_correlation_id",
        description="No request correlation ID in logs",
        regex=r"def\s+lambda_handler.*?(?!correlation|request.?id|trace.?id)",
        recommendation="Add correlation IDs to logs for better request tracing",
        severity="info",
        category="observability"
    ),
    Pattern(
        name="inefficient_connection_pooling",
        description="Creating new database connections in loops",
        regex=r"for\s+\w+.*?(?:psycopg2|pymongo|mysql).*?connect",
        recommendation="Use connection pooling or create connections outside loops",
        severity="warning",
        category="performance"
    )
]


class PatternAnalyzer:
    """Analyzes Lambda code for common patterns and anti-patterns"""

    def __init__(self):
        self.patterns = LAMBDA_PATTERNS

    def analyze(self, code: str, ast_analyzer=None) -> List[Dict]:
        """
        Analyze code for Lambda patterns

        Args:
            code: Python source code to analyze
            ast_analyzer: Optional AST analyzer results for additional context

        Returns:
            List of pattern matches with recommendations
        """
        matches = []

        for pattern in self.patterns:
            pattern_matches = self._find_pattern_matches(pattern, code)
            matches.extend(pattern_matches)

        # Add context-aware analysis if AST analyzer provided
        if ast_analyzer:
            context_matches = self._analyze_with_context(code, ast_analyzer)
            matches.extend(context_matches)

        return sorted(matches, key=lambda x: self._get_severity_score(x['severity']), reverse=True)

    def _find_pattern_matches(self, pattern: Pattern, code: str) -> List[Dict]:
        """Find matches for a specific pattern"""
        matches = []

        try:
            pattern_matches = list(re.finditer(pattern.regex, code, re.MULTILINE | re.DOTALL))

            for match in pattern_matches:
                line_number = code[:match.start()].count('\n') + 1

                matches.append({
                    'pattern': pattern.name,
                    'description': pattern.description,
                    'line_number': line_number,
                    'recommendation': pattern.recommendation,
                    'severity': pattern.severity,
                    'category': pattern.category,
                    'matched_text': self._get_context_snippet(code, match.start(), match.end())
                })
        except re.error as e:
            # Skip invalid regex patterns
            pass

        return matches

    def _analyze_with_context(self, code: str, ast_analyzer) -> List[Dict]:
        """Perform context-aware analysis using AST information"""
        matches = []

        # Check for unused imports
        unused_imports = self._find_unused_imports(code, ast_analyzer)
        matches.extend(unused_imports)

        # Check for inefficient service usage patterns
        service_patterns = self._analyze_service_usage_patterns(ast_analyzer)
        matches.extend(service_patterns)

        # Check for missing optimizations
        optimization_patterns = self._suggest_optimizations(ast_analyzer)
        matches.extend(optimization_patterns)

        return matches

    def _find_unused_imports(self, code: str, ast_analyzer) -> List[Dict]:
        """Find potentially unused imports"""
        matches = []

        for import_alias, full_import in ast_analyzer.imports.items():
            # Simple check - more sophisticated analysis would track actual usage
            if import_alias not in code.replace(f"import {import_alias}", ""):
                matches.append({
                    'pattern': 'unused_import',
                    'description': f'Potentially unused import: {import_alias}',
                    'line_number': None,
                    'recommendation': f'Remove unused import {import_alias} to reduce cold start time',
                    'severity': 'info',
                    'category': 'performance',
                    'matched_text': f'import {full_import}'
                })

        return matches

    def _analyze_service_usage_patterns(self, ast_analyzer) -> List[Dict]:
        """Analyze AWS service usage patterns"""
        matches = []

        # Check for excessive service clients
        if len(ast_analyzer.service_clients) > 5:
            matches.append({
                'pattern': 'excessive_service_clients',
                'description': f'Using {len(ast_analyzer.service_clients)} AWS service clients',
                'line_number': None,
                'recommendation': 'Consider splitting Lambda function into smaller, focused functions',
                'severity': 'warning',
                'category': 'architecture',
                'matched_text': f'Services: {", ".join(ast_analyzer.service_clients.keys())}'
            })

        # Check for DynamoDB anti-patterns
        if 'dynamodb' in ast_analyzer.api_calls:
            dynamodb_calls = ast_analyzer.api_calls['dynamodb']
            if 'scan' in dynamodb_calls and 'query' not in dynamodb_calls:
                matches.append({
                    'pattern': 'dynamodb_scan_only',
                    'description': 'Only using DynamoDB Scan operations',
                    'line_number': None,
                    'recommendation': 'Consider adding GSI and using Query operations for better performance',
                    'severity': 'warning',
                    'category': 'performance',
                    'matched_text': 'DynamoDB Scan operations detected'
                })

        return matches

    def _suggest_optimizations(self, ast_analyzer) -> List[Dict]:
        """Suggest performance optimizations"""
        matches = []

        # Suggest Lambda Layers for many dependencies
        if len(ast_analyzer.imports) > 10:
            matches.append({
                'pattern': 'many_dependencies',
                'description': f'Function has {len(ast_analyzer.imports)} imports',
                'line_number': None,
                'recommendation': 'Consider using Lambda Layers for shared dependencies',
                'severity': 'info',
                'category': 'performance',
                'matched_text': f'{len(ast_analyzer.imports)} imports detected'
            })

        # Suggest environment variable consolidation
        if len(ast_analyzer.environment_variables) > 15:
            matches.append({
                'pattern': 'many_env_vars',
                'description': f'Function uses {len(ast_analyzer.environment_variables)} environment variables',
                'line_number': None,
                'recommendation': 'Consider using AWS Systems Manager Parameter Store for configuration',
                'severity': 'info',
                'category': 'configuration',
                'matched_text': f'{len(ast_analyzer.environment_variables)} environment variables'
            })

        return matches

    def _get_context_snippet(self, code: str, start: int, end: int, context_lines: int = 2) -> str:
        """Get code snippet with context around the match"""
        lines = code.split('\n')
        start_line = code[:start].count('\n')
        end_line = code[:end].count('\n')

        context_start = max(0, start_line - context_lines)
        context_end = min(len(lines), end_line + context_lines + 1)

        snippet_lines = lines[context_start:context_end]
        snippet = '\n'.join(snippet_lines)

        # Truncate if too long
        if len(snippet) > 200:
            snippet = snippet[:197] + "..."

        return snippet

    def _get_severity_score(self, severity: str) -> int:
        """Get numeric score for severity level"""
        severity_scores = {
            'error': 3,
            'warning': 2,
            'info': 1
        }
        return severity_scores.get(severity, 0)

    def get_patterns_by_category(self, category: str = None) -> List[Pattern]:
        """Get patterns filtered by category"""
        if category is None:
            return self.patterns

        return [p for p in self.patterns if p.category == category]

    def get_pattern_categories(self) -> Set[str]:
        """Get all available pattern categories"""
        return {p.category for p in self.patterns}


def suggest_optimizations_from_analysis(analysis_result) -> List[str]:
    """
    Suggest optimizations based on analysis results

    Args:
        analysis_result: AnalysisResult object

    Returns:
        List of optimization suggestions
    """
    suggestions = []

    # Memory optimization suggestions
    if len(analysis_result.services) <= 2:
        suggestions.append("Consider reducing Lambda memory allocation if resource usage is low")
    elif len(analysis_result.services) > 5:
        suggestions.append("Consider increasing Lambda memory allocation for better performance")

    # Cold start optimization
    service_count = len(set().union(*analysis_result.api_calls.values())) if analysis_result.api_calls else 0
    if service_count > 5:
        suggestions.append("Consider using Lambda Layers for shared AWS SDK dependencies")

    # Service-specific optimizations
    if 'dynamodb' in analysis_result.services:
        dynamodb_calls = analysis_result.api_calls.get('dynamodb', [])
        if 'scan' in dynamodb_calls and len(dynamodb_calls) > 2:
            suggestions.append("Optimize DynamoDB usage with Query operations and proper indexing")
        if 'batch_get_item' not in dynamodb_calls and 'get_item' in dynamodb_calls:
            suggestions.append("Consider using DynamoDB batch operations for multiple items")

    if 's3' in analysis_result.services:
        s3_calls = analysis_result.api_calls.get('s3', [])
        if 'list_objects_v2' in s3_calls:
            suggestions.append("Use pagination for S3 list operations with large datasets")
        if 'put_object' in s3_calls:
            suggestions.append("Consider using S3 multipart upload for large files")

    # Configuration optimizations
    if len(analysis_result.environment_variables) > 10:
        suggestions.append("Consolidate configuration using AWS Systems Manager Parameter Store")

    # Architecture suggestions
    if analysis_result.confidence_score < 0.5:
        suggestions.append("Review function structure - low confidence may indicate complex patterns")

    return suggestions