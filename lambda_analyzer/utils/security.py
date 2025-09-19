"""
Security analysis utilities for Lambda functions
"""

import re
from typing import List, Dict, Set, Pattern as RePattern
from dataclasses import dataclass


@dataclass
class SecurityPattern:
    """Security pattern definition"""
    name: str
    description: str
    regex: str
    severity: str  # 'high', 'medium', 'low'
    category: str  # 'secrets', 'permissions', 'injection', 'configuration'
    suggestion: str


class SecurityAnalyzer:
    """Analyzes Lambda code for security issues"""

    # Security patterns to detect
    SECURITY_PATTERNS = [
        SecurityPattern(
            name="aws_access_key",
            description="AWS Access Key ID detected",
            regex=r'AKIA[A-Z0-9]{16}',
            severity="high",
            category="secrets",
            suggestion="Use AWS IAM roles instead of hardcoded access keys"
        ),
        SecurityPattern(
            name="aws_secret_key",
            description="Potential AWS Secret Access Key detected",
            regex=r'[A-Za-z0-9+/]{40}',
            severity="high",
            category="secrets",
            suggestion="Use AWS Secrets Manager or environment variables"
        ),
        SecurityPattern(
            name="hardcoded_password",
            description="Hardcoded password detected",
            regex=r'password\s*[=:]\s*["\'][^"\']{8,}["\']',
            severity="high",
            category="secrets",
            suggestion="Use AWS Secrets Manager for password storage"
        ),
        SecurityPattern(
            name="api_key_hardcoded",
            description="Hardcoded API key detected",
            regex=r'api[_-]?key\s*[=:]\s*["\'][^"\']{10,}["\']',
            severity="high",
            category="secrets",
            suggestion="Store API keys in AWS Secrets Manager or Parameter Store"
        ),
        SecurityPattern(
            name="database_connection_string",
            description="Database connection string with credentials",
            regex=r'["\'](?:mysql|postgres|mongodb)://[^"\']*:[^"\']*@[^"\']+["\']',
            severity="high",
            category="secrets",
            suggestion="Use AWS RDS IAM authentication or Secrets Manager"
        ),
        SecurityPattern(
            name="private_key",
            description="Private key detected",
            regex=r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
            severity="high",
            category="secrets",
            suggestion="Store private keys in AWS Secrets Manager or Parameter Store"
        ),
        SecurityPattern(
            name="wildcard_resource",
            description="Wildcard resource permissions",
            regex=r'["\']Resource["\']\s*:\s*["\']\*["\']',
            severity="medium",
            category="permissions",
            suggestion="Use specific resource ARNs instead of wildcards"
        ),
        SecurityPattern(
            name="sql_injection_risk",
            description="Potential SQL injection vulnerability",
            regex=r'(?:SELECT|INSERT|UPDATE|DELETE).*?\+.*?(?:event|request|input)',
            severity="medium",
            category="injection",
            suggestion="Use parameterized queries to prevent SQL injection"
        ),
        SecurityPattern(
            name="command_injection_risk",
            description="Potential command injection vulnerability",
            regex=r'(?:os\.system|subprocess\.call|subprocess\.run)\([^)]*(?:event|request|input)',
            severity="high",
            category="injection",
            suggestion="Sanitize input before executing system commands"
        ),
        SecurityPattern(
            name="path_traversal_risk",
            description="Potential path traversal vulnerability",
            regex=r'(?:open|file|read).*?event.*?["\'][^"\']*\.\./.*?["\']',
            severity="medium",
            category="injection",
            suggestion="Validate file paths and use absolute paths"
        ),
        SecurityPattern(
            name="debug_mode_enabled",
            description="Debug mode enabled in production code",
            regex=r'debug\s*[=:]\s*True',
            severity="medium",
            category="configuration",
            suggestion="Disable debug mode in production environments"
        ),
        SecurityPattern(
            name="insecure_random",
            description="Using insecure random number generation",
            regex=r'random\.random\(\)|random\.choice\(',
            severity="low",
            category="configuration",
            suggestion="Use secrets.SystemRandom() for cryptographically secure randomness"
        ),
        SecurityPattern(
            name="http_without_https",
            description="HTTP URL without HTTPS",
            regex=r'["\']http://[^"\']+["\']',
            severity="low",
            category="configuration",
            suggestion="Use HTTPS for all external communications"
        ),
        SecurityPattern(
            name="weak_cipher",
            description="Weak cryptographic cipher detected",
            regex=r'(?:DES|MD5|SHA1)(?!.*HMAC)',
            severity="medium",
            category="configuration",
            suggestion="Use strong cryptographic algorithms like AES-256 or SHA-256"
        ),
        SecurityPattern(
            name="exposed_sensitive_info",
            description="Sensitive information in logs",
            regex=r'(?:print|log|logger).*?(?:password|token|key|secret)',
            severity="medium",
            category="configuration",
            suggestion="Avoid logging sensitive information"
        )
    ]

    def __init__(self, config: Dict):
        """Initialize with configuration"""
        self.config = config
        self.security_config = config.get('security', {})
        self.compiled_patterns = self._compile_patterns()

    def _compile_patterns(self) -> List[tuple]:
        """Compile regex patterns for better performance"""
        compiled = []
        for pattern in self.SECURITY_PATTERNS:
            try:
                compiled.append((pattern, re.compile(pattern.regex, re.IGNORECASE)))
            except re.error:
                # Skip invalid patterns
                continue
        return compiled

    def analyze(self, code: str, ast_analyzer=None) -> List:
        """
        Perform comprehensive security analysis

        Args:
            code: Python source code to analyze
            ast_analyzer: Optional AST analyzer results for additional context

        Returns:
            List of SecurityIssue objects
        """
        from ..core.analyzer import SecurityIssue  # Import here to avoid circular imports

        issues = []

        # Pattern-based analysis
        if self.security_config.get('check_hardcoded_secrets', True):
            issues.extend(self._check_patterns(code))

        # Context-aware analysis using AST information
        if ast_analyzer:
            if self.security_config.get('check_wildcard_permissions', True):
                issues.extend(self._check_wildcard_permissions(ast_analyzer))

            if self.security_config.get('check_error_handling', True):
                issues.extend(self._check_error_handling(code, ast_analyzer))

            issues.extend(self._check_service_specific_security(ast_analyzer))

        # Additional checks
        issues.extend(self._check_lambda_specific_security(code))

        return issues

    def _check_patterns(self, code: str) -> List:
        """Check for security patterns in code"""
        from ..core.analyzer import SecurityIssue

        issues = []

        for pattern, compiled_regex in self.compiled_patterns:
            matches = compiled_regex.finditer(code)

            for match in matches:
                line_number = code[:match.start()].count('\n') + 1

                # Additional validation for some patterns
                if self._validate_match(pattern, match.group(0), code):
                    issues.append(SecurityIssue(
                        severity=pattern.severity,
                        message=pattern.description,
                        line_number=line_number,
                        suggestion=pattern.suggestion
                    ))

        return issues

    def _validate_match(self, pattern: SecurityPattern, matched_text: str, code: str) -> bool:
        """Validate that a pattern match is a real security issue"""

        # Filter out common false positives
        false_positive_indicators = [
            '# TODO', '# FIXME', '# NOTE', '# EXAMPLE',
            'test_', 'mock_', 'fake_', 'dummy_',
            'example.com', 'localhost', '127.0.0.1'
        ]

        # Check if match is in a comment or test context
        for indicator in false_positive_indicators:
            if indicator.lower() in matched_text.lower():
                return False

        # Pattern-specific validation
        if pattern.name == "aws_secret_key":
            # AWS secret keys should be exactly 40 characters and base64-like
            if len(matched_text) != 40:
                return False
            # Additional checks could include entropy analysis

        elif pattern.name == "hardcoded_password":
            # Avoid flagging obvious placeholders
            placeholder_patterns = ['password', 'secret', 'key', '123456', 'admin']
            if any(placeholder in matched_text.lower() for placeholder in placeholder_patterns):
                return False

        return True

    def _check_wildcard_permissions(self, ast_analyzer) -> List:
        """Check for overly permissive IAM policies"""
        from ..core.analyzer import SecurityIssue

        issues = []

        # Check if any API calls suggest wildcard usage
        for service, calls in ast_analyzer.api_calls.items():
            if any('*' in str(call) for call in calls):
                issues.append(SecurityIssue(
                    severity="medium",
                    message=f"Potential wildcard permissions detected in {service} usage",
                    suggestion="Use specific resource ARNs instead of wildcards for better security"
                ))

        return issues

    def _check_error_handling(self, code: str, ast_analyzer) -> List:
        """Check for proper error handling around security-sensitive operations"""
        from ..core.analyzer import SecurityIssue

        issues = []

        # Check if there are AWS API calls without try-except blocks
        if ast_analyzer.api_calls and not ast_analyzer.has_try_except:
            issues.append(SecurityIssue(
                severity="low",
                message="AWS API calls without error handling detected",
                suggestion="Add try-except blocks to handle AWS API errors securely"
            ))

        # Check for generic exception handling that might hide security issues
        if 'except Exception:' in code or 'except:' in code:
            issues.append(SecurityIssue(
                severity="low",
                message="Generic exception handling detected",
                suggestion="Use specific exception types to avoid masking security issues"
            ))

        return issues

    def _check_service_specific_security(self, ast_analyzer) -> List:
        """Check for service-specific security issues"""
        from ..core.analyzer import SecurityIssue

        issues = []

        # S3 security checks
        if 's3' in ast_analyzer.api_calls:
            s3_calls = ast_analyzer.api_calls['s3']
            if 'put_bucket_policy' in s3_calls:
                issues.append(SecurityIssue(
                    severity="medium",
                    message="S3 bucket policy modifications detected",
                    suggestion="Ensure bucket policies follow principle of least privilege"
                ))

            if 'put_object' in s3_calls:
                issues.append(SecurityIssue(
                    severity="low",
                    message="S3 object uploads detected",
                    suggestion="Ensure uploaded content is validated and scanned"
                ))

        # DynamoDB security checks
        if 'dynamodb' in ast_analyzer.api_calls:
            dynamodb_calls = ast_analyzer.api_calls['dynamodb']
            if 'scan' in dynamodb_calls:
                issues.append(SecurityIssue(
                    severity="low",
                    message="DynamoDB scan operations may expose sensitive data",
                    suggestion="Use Query operations with proper filtering to limit data exposure"
                ))

        # Lambda security checks
        if 'lambda' in ast_analyzer.api_calls:
            issues.append(SecurityIssue(
                severity="medium",
                message="Lambda function invocations detected",
                suggestion="Ensure invoked functions have proper IAM permissions and input validation"
            ))

        return issues

    def _check_lambda_specific_security(self, code: str) -> List:
        """Check for Lambda-specific security issues"""
        from ..core.analyzer import SecurityIssue

        issues = []

        # Check for environment variable usage patterns
        env_access_patterns = [
            r'os\.environ\[["\']([^"\']+)["\']\]',
            r'os\.getenv\(["\']([^"\']+)["\']'
        ]

        for pattern in env_access_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                env_var = match.group(1)
                if any(sensitive in env_var.lower() for sensitive in ['key', 'secret', 'password', 'token']):
                    line_number = code[:match.start()].count('\n') + 1
                    issues.append(SecurityIssue(
                        severity="medium",
                        message=f"Sensitive environment variable access: {env_var}",
                        line_number=line_number,
                        suggestion="Consider using AWS Secrets Manager for sensitive configuration"
                    ))

        # Check for event data handling
        if 'event[' in code and 'json.loads' not in code:
            issues.append(SecurityIssue(
                severity="low",
                message="Direct event data usage without validation",
                suggestion="Validate and sanitize event data before processing"
            ))

        # Check for response data handling
        if re.search(r'return\s*{[^}]*["\']body["\']', code):
            issues.append(SecurityIssue(
                severity="low",
                message="Response body construction detected",
                suggestion="Ensure response data doesn't contain sensitive information"
            ))

        return issues

    def get_security_summary(self, issues: List) -> Dict[str, int]:
        """Get summary of security issues by severity"""
        summary = {'high': 0, 'medium': 0, 'low': 0}

        for issue in issues:
            if issue.severity in summary:
                summary[issue.severity] += 1

        return summary

    def get_issues_by_category(self, issues: List, category: str = None) -> List:
        """Filter issues by category"""
        if category is None:
            return issues

        # This would need to track pattern categories in the SecurityIssue
        # For now, return all issues
        return issues