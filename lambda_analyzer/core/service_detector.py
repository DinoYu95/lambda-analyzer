"""
AWS Service Detection Module

This module is responsible for detecting AWS services used in Lambda functions
and inferring trigger sources from event patterns.
"""

import re
from typing import Dict, List, Set, Tuple
from .ast_parser import ASTAnalyzer


class AWSServiceDetector:
    """Detects AWS services and triggers from analyzed code"""

    # AWS Service name mappings for display
    SERVICE_DISPLAY_NAMES = {
        's3': 'Amazon S3',
        'dynamodb': 'Amazon DynamoDB',
        'sns': 'Amazon SNS',
        'sqs': 'Amazon SQS',
        'lambda': 'AWS Lambda',
        'secretsmanager': 'AWS Secrets Manager',
        'ssm': 'AWS Systems Manager',
        'rds': 'Amazon RDS',
        'ec2': 'Amazon EC2',
        'cloudwatch': 'Amazon CloudWatch',
        'logs': 'Amazon CloudWatch Logs',
        'kinesis': 'Amazon Kinesis',
        'elasticache': 'Amazon ElastiCache',
        'ses': 'Amazon SES',
        'cognito-idp': 'Amazon Cognito',
        'stepfunctions': 'AWS Step Functions',
        'apigateway': 'Amazon API Gateway',
    }

    # Event patterns for trigger detection
    TRIGGER_PATTERNS = {
        'api_gateway': [
            r"event\s*\[\s*['\"]httpMethod['\"]",
            r"event\s*\[\s*['\"]path['\"]",
            r"event\s*\[\s*['\"]headers['\"]",
            r"event\s*\[\s*['\"]queryStringParameters['\"]",
            r"event\s*\[\s*['\"]body['\"]",
        ],
        's3': [
            r"event\s*\[\s*['\"]Records['\"].*\[\s*0\s*\]\s*\[\s*['\"]s3['\"]",
            r"event\s*\[\s*['\"]Records['\"].*eventSource.*aws:s3",
            r"\.s3\.\s*bucket\.\s*name",
            r"\.s3\.\s*object\.\s*key",
        ],
        'dynamodb': [
            r"event\s*\[\s*['\"]Records['\"].*\[\s*0\s*\]\s*\[\s*['\"]dynamodb['\"]",
            r"event\s*\[\s*['\"]Records['\"].*eventSource.*aws:dynamodb",
            r"\.dynamodb\.\s*Keys",
            r"\.dynamodb\.\s*NewImage",
            r"\.dynamodb\.\s*OldImage",
        ],
        'sqs': [
            r"event\s*\[\s*['\"]Records['\"].*\[\s*0\s*\]\s*\[\s*['\"]body['\"]",
            r"event\s*\[\s*['\"]Records['\"].*eventSource.*aws:sqs",
            r"\.messageId",
            r"\.receiptHandle",
        ],
        'sns': [
            r"event\s*\[\s*['\"]Records['\"].*\[\s*0\s*\]\s*\[\s*['\"]Sns['\"]",
            r"event\s*\[\s*['\"]Records['\"].*eventSource.*aws:sns",
            r"\.Sns\.\s*Message",
            r"\.Sns\.\s*Subject",
        ],
        'kinesis': [
            r"event\s*\[\s*['\"]Records['\"].*\[\s*0\s*\]\s*\[\s*['\"]kinesis['\"]",
            r"event\s*\[\s*['\"]Records['\"].*eventSource.*aws:kinesis",
            r"\.kinesis\.\s*data",
            r"\.kinesis\.\s*sequenceNumber",
        ],
        'cloudwatch_events': [
            r"event\s*\[\s*['\"]source['\"].*aws\.events",
            r"event\s*\[\s*['\"]detail-type['\"]",
            r"event\s*\[\s*['\"]detail['\"]",
        ],
        'cloudwatch_logs': [
            r"event\s*\[\s*['\"]awslogs['\"]",
            r"gzip\.decompress",
            r"base64\.b64decode.*awslogs",
        ],
        'scheduled': [
            r"event\s*\[\s*['\"]source['\"].*aws\.events",
            r"ScheduleExpression",
            r"aws\.events.*Scheduled",
        ]
    }

    def detect_services(self, ast_analyzer: ASTAnalyzer) -> Tuple[List[str], Dict[str, List[str]]]:
        """
        Detect AWS services used in the code

        Args:
            ast_analyzer: Analyzed AST information

        Returns:
            Tuple of (service_list, api_calls_dict)
        """
        services = set()
        api_calls = {}

        # Get services from direct API calls
        for service, methods in ast_analyzer.api_calls.items():
            services.add(service)
            api_calls[service] = list(methods)

        # Get services from service client creation
        for client_info in ast_analyzer.service_clients.values():
            service = client_info['service']
            services.add(service)
            if service not in api_calls:
                api_calls[service] = []

        # Infer additional services from string patterns
        inferred_services = self._infer_services_from_strings(
            ast_analyzer.string_literals,
            ast_analyzer.environment_variables
        )
        services.update(inferred_services)

        return sorted(list(services)), api_calls

    def detect_triggers(self, event_accesses: List[str], code: str) -> List[Dict]:
        """
        Detect Lambda trigger sources from event access patterns

        Args:
            event_accesses: List of event access patterns from AST
            code: Raw source code for pattern matching

        Returns:
            List of trigger information dictionaries
        """
        triggers = []
        detected_triggers = set()

        # Check each trigger pattern
        for trigger_type, patterns in self.TRIGGER_PATTERNS.items():
            confidence = self._calculate_trigger_confidence(patterns, event_accesses, code)

            if confidence > 0:
                if trigger_type not in detected_triggers:
                    triggers.append({
                        'type': trigger_type,
                        'confidence': self._confidence_to_level(confidence),
                        'score': confidence
                    })
                    detected_triggers.add(trigger_type)

        # Sort by confidence score
        triggers.sort(key=lambda x: x['score'], reverse=True)

        return triggers

    def _infer_services_from_strings(self, string_literals: List[str],
                                     env_vars: Set[str]) -> Set[str]:
        """Infer AWS services from string literals and environment variables"""
        inferred = set()

        # Common environment variable patterns
        env_patterns = {
            'TABLE_NAME': 'dynamodb',
            'BUCKET_NAME': 's3',
            'TOPIC_ARN': 'sns',
            'QUEUE_URL': 'sqs',
            'DB_HOST': 'rds',
            'CLUSTER_ENDPOINT': 'rds',
            'SECRET_ARN': 'secretsmanager',
            'PARAMETER_NAME': 'ssm',
        }

        for env_var in env_vars:
            env_upper = env_var.upper()
            for pattern, service in env_patterns.items():
                if pattern in env_upper:
                    inferred.add(service)
                    break

        # String literal patterns
        string_patterns = {
            'arn:aws:s3:': 's3',
            'arn:aws:dynamodb:': 'dynamodb',
            'arn:aws:sns:': 'sns',
            'arn:aws:sqs:': 'sqs',
            'arn:aws:lambda:': 'lambda',
            'arn:aws:secretsmanager:': 'secretsmanager',
            'arn:aws:ssm:': 'ssm',
            'arn:aws:rds:': 'rds',
            '.amazonaws.com': 'general_aws',
        }

        for literal in string_literals:
            if isinstance(literal, str):
                literal_lower = literal.lower()
                for pattern, service in string_patterns.items():
                    if pattern in literal_lower and service != 'general_aws':
                        inferred.add(service)

        return inferred

    def _calculate_trigger_confidence(self, patterns: List[str],
                                      event_accesses: List[str], code: str) -> float:
        """Calculate confidence score for a specific trigger type"""
        matches = 0
        total_patterns = len(patterns)

        # Check patterns against event accesses
        for pattern in patterns:
            # Check in event access patterns
            for access in event_accesses:
                if re.search(pattern, access, re.IGNORECASE):
                    matches += 1
                    break
            else:
                # Check in raw code if not found in event accesses
                if re.search(pattern, code, re.IGNORECASE):
                    matches += 0.5  # Lower confidence for general code matches

        return matches / total_patterns if total_patterns > 0 else 0.0

    def _confidence_to_level(self, score: float) -> str:
        """Convert numerical confidence to level string"""
        if score >= 0.7:
            return 'high'
        elif score >= 0.4:
            return 'medium'
        elif score > 0:
            return 'low'
        else:
            return 'none'

    def get_service_display_name(self, service: str) -> str:
        """Get human-readable display name for AWS service"""
        return self.SERVICE_DISPLAY_NAMES.get(service, service.upper())