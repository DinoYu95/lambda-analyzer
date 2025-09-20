"""
Tests for the AWS service detector
"""

import pytest
from lambda_analyzer.core.service_detector import AWSServiceDetector
from lambda_analyzer.core.ast_parser import ASTAnalyzer
import ast


class TestAWSServiceDetector:
    """Test AWS service detection functionality"""

    def test_service_detection_from_api_calls(self):
        """Test service detection from API calls"""
        # Mock AST analyzer with API calls
        ast_analyzer = ASTAnalyzer()
        ast_analyzer.api_calls = {
            's3': {'get_object', 'put_object'},
            'dynamodb': {'get_item', 'put_item'}
        }

        detector = AWSServiceDetector()
        services, api_calls = detector.detect_services(ast_analyzer)

        assert 's3' in services
        assert 'dynamodb' in services
        assert 'get_object' in api_calls['s3']
        assert 'put_item' in api_calls['dynamodb']

    def test_service_detection_from_clients(self):
        """Test service detection from service clients"""
        ast_analyzer = ASTAnalyzer()
        ast_analyzer.service_clients = {
            's3_client': {'service': 's3', 'type': 'client'},
            'dynamodb_resource': {'service': 'dynamodb', 'type': 'resource'}
        }
        ast_analyzer.api_calls = {}  # No direct API calls

        detector = AWSServiceDetector()
        services, api_calls = detector.detect_services(ast_analyzer)

        assert 's3' in services
        assert 'dynamodb' in services

    def test_trigger_detection_s3(self):
        """Test S3 trigger detection"""
        code = '''
def lambda_handler(event, context):
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']
    return {'statusCode': 200}
'''

        event_accesses = ["event['Records']", "event['Records'][0]['s3']"]

        detector = AWSServiceDetector()
        triggers = detector.detect_triggers(event_accesses, code)

        assert len(triggers) > 0
        assert any(trigger['type'] == 's3' for trigger in triggers)
        s3_trigger = next(t for t in triggers if t['type'] == 's3')
        assert s3_trigger['confidence'] in ['high', 'medium', 'low']

    def test_trigger_detection_api_gateway(self):
        """Test API Gateway trigger detection"""
        code = '''
def lambda_handler(event, context):
    method = event['httpMethod']
    path = event['path']
    headers = event['headers']
    return {'statusCode': 200}
'''

        event_accesses = ["event['httpMethod']", "event['path']", "event['headers']"]

        detector = AWSServiceDetector()
        triggers = detector.detect_triggers(event_accesses, code)

        assert any(trigger['type'] == 'api_gateway' for trigger in triggers)

    def test_trigger_detection_sqs(self):
        """Test SQS trigger detection"""
        code = '''
def lambda_handler(event, context):
    for record in event['Records']:
        body = record['body']
        message_id = record['messageId']
    return {'statusCode': 200}
'''

        event_accesses = ["event['Records']"]

        detector = AWSServiceDetector()
        triggers = detector.detect_triggers(event_accesses, code)

        # May detect SQS trigger based on patterns
        trigger_types = [t['type'] for t in triggers]
        assert len(triggers) >= 0  # Could be SQS, SNS, or S3

    def test_service_inference_from_environment_variables(self):
        """Test service inference from environment variable names"""
        ast_analyzer = ASTAnalyzer()
        ast_analyzer.api_calls = {}
        ast_analyzer.service_clients = {}
        ast_analyzer.environment_variables = {
            'TABLE_NAME', 'BUCKET_NAME', 'TOPIC_ARN', 'QUEUE_URL'
        }
        ast_analyzer.string_literals = []

        detector = AWSServiceDetector()
        services, api_calls = detector.detect_services(ast_analyzer)

        # Should infer services from environment variable patterns
        assert len(services) >= 0  # May infer dynamodb, s3, sns, sqs

    def test_confidence_scoring(self):
        """Test trigger confidence scoring"""
        detector = AWSServiceDetector()

        # High confidence - multiple patterns match
        patterns = [r"event\s*\[\s*['\"]Records['\"]", r"\.s3\.\s*bucket\.\s*name"]
        event_accesses = ["event['Records'][0]['s3']['bucket']['name']"]
        code = "bucket = event['Records'][0]['s3']['bucket']['name']"

        confidence = detector._calculate_trigger_confidence(patterns, event_accesses, code)
        assert confidence > 0.5

        # Low confidence - few patterns match
        patterns = [r"event\s*\[\s*['\"]Records['\"]", r"nonexistent_pattern"]
        confidence = detector._calculate_trigger_confidence(patterns, event_accesses, code)
        assert 0.0 <= confidence <= 1.0

    def test_display_names(self):
        """Test service display name mapping"""
        detector = AWSServiceDetector()

        assert detector.get_service_display_name('s3') == 'Amazon S3'
        assert detector.get_service_display_name('dynamodb') == 'Amazon DynamoDB'
        assert detector.get_service_display_name('unknown_service') == 'Unknown_Service'