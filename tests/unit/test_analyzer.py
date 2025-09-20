"""
Tests for the main LambdaAnalyzer class
"""

import pytest
import os
from pathlib import Path

from lambda_analyzer import LambdaAnalyzer, AnalysisResult
from lambda_analyzer.core.analyzer import SecurityIssue


class TestLambdaAnalyzer:
    """Test the main LambdaAnalyzer functionality"""

    def test_initialization(self, sample_config):
        """Test analyzer initialization"""
        analyzer = LambdaAnalyzer()
        assert analyzer is not None
        assert analyzer.config is not None

    def test_analyze_simple_lambda(self, temp_dir):
        """Test analysis of simple Lambda function"""
        # Create test file
        lambda_content = '''
            import json
            
            def lambda_handler(event, context):
                return {
                    'statusCode': 200,
                    'body': json.dumps('Hello World')
                }
        '''
        lambda_file = temp_dir / "simple_lambda.py"
        lambda_file.write_text(lambda_content)

        analyzer = LambdaAnalyzer()
        result = analyzer.analyze_file(str(lambda_file))

        assert isinstance(result, AnalysisResult)
        assert result.file_path == str(lambda_file)
        assert result.confidence_score >= 0.0
        assert isinstance(result.services, list)
        assert isinstance(result.api_calls, dict)

    def test_analyze_s3_lambda(self, temp_dir):
        """Test analysis of S3 Lambda function"""
        lambda_content = '''
import boto3
import json

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']

    response = s3.get_object(Bucket=bucket, Key=key)
    s3.put_object(Bucket=bucket, Key=f"processed/{key}", Body="processed")

    return {'statusCode': 200}
'''
        lambda_file = temp_dir / "s3_lambda.py"
        lambda_file.write_text(lambda_content)

        analyzer = LambdaAnalyzer()
        result = analyzer.analyze_file(str(lambda_file))

        assert 's3' in result.services
        assert 's3' in result.api_calls
        assert 'get_object' in result.api_calls['s3']
        assert 'put_object' in result.api_calls['s3']
        assert len(result.triggers) > 0
        assert any(trigger['type'] == 's3' for trigger in result.triggers)
        assert result.confidence_score > 0.5

    def test_analyze_multi_service_lambda(self, temp_dir):
        """Test analysis of Lambda using multiple services"""
        lambda_content = '''
import boto3
import os

def lambda_handler(event, context):
    dynamodb = boto3.resource('dynamodb')
    s3 = boto3.client('s3')
    sns = boto3.client('sns')

    table_name = os.environ['TABLE_NAME']
    bucket_name = os.environ['BUCKET_NAME']
    topic_arn = os.environ['TOPIC_ARN']

    table = dynamodb.Table(table_name)

    table.put_item(Item={'id': '123', 'data': event})
    s3.put_object(Bucket=bucket_name, Key='data.json', Body='{}')
    sns.publish(TopicArn=topic_arn, Message='Done')

    return {'statusCode': 200}
'''
        lambda_file = temp_dir / "multi_lambda.py"
        lambda_file.write_text(lambda_content)

        analyzer = LambdaAnalyzer()
        result = analyzer.analyze_file(str(lambda_file))

        expected_services = {'dynamodb', 's3', 'sns'}
        assert expected_services.issubset(set(result.services))

        expected_env_vars = {'TABLE_NAME', 'BUCKET_NAME', 'TOPIC_ARN'}
        assert expected_env_vars.issubset(set(result.environment_variables))

        # Check IAM permissions
        iam_str = str(result.iam_policy)
        assert 'dynamodb:PutItem' in iam_str
        assert 's3:PutObject' in iam_str
        assert 'sns:Publish' in iam_str

    def test_analyze_directory(self, temp_dir):
        """Test directory analysis"""
        # Create multiple Lambda files
        lambda1 = temp_dir / "lambda1.py"
        lambda1.write_text('''
import boto3
def lambda_handler(event, context):
    s3 = boto3.client('s3')
    return {'statusCode': 200}
''')

        lambda2 = temp_dir / "lambda2.py"
        lambda2.write_text('''
import boto3
def lambda_handler(event, context):
    dynamodb = boto3.resource('dynamodb')
    return {'statusCode': 200}
''')

        # Create a test file that should be excluded
        test_file = temp_dir / "test_lambda.py"
        test_file.write_text('# test file')

        analyzer = LambdaAnalyzer()
        results = analyzer.analyze_directory(str(temp_dir))

        # Should analyze 2 files (excluding test file)
        assert len(results) == 2
        assert all(isinstance(r, AnalysisResult) for r in results)

        # Check that different services were detected
        all_services = set()
        for result in results:
            all_services.update(result.services)
        assert 's3' in all_services or 'dynamodb' in all_services

    def test_security_analysis(self, temp_dir):
        """Test security issue detection"""
        insecure_content = '''
import boto3

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
API_KEY = "sk-1234567890abcdef"

def lambda_handler(event, context):
    s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY)
    # No error handling
    response = s3.get_object(Bucket='*', Key=event['key'])
    print(f"API key: {API_KEY}")
    return response
'''
        lambda_file = temp_dir / "insecure.py"
        lambda_file.write_text(insecure_content)

        analyzer = LambdaAnalyzer()
        result = analyzer.analyze_file(str(lambda_file))

        # Should detect security issues
        assert len(result.security_issues) > 0

        # Check for specific security issues
        issue_messages = [issue.message for issue in result.security_issues]
        assert any('access key' in msg.lower() for msg in issue_messages)

    def test_confidence_scoring(self, temp_dir):
        """Test confidence score calculation"""
        # High confidence code (clear boto3 usage)
        high_confidence = '''
import boto3
def lambda_handler(event, context):
    s3 = boto3.client('s3')
    return s3.get_object(Bucket='test', Key='test.txt')
'''

        # Low confidence code (only imports)
        low_confidence = '''
import boto3
def lambda_handler(event, context):
    return {'statusCode': 200}
'''

        analyzer = LambdaAnalyzer()

        high_file = temp_dir / "high.py"
        high_file.write_text(high_confidence)
        high_result = analyzer.analyze_file(str(high_file))

        low_file = temp_dir / "low.py"
        low_file.write_text(low_confidence)
        low_result = analyzer.analyze_file(str(low_file))

        assert high_result.confidence_score > low_result.confidence_score
        assert high_result.confidence_score > 0.5

    def test_file_not_found(self, temp_dir):
        """Test handling of non-existent files"""
        analyzer = LambdaAnalyzer()
        result = analyzer.analyze_file(str(temp_dir / "nonexistent.py"))

        assert len(result.security_issues) > 0
        assert any('not found' in issue.message.lower() for issue in result.security_issues)
        assert result.confidence_score == 0.0

    def test_syntax_error_handling(self, temp_dir):
        """Test handling of files with syntax errors"""
        invalid_content = "this is not valid python syntax !!!"

        invalid_file = temp_dir / "invalid.py"
        invalid_file.write_text(invalid_content)

        analyzer = LambdaAnalyzer()
        result = analyzer.analyze_file(str(invalid_file))

        assert len(result.security_issues) > 0
        assert any('syntax error' in issue.message.lower() for issue in result.security_issues)

    def test_empty_file(self, temp_dir):
        """Test handling of empty files"""
        empty_file = temp_dir / "empty.py"
        empty_file.write_text("")

        analyzer = LambdaAnalyzer()
        result = analyzer.analyze_file(str(empty_file))

        assert result.confidence_score == 0.0
        assert len(result.services) == 0